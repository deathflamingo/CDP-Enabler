#!/usr/bin/env python3
"""
PE/PDB Signature Finder Tool

Analyzes PE files with PDB symbols to find minimum unique signatures for functions.
Supports wildcard pattern matching for symbol names.

Usage:
    python pe_signature_finder.py <pe_file> <pdb_file> <symbol_pattern>

Examples:
    python pe_signature_finder.py app.exe app.pdb "*::MyClass::*"
    python pe_signature_finder.py app.exe app.pdb "*::SomeFunc"
    python pe_signature_finder.py app.exe app.pdb "??_7*@@6B@"  # vtable pattern
"""

import argparse
import fnmatch
import struct
import sys
import mmap
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Iterator, Dict

try:
    import pefile
except ImportError:
    print("Error: pefile library not found. Install with: pip install pefile")
    sys.exit(1)


# PDB Magic signatures
PDB_SIGNATURE_700 = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"


@dataclass
class SymbolInfo:
    """Represents a symbol from the PDB."""
    name: str
    rva: int
    size: int = 0
    segment: int = 0
    offset: int = 0


@dataclass
class SignatureResult:
    """Result of signature finding for a symbol."""
    symbol: SymbolInfo
    signature: Optional[bytes] = None
    signature_length: int = 0
    match_count: int = 0
    section: str = ""
    vtable_refs: List[int] = field(default_factory=list)
    error: Optional[str] = None


def demangle_symbol(name: str) -> str:
    """
    Attempt to demangle a C++ symbol name.
    This is a simplified demangler for common MSVC patterns.
    """
    if not name.startswith('?'):
        return name

    # ??_7ClassName@@6B@ = vtable
    if name.startswith('??_7') and '@@6B@' in name:
        class_name = name[4:].split('@@')[0].replace('@', '::')
        return f"{class_name}::`vftable'"

    # ??0ClassName@@... = constructor
    if name.startswith('??0'):
        parts = name[3:].split('@@')
        if parts:
            class_name = parts[0].replace('@', '::')
            short_name = class_name.split('::')[-1]
            return f"{class_name}::{short_name}()"

    # ??1ClassName@@... = destructor
    if name.startswith('??1'):
        parts = name[3:].split('@@')
        if parts:
            class_name = parts[0].replace('@', '::')
            short_name = class_name.split('::')[-1]
            return f"{class_name}::~{short_name}()"

    # ?FuncName@ClassName@@... = member function
    if name.startswith('?') and '@' in name:
        parts = name[1:].split('@')
        if len(parts) >= 2:
            func_name = parts[0]
            class_parts = []
            for part in parts[1:]:
                if part.startswith('@'):
                    break
                if part:
                    class_parts.append(part)
            if class_parts:
                class_name = '::'.join(reversed(class_parts))
                return f"{class_name}::{func_name}()"

    return name


class PDBParser:
    """
    PDB parser for extracting symbol information.
    Supports PDB 7.0 format (MSF format).
    """

    # Symbol record types
    S_PUB32 = 0x110E
    S_GDATA32 = 0x110D
    S_LDATA32 = 0x110C
    S_PROCREF = 0x1125
    S_LPROCREF = 0x1127
    S_GPROC32 = 0x1110
    S_LPROC32 = 0x110F
    S_GPROC32_ID = 0x1147
    S_LPROC32_ID = 0x1146
    S_PUB32_ST = 0x1009  # Older format

    def __init__(self, pdb_path: str, pe: pefile.PE, verbose: bool = False):
        self.pdb_path = Path(pdb_path)
        self.pe = pe
        self.verbose = verbose
        self.symbols: List[SymbolInfo] = []
        self.section_headers: List[Tuple[int, int]] = []  # (VA, size) pairs from PDB
        self._build_section_map_from_pe()
        self._parse()

    def _build_section_map_from_pe(self):
        """Build section map from PE file."""
        self.section_map = {}
        for idx, section in enumerate(self.pe.sections, 1):
            self.section_map[idx] = section.VirtualAddress

    def _log(self, msg: str):
        if self.verbose:
            print(f"[PDB] {msg}", file=sys.stderr)

    def _parse(self):
        """Parse the PDB file."""
        with open(self.pdb_path, 'rb') as f:
            data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                self._parse_pdb7(data)
            finally:
                data.close()

    def _read_pages(self, data: mmap.mmap, pages: List[int], page_size: int, total_size: int) -> bytes:
        """Read data from specified pages."""
        result = bytearray()
        remaining = total_size
        for page in pages:
            chunk_size = min(page_size, remaining)
            offset = page * page_size
            result.extend(data[offset:offset + chunk_size])
            remaining -= chunk_size
        return bytes(result)

    def _parse_pdb7(self, data: mmap.mmap):
        """Parse PDB 7.0 (MSF) format."""
        # Check signature
        if data[:len(PDB_SIGNATURE_700)] != PDB_SIGNATURE_700:
            raise ValueError("Not a valid PDB 7.0 file")

        # Read MSF header
        header_offset = len(PDB_SIGNATURE_700)
        page_size, = struct.unpack_from('<I', data, header_offset)
        dir_size, = struct.unpack_from('<I', data, header_offset + 12)
        dir_map_page, = struct.unpack_from('<I', data, header_offset + 20)

        self._log(f"Page size: {page_size}, Dir size: {dir_size}")

        # Calculate directory pages
        dir_pages_count = (dir_size + page_size - 1) // page_size
        dir_map_offset = dir_map_page * page_size
        dir_page_list = []
        for i in range(dir_pages_count):
            page_num, = struct.unpack_from('<I', data, dir_map_offset + i * 4)
            dir_page_list.append(page_num)

        # Read directory
        directory = self._read_pages(data, dir_page_list, page_size, dir_size)

        # Parse directory - get stream count and sizes
        stream_count, = struct.unpack_from('<I', directory, 0)
        self._log(f"Stream count: {stream_count}")

        stream_sizes = []
        offset = 4
        for i in range(stream_count):
            size, = struct.unpack_from('<I', directory, offset)
            stream_sizes.append(size)
            offset += 4

        # Build page lists for each stream
        stream_pages = []
        for i in range(stream_count):
            size = stream_sizes[i]
            if size == 0 or size == 0xFFFFFFFF:
                stream_pages.append([])
                continue

            pages_needed = (size + page_size - 1) // page_size
            pages = []
            for j in range(pages_needed):
                page, = struct.unpack_from('<I', directory, offset)
                pages.append(page)
                offset += 4
            stream_pages.append(pages)

        # Helper to read a stream
        def read_stream(idx: int) -> Optional[bytes]:
            if idx >= stream_count or stream_sizes[idx] == 0 or stream_sizes[idx] == 0xFFFFFFFF:
                return None
            return self._read_pages(data, stream_pages[idx], page_size, stream_sizes[idx])

        # Read DBI stream (stream 3)
        dbi_data = read_stream(3)
        if not dbi_data or len(dbi_data) < 64:
            self._log("No DBI stream found")
            return

        # Parse DBI header
        gs_stream, = struct.unpack_from('<H', dbi_data, 12)  # Global symbols stream index
        ps_stream, = struct.unpack_from('<H', dbi_data, 16)  # Public symbols stream index
        sym_rec_stream, = struct.unpack_from('<H', dbi_data, 20)  # Symbol records stream

        self._log(f"GSI stream: {gs_stream}, PSI stream: {ps_stream}, SymRec stream: {sym_rec_stream}")

        # Get substream sizes from DBI header
        mod_size, = struct.unpack_from('<I', dbi_data, 24)
        sec_con_size, = struct.unpack_from('<I', dbi_data, 28)
        sec_map_size, = struct.unpack_from('<I', dbi_data, 32)
        file_info_size, = struct.unpack_from('<I', dbi_data, 36)
        ts_map_size, = struct.unpack_from('<I', dbi_data, 40)
        ec_info_size, = struct.unpack_from('<I', dbi_data, 44)
        dbg_hdr_size, = struct.unpack_from('<I', dbi_data, 48)

        # Read section headers from debug header
        dbi_header_size = 64
        dbg_hdr_offset = dbi_header_size + mod_size + sec_con_size + sec_map_size + file_info_size + ts_map_size + ec_info_size

        if dbg_hdr_size >= 24 and dbg_hdr_offset + 24 <= len(dbi_data):
            # Debug header contains stream indices for various debug info
            sec_hdr_stream, = struct.unpack_from('<H', dbi_data, dbg_hdr_offset + 12)
            if sec_hdr_stream != 0xFFFF:
                sec_hdr_data = read_stream(sec_hdr_stream)
                if sec_hdr_data:
                    self._parse_section_headers(sec_hdr_data)

        # Read symbol records stream - this contains all the actual symbols
        sym_rec_data = read_stream(sym_rec_stream)
        if sym_rec_data:
            self._log(f"Symbol records stream size: {len(sym_rec_data)}")
            self._parse_symbol_records(sym_rec_data)

    def _parse_section_headers(self, data: bytes):
        """Parse section headers from PDB (optional, PE sections are authoritative)."""
        # Each section header is 40 bytes (IMAGE_SECTION_HEADER)
        # We DON'T overwrite section_map - PE sections are authoritative
        # This is just for informational purposes
        entry_size = 40
        offset = 0
        while offset + entry_size <= len(data):
            name = data[offset:offset+8].rstrip(b'\x00')
            va, = struct.unpack_from('<I', data, offset + 12)
            size, = struct.unpack_from('<I', data, offset + 8)
            # Only store if it looks valid (VA should be > 0 and name should be printable)
            if va > 0 and all(32 <= b < 127 or b == 0 for b in name):
                self.section_headers.append((va, size))
            offset += entry_size

        self._log(f"Parsed {len(self.section_headers)} section headers from PDB")

    def _parse_symbol_records(self, data: bytes):
        """Parse symbol records stream."""
        offset = 0
        count = 0
        while offset + 4 <= len(data):
            rec_len, = struct.unpack_from('<H', data, offset)
            if rec_len < 2 or offset + rec_len + 2 > len(data):
                offset += 1
                continue

            rec_type, = struct.unpack_from('<H', data, offset + 2)

            if rec_type == self.S_PUB32:
                self._parse_pub32(data, offset, rec_len)
                count += 1
            elif rec_type in (self.S_GPROC32, self.S_LPROC32):
                self._parse_proc32(data, offset, rec_len)
                count += 1
            elif rec_type in (self.S_GPROC32_ID, self.S_LPROC32_ID):
                self._parse_proc32_id(data, offset, rec_len)
                count += 1
            elif rec_type in (self.S_GDATA32, self.S_LDATA32):
                self._parse_data32(data, offset, rec_len)
                count += 1

            offset += rec_len + 2

        self._log(f"Parsed {count} symbol records, found {len(self.symbols)} symbols")

    def _parse_pub32(self, data: bytes, offset: int, rec_len: int):
        """Parse S_PUB32 record (public symbol)."""
        if rec_len < 14:
            return

        try:
            # pubsymflags (4), offset (4), segment (2), name
            flags, = struct.unpack_from('<I', data, offset + 4)
            sym_offset, = struct.unpack_from('<I', data, offset + 8)
            segment, = struct.unpack_from('<H', data, offset + 12)

            name_start = offset + 14
            name_end = data.find(b'\x00', name_start, offset + rec_len + 2)
            if name_end == -1:
                name_end = offset + rec_len + 2

            name = data[name_start:name_end].decode('utf-8', errors='replace')

            if name and segment > 0:
                rva = self._calculate_rva(segment, sym_offset)
                if rva is not None:
                    self.symbols.append(SymbolInfo(
                        name=name,
                        rva=rva,
                        segment=segment,
                        offset=sym_offset
                    ))
        except (struct.error, UnicodeDecodeError):
            pass

    def _parse_proc32(self, data: bytes, offset: int, rec_len: int):
        """Parse S_GPROC32/S_LPROC32 record."""
        if rec_len < 36:
            return

        try:
            # parent(4), end(4), next(4), len(4), dbgstart(4), dbgend(4), type(4), offset(4), seg(2), flags(1), name
            proc_len, = struct.unpack_from('<I', data, offset + 16)
            sym_offset, = struct.unpack_from('<I', data, offset + 32)
            segment, = struct.unpack_from('<H', data, offset + 36)

            name_start = offset + 39
            name_end = data.find(b'\x00', name_start, offset + rec_len + 2)
            if name_end == -1:
                name_end = offset + rec_len + 2

            name = data[name_start:name_end].decode('utf-8', errors='replace')

            if name and segment > 0:
                rva = self._calculate_rva(segment, sym_offset)
                if rva is not None:
                    self.symbols.append(SymbolInfo(
                        name=name,
                        rva=rva,
                        size=proc_len,
                        segment=segment,
                        offset=sym_offset
                    ))
        except (struct.error, UnicodeDecodeError):
            pass

    def _parse_proc32_id(self, data: bytes, offset: int, rec_len: int):
        """Parse S_GPROC32_ID/S_LPROC32_ID record."""
        # Same structure as PROC32 but type field is an ID not index
        self._parse_proc32(data, offset, rec_len)

    def _parse_data32(self, data: bytes, offset: int, rec_len: int):
        """Parse S_GDATA32/S_LDATA32 record."""
        if rec_len < 12:
            return

        try:
            # type(4), offset(4), seg(2), name
            sym_offset, = struct.unpack_from('<I', data, offset + 8)
            segment, = struct.unpack_from('<H', data, offset + 12)

            name_start = offset + 14
            name_end = data.find(b'\x00', name_start, offset + rec_len + 2)
            if name_end == -1:
                name_end = offset + rec_len + 2

            name = data[name_start:name_end].decode('utf-8', errors='replace')

            if name and segment > 0:
                rva = self._calculate_rva(segment, sym_offset)
                if rva is not None:
                    self.symbols.append(SymbolInfo(
                        name=name,
                        rva=rva,
                        segment=segment,
                        offset=sym_offset
                    ))
        except (struct.error, UnicodeDecodeError):
            pass

    def _calculate_rva(self, segment: int, offset: int) -> Optional[int]:
        """Calculate RVA from segment:offset."""
        if segment in self.section_map:
            return self.section_map[segment] + offset
        return None

    def find_symbols(self, pattern: str) -> List[SymbolInfo]:
        """Find symbols matching the given pattern (supports wildcards).

        Matches against both mangled and demangled names.
        """
        matches = []
        seen = set()
        for sym in self.symbols:
            # Match against mangled name
            if fnmatch.fnmatch(sym.name, pattern):
                key = (sym.name, sym.rva)
                if key not in seen:
                    seen.add(key)
                    matches.append(sym)
                continue

            # Also try matching against demangled name
            demangled = demangle_symbol(sym.name)
            if demangled != sym.name and fnmatch.fnmatch(demangled, pattern):
                key = (sym.name, sym.rva)
                if key not in seen:
                    seen.add(key)
                    matches.append(sym)
        return matches


class PEAnalyzer:
    """Analyzes PE files for signatures and vtable references."""

    MIN_SIG_LENGTH = 8
    MAX_SIG_LENGTH = 64

    def __init__(self, pe_path: str):
        self.pe_path = Path(pe_path)
        self.pe = pefile.PE(str(pe_path))
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase

        # Cache all section data for searching
        self._section_cache = {}
        for section in self.pe.sections:
            name = section.Name.decode('utf-8').rstrip('\x00')
            self._section_cache[name] = {
                'section': section,
                'data': section.get_data(),
                'va': section.VirtualAddress,
                'size': section.Misc_VirtualSize
            }

        # Quick references for common sections
        self._text_section = self._find_section('.text')
        self._rdata_section = self._find_section('.rdata')

    def _find_section(self, name: str) -> Optional[pefile.SectionStructure]:
        """Find a section by name."""
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            if section_name == name:
                return section
        name_lower = name.lower()
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00').lower()
            if section_name == name_lower:
                return section
        return None

    def _get_section_for_rva(self, rva: int) -> Optional[Tuple[str, dict]]:
        """Get the section that contains the given RVA."""
        for name, info in self._section_cache.items():
            if info['va'] <= rva < info['va'] + info['size']:
                return (name, info)
        return None

    def get_bytes_at_rva(self, rva: int, size: int) -> Optional[bytes]:
        """Get bytes at a given RVA."""
        try:
            return self.pe.get_data(rva, size)
        except:
            return None

    def find_pattern_in_section(self, pattern: bytes, section_name: str) -> List[int]:
        """Find all occurrences of a pattern in specified section, return RVAs."""
        if section_name not in self._section_cache:
            return []

        info = self._section_cache[section_name]
        data = info['data']
        base_va = info['va']

        matches = []
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            rva = base_va + pos
            matches.append(rva)
            start = pos + 1

        return matches

    def find_pattern_all_sections(self, pattern: bytes) -> List[Tuple[str, int]]:
        """Find all occurrences of a pattern in all sections, return (section, RVA) pairs."""
        all_matches = []
        for name, info in self._section_cache.items():
            data = info['data']
            base_va = info['va']
            start = 0
            while True:
                pos = data.find(pattern, start)
                if pos == -1:
                    break
                rva = base_va + pos
                all_matches.append((name, rva))
                start = pos + 1
        return all_matches

    def find_minimum_unique_signature(self, rva: int) -> Tuple[Optional[bytes], int, int, str]:
        """
        Find the minimum unique byte signature for a symbol at the given RVA.
        Searches the section containing the RVA.
        Returns: (signature_bytes, length, match_count, section_name)
        """
        # Find which section this RVA belongs to
        section_info = self._get_section_for_rva(rva)
        if section_info is None:
            return None, 0, 0, ""

        section_name, info = section_info

        # Get enough bytes to work with
        func_bytes = self.get_bytes_at_rva(rva, self.MAX_SIG_LENGTH)
        if func_bytes is None or len(func_bytes) < self.MIN_SIG_LENGTH:
            return None, 0, 0, section_name

        # Incrementally increase pattern length until unique
        for length in range(self.MIN_SIG_LENGTH, min(len(func_bytes), self.MAX_SIG_LENGTH) + 1):
            pattern = func_bytes[:length]
            matches = self.find_pattern_in_section(pattern, section_name)

            if len(matches) == 1:
                return pattern, length, 1, section_name
            elif len(matches) == 0:
                return pattern, length, 0, section_name

        # No unique signature found within max length
        pattern = func_bytes[:self.MAX_SIG_LENGTH]
        matches = self.find_pattern_in_section(pattern, section_name)
        return pattern, self.MAX_SIG_LENGTH, len(matches), section_name

    def find_vtable_references(self, rva: int) -> List[int]:
        """
        Find vtable entries in .rdata that point to this function's RVA.
        Returns list of RVAs where references were found.
        """
        if '.rdata' not in self._section_cache:
            return []

        rdata_info = self._section_cache['.rdata']
        data = rdata_info['data']
        base_va = rdata_info['va']

        references = []

        # Determine pointer size based on PE type
        is_64bit = self.pe.FILE_HEADER.Machine == 0x8664
        ptr_size = 8 if is_64bit else 4
        ptr_format = '<Q' if is_64bit else '<I'

        # Calculate the VA we're looking for
        target_va = self.image_base + rva

        # Scan through .rdata looking for pointers to our function
        for offset in range(0, len(data) - ptr_size + 1, ptr_size):
            try:
                ptr_value = struct.unpack(ptr_format, data[offset:offset + ptr_size])[0]
                if ptr_value == target_va:
                    ref_rva = base_va + offset
                    references.append(ref_rva)
            except struct.error:
                continue

        return references


def format_bytes(data: bytes) -> str:
    """Format bytes as hex string."""
    return ' '.join(f'{b:02X}' for b in data)


def analyze_symbols(pe_path: str, pdb_path: str, pattern: str,
                    min_sig: int = 8, max_sig: int = 64,
                    verbose: bool = False) -> Iterator[SignatureResult]:
    """
    Main analysis function.
    Yields SignatureResult for each matching symbol.
    """
    # Load PE file
    try:
        pe_analyzer = PEAnalyzer(pe_path)
        pe_analyzer.MIN_SIG_LENGTH = min_sig
        pe_analyzer.MAX_SIG_LENGTH = max_sig
    except Exception as e:
        yield SignatureResult(
            symbol=SymbolInfo(name="", rva=0),
            error=f"Failed to load PE file: {e}"
        )
        return

    # Parse PDB
    try:
        pdb_parser = PDBParser(pdb_path, pe_analyzer.pe, verbose=verbose)
    except Exception as e:
        yield SignatureResult(
            symbol=SymbolInfo(name="", rva=0),
            error=f"Failed to parse PDB file: {e}"
        )
        return

    if not pdb_parser.symbols:
        yield SignatureResult(
            symbol=SymbolInfo(name="", rva=0),
            error="No symbols found in PDB"
        )
        return

    # Find matching symbols
    matches = pdb_parser.find_symbols(pattern)

    if not matches:
        yield SignatureResult(
            symbol=SymbolInfo(name=pattern, rva=0),
            error=f"No symbols found matching pattern: {pattern}"
        )
        return

    print(f"Found {len(matches)} symbol(s) matching pattern '{pattern}'\n", file=sys.stderr)

    # Analyze each matching symbol
    for sym in matches:
        sig_bytes, sig_len, match_count, section = pe_analyzer.find_minimum_unique_signature(sym.rva)
        vtable_refs = pe_analyzer.find_vtable_references(sym.rva)

        error = None
        if sig_bytes is None:
            error = "Could not read bytes at RVA"
        elif match_count > 1:
            error = f"Warning: No unique signature found within {max_sig} bytes ({match_count} matches)"
        elif match_count == 0:
            error = f"Warning: Pattern not found in {section or 'any'} section (RVA may be invalid)"

        yield SignatureResult(
            symbol=sym,
            signature=sig_bytes,
            signature_length=sig_len,
            section=section,
            match_count=match_count,
            vtable_refs=vtable_refs,
            error=error
        )


def print_result(result: SignatureResult):
    """Print a single result in a clean, parseable format."""
    print("-" * 60)

    # Symbol name (both mangled and demangled if different)
    demangled = demangle_symbol(result.symbol.name)
    if demangled != result.symbol.name:
        print(f"Symbol: {demangled}")
        print(f"Mangled: {result.symbol.name}")
    else:
        print(f"Symbol: {result.symbol.name}")

    print(f"RVA: 0x{result.symbol.rva:08X}")
    if result.section:
        print(f"Section: {result.section}")

    if result.symbol.size > 0:
        print(f"Size: {result.symbol.size} bytes")

    if result.error and result.signature is None:
        print(f"Error: {result.error}")
    else:
        if result.signature:
            sig_str = format_bytes(result.signature)
            if result.match_count == 1:
                print(f"Minimum Signature ({result.signature_length} bytes): {sig_str}")
            else:
                print(f"Signature ({result.signature_length} bytes, {result.match_count} matches): {sig_str}")

        if result.error:
            print(f"Note: {result.error}")

    if result.vtable_refs:
        print(f"VTable References ({len(result.vtable_refs)}):")
        for ref_rva in result.vtable_refs:
            print(f"  0x{ref_rva:08X}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description='Find minimum unique signatures for functions in PE files using PDB symbols.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s app.exe app.pdb "*::MyClass::*"
  %(prog)s app.exe app.pdb "?Init@*"
  %(prog)s app.exe app.pdb "??_7*@@6B@"  (vtable pattern)

Pattern Syntax:
  *      matches everything
  ?      matches any single character
  [seq]  matches any character in seq
  [!seq] matches any character not in seq
'''
    )

    parser.add_argument('pe_file', help='Path to the PE file (.exe or .dll)')
    parser.add_argument('pdb_file', help='Path to the PDB file')
    parser.add_argument('pattern', help='Symbol pattern (supports wildcards)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--min-sig', type=int, default=8,
                        help='Minimum signature length (default: 8)')
    parser.add_argument('--max-sig', type=int, default=64,
                        help='Maximum signature length (default: 64)')
    parser.add_argument('--list-symbols', action='store_true',
                        help='List all symbols without signature analysis')

    args = parser.parse_args()

    # Validate files exist
    if not Path(args.pe_file).exists():
        print(f"Error: PE file not found: {args.pe_file}", file=sys.stderr)
        sys.exit(1)

    if not Path(args.pdb_file).exists():
        print(f"Error: PDB file not found: {args.pdb_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing: {args.pe_file}")
    print(f"PDB: {args.pdb_file}")
    print(f"Pattern: {args.pattern}")
    print()

    if args.list_symbols:
        # Just list matching symbols
        try:
            pe = pefile.PE(args.pe_file)
            pdb_parser = PDBParser(args.pdb_file, pe, verbose=args.verbose)
            matches = pdb_parser.find_symbols(args.pattern)
            print(f"Found {len(matches)} matching symbol(s):\n")
            for sym in matches:
                demangled = demangle_symbol(sym.name)
                if demangled != sym.name:
                    print(f"0x{sym.rva:08X}: {demangled}")
                    print(f"           {sym.name}")
                else:
                    print(f"0x{sym.rva:08X}: {sym.name}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # Run full analysis
    results = list(analyze_symbols(
        args.pe_file, args.pdb_file, args.pattern,
        min_sig=args.min_sig, max_sig=args.max_sig,
        verbose=args.verbose
    ))

    for result in results:
        print_result(result)

    # Summary
    successful = sum(1 for r in results if r.signature is not None and r.match_count == 1)
    total = len(results)
    print("=" * 60)
    print(f"Summary: {successful}/{total} symbols with unique signatures found")


if __name__ == '__main__':
    main()
