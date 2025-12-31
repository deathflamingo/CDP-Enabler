# Edge CDP Injector

A security research tool for enabling Chrome DevTools Protocol (CDP) debugging on Microsoft Edge browser processes at runtime. This project demonstrates advanced Windows API usage, PE file analysis, and dynamic code manipulation techniques.

## Overview

This tool injects a DLL into Microsoft Edge to enable Chrome DevTools Protocol debugging capabilities without requiring command-line flags or browser restarts. It uses signature-based symbol resolution to locate required functions within Edge's internal libraries, avoiding the need for PDB files.

## Features

- **Runtime CDP Enablement**: Enable DevTools Protocol on already-running Edge instances
- **Signature-Based Resolution**: No PDB files required - uses byte pattern matching
- **Automatic Process Discovery**: Finds running Edge browser processes automatically
- **Port 8181 CDP Server**: Creates a TCP socket server for CDP client connections
- **Comprehensive Logging**: Detailed debug output for troubleshooting
- **Clean Injection**: Proper memory management and thread-safe operations

## Project Structure

```
Edge/
├── cdp_inject.c         # Core DLL injected into Edge (starts CDP server)
├── injector.c           # Standalone injector executable
├── pe_signature_finder.py  # Python utility for finding function signatures
├── build.bat            # Windows build script
└── bin/                 # Build output directory
    ├── cdp_inject.dll
    └── injector.exe
```

## Building

### Prerequisites

- Windows 10/11
- Visual Studio 2019 or 2022 with C++ build tools
- Windows SDK
- x64 Native Tools Command Prompt for VS

### Build Steps

1. Open **x64 Native Tools Command Prompt for VS 2022** (or VS 2019)
2. Navigate to the project directory
3. Run the build script:

```batch
build.bat
```

The build will produce:
- `bin\cdp_inject.dll` - The injection DLL
- `bin\injector.exe` - The injector executable

## Usage

### Basic Usage

Automatically detect and inject into a running Edge process:

```batch
bin\injector.exe
```

### Specify Target Process

Inject into a specific Edge process by PID:

```batch
bin\injector.exe path\to\cdp_inject.dll 1234
```

### Connecting to CDP

After successful injection, connect to the CDP server:

```
localhost:8181
```

You can use any CDP client such as:
- Chrome DevTools (chrome://inspect)
- Puppeteer/Playwright
- Custom CDP clients

## Technical Details

### Target Version

Tested with Microsoft Edge version **143.0.3650.96**.

### Required Symbols

The injector locates these functions in `msedge.dll` via signature scanning:

| Symbol | Purpose |
|--------|---------|
| `TCPServerSocketFactory` (vtable) | Creates the TCP socket server |
| `operator new` | Chrome's PartitionAlloc memory allocator |
| `content::DevToolsAgentHost::StartRemoteDebuggingServer` | Initializes CDP server |
| `content::DevToolsManager::GetInstance` | Retrieves DevTools manager singleton |

### Injection Process

1. **Process Discovery**: Find running Edge browser process
2. **DLL Injection**: Load `cdp_inject.dll` into target process via `CreateRemoteThread`
3. **Symbol Resolution**: Scan `msedge.dll` for required function signatures
4. **UI Thread Execution**: Use window subclassing to execute on Edge's UI thread
5. **CDP Server Creation**: Allocate and initialize TCPServerSocketFactory
6. **Server Start**: Call StartRemoteDebuggingServer on port 8181



## Troubleshooting

### Debug Logging

The tool writes detailed logs to:
```
D:\Temp\Edge\log.txt
```

Enable debug logging by defining `DEBUG_LOG` in `cdp_inject.c`.

### Common Issues

**Issue**: "No Edge browser process found"
- **Solution**: Ensure Edge is running before executing the injector

**Issue**: "Failed to resolve symbol signatures"
- **Cause**: Edge version mismatch - signatures are version-specific
- **Solution**: See "Finding New Signatures" below

**Issue**: Injection succeeds but CDP not accessible on port 8181
- **Solution**: Check firewall settings and verify Edge is not already using the port

## Finding New Signatures

While the signatures should be version resilient for the most part, if the injector fails with signature resolution errors, you likely need to update the byte patterns for your Edge version. The signatures are hardcoded in `cdp_inject.c`.

### Required Signatures

You will need to find patterns for these symbols:

1. `TCPServerSocketFactory` - vtable in .rdata section
2. `operator new` - Chrome's allocator (appears multiple times, so use `*??2@YAPEAX_K@Z*` )
3. `content::DevToolsAgentHost::StartRemoteDebuggingServer` - main CDP function
4. `content::DevToolsManager::GetInstance` - singleton accessor

### Methods

#### Method 1: Using PDB Symbols (Recommended)

1. Download the PDB file for your `msedge.dll` version
2. Use the provided `pe_signature_finder.py` script:

```batch
python pe_signature_finder.py --pdb msedge.pdb --symbol "*DevToolsAgentHost::StartRemoteDebuggingServer*"
```

3. The script will output minimal unique byte patterns

#### Method 2: Manual Analysis with IDA/Ghidra

1. Open `msedge.dll` in your disassembler
2. Load PDB symbols if available
3. Navigate to the target function
4. Extract the first 16-32 bytes as a signature
5. Replace wildcard bytes (`??`) with appropriate patterns


## Security Considerations

This project is intended for:
- Security research and education
- Automated testing and debugging
- Authorized testing and use only

## Research Value

This project serves as a reference for:

- **Dynamic Binary Analysis**: PE file parsing and signature scanning
- **Process Injection**: Advanced Windows API techniques
- **Memory Management**: Working with custom allocators (PartitionAlloc)
- **Reverse Engineering**: Understanding Chrome/Edge internal architecture
- **Protocol Implementation**: Chrome DevTools Protocol integration

## License

This is a security research tool. Use responsibly and in accordance with applicable laws and regulations.

