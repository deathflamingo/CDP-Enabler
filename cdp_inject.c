/*
 * CDP Injector DLL for Microsoft Edge/Chrome
 * Enables Chrome DevTools Protocol on a running browser process.
 * For security research purposes only.
 *
 * Build: cl /LD /O2 cdp_inject.c /Fe:cdp_inject.dll user32.lib
 *
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

/* Set this to 1 to enable debug logging, 0 to disable (no-op) */
#define DEBUG_ENABLED 1

/* Target configuration - change this to switch between Edge and Chrome */
#define TARGET_DLL "chrome.dll"           /* "chrome.dll" for Chrome */

#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")

/* Configuration */
#define CDP_PORT 8182
#define WM_START_CDP (WM_USER + 0x1337)

/* TCPServerSocketFactory layout (from WinDbg analysis of working Edge):
 * Working factory memory dump:
 *   +0x00: vtable pointer (8 bytes)
 *   +0x08: port (2 bytes) + 6 bytes uninitialized padding
 *   +0x10: badbad00 poison pattern (beyond struct = uninitialized)
 *
 * Total: 16 bytes (0x10)
 */
typedef struct {
    void*    vtable;        /* 0x00 - vtable pointer */
    uint16_t port;          /* 0x08 - CDP port */
    uint8_t  padding[6];    /* 0x0A - alignment padding (can be uninitialized) */
} TCPServerSocketFactory;   /* Total: 0x10 bytes (16) */


typedef struct {
    uint8_t data[24];   
} FilePath;

static void InitEmptyFilePath(FilePath* fp) {
    /* All zeros = empty short string in libc++ */
    memset(fp, 0, sizeof(FilePath));
}

/* Function pointer type for StartRemoteDebuggingServer
 * Signature: void StartRemoteDebuggingServer(
 *     unique_ptr<DevToolsSocketFactory> arg1,  // rcx - passed as ptr to ptr
 *     FilePath const& arg2,                     // rdx - output directory
 *     FilePath const& arg3                      // r8  - frontend dir
 * )
 */
typedef void (*StartRemoteDebuggingServerFn)(void** factory_ptr, FilePath* output_dir, FilePath* frontend_dir);

/* Chrome's operator new - uses PartitionAlloc */
typedef void* (*ChromeNewFn)(size_t size);

/* DevToolsManager::GetInstance() */
typedef void* (*GetDevToolsManagerFn)(void);

/* Global state */
static GetDevToolsManagerFn g_get_devtools_manager = NULL;
static HWND g_target_hwnd = NULL;
static WNDPROC g_original_wndproc = NULL;
static StartRemoteDebuggingServerFn g_start_server = NULL;
static void* g_factory_vtable = NULL;
static ChromeNewFn g_chrome_new = NULL;
static volatile LONG g_cdp_started = 0;
static HMODULE g_this_module = NULL;

/*
 * Universal signatures for Chrome/Edge (tested on Chrome 143.0.7499.170, Edge 143.0.3650.96)
 * These signatures work on both browsers using wildcard masks.
 */

/* Signature for StartRemoteDebuggingServer - matches INSIDE the function
 * Pattern: mov ecx, 0x88; call operator_new; mov r15, rax; mov rax, [rsi]; xor r12d, r12d; mov [rsi], r12
 * This pattern appears at offset +63 (Chrome) or +55 (Edge) from function start.
 * After finding the pattern, backtrack to find the function prologue. */
static const uint8_t SIG_START_SERVER[] = {
    0xB9, 0x88, 0x00, 0x00, 0x00,                    /* 0-4:   mov ecx, 0x88 (sizeof DevToolsHttpHandler) */
    0xE8, 0x00, 0x00, 0x00, 0x00,                    /* 5-9:   call operator new */
    0x49, 0x89, 0xC7,                                /* 10-12: mov r15, rax */
    0x48, 0x8B, 0x06,                                /* 13-15: mov rax, [rsi] */
    0x45, 0x31, 0xE4,                                /* 16-18: xor r12d, r12d */
    0x4C, 0x89, 0x26                                 /* 19-21: mov [rsi], r12 */
};
static const uint8_t SIG_START_SERVER_MASK[] = {
    1, 1, 1, 1, 1,  /* mov ecx, 0x88 - must match */
    1, 0, 0, 0, 0,  /* call - opcode match, offset wildcard */
    1, 1, 1,        /* mov r15, rax - must match */
    1, 1, 1,        /* mov rax, [rsi] - must match */
    1, 1, 1,        /* xor r12d, r12d - must match */
    1, 1, 1         /* mov [rsi], r12 - must match */
};
#define SIG_START_SERVER_LEN 22

/* Function prologue to verify StartRemoteDebuggingServer after backtracking */
static const uint8_t SIG_START_SERVER_PROLOGUE[] = {
    0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x56, 0x57,  /* push r15/r14/r12/rsi/rdi */
    0x53, 0x48, 0x83, 0xEC, 0x48                      /* push rbx; sub rsp, 0x48 */
};
#define SIG_START_SERVER_PROLOGUE_LEN 13
/* Backtrack offsets to try (Chrome=63, Edge=55) */
#define SIG_START_SERVER_BACKTRACK_CHROME 63
#define SIG_START_SERVER_BACKTRACK_EDGE 55

/* Signature for operator new (in .text section)
 * Pattern: push rbx; sub rsp, 0x20; mov rbx, rcx; jmp; mov rcx, rbx; call _callnewh; test eax, eax */
static const uint8_t SIG_OPERATOR_NEW[] = {
    0x40, 0x53,                                      /* 0-1:   push rbx (REX prefix) */
    0x48, 0x83, 0xEC, 0x20,                          /* 2-5:   sub rsp, 0x20 */
    0x48, 0x8B, 0xD9,                                /* 6-8:   mov rbx, rcx */
    0xEB, 0x00,                                      /* 9-10:  jmp +offset */
    0x48, 0x8B, 0xCB,                                /* 11-13: mov rcx, rbx */
    0xE8, 0x00, 0x00, 0x00, 0x00,                    /* 14-18: call _callnewh */
    0x85, 0xC0,                                      /* 19-20: test eax, eax */
    0x74, 0x00,                                      /* 21-22: je +offset */
    0x48, 0x8B, 0xCB                                 /* 23-25: mov rcx, rbx */
};
static const uint8_t SIG_OPERATOR_NEW_MASK[] = {
    1, 1,           /* push rbx */
    1, 1, 1, 1,     /* sub rsp, 0x20 */
    1, 1, 1,        /* mov rbx, rcx */
    1, 0,           /* jmp - offset wildcard */
    1, 1, 1,        /* mov rcx, rbx */
    1, 0, 0, 0, 0,  /* call - offset wildcard */
    1, 1,           /* test eax, eax */
    1, 0,           /* je - offset wildcard */
    1, 1, 1         /* mov rcx, rbx */
};
#define SIG_OPERATOR_NEW_LEN 26

/* GetInstance is derived at runtime from StartRemoteDebuggingServer.
 * No static signature needed - see ResolveGetInstance(). */

/* To find the TCPServerSocketFactory vtable, we:
 * 1. Find destructor candidates by signature (may have multiple matches)
 * 2. Find CreateForHttpServer by signature (unique)
 * 3. Search .rdata for consecutive pointers [destructor, CreateForHttpServer]
 * This cross-reference uniquely identifies both the correct destructor and vtable.
 */

/* Signature for scalar deleting destructor (vtable[0])
 * This may match multiple functions - we find the correct one via vtable cross-reference */
static const uint8_t SIG_VTABLE_ENTRY0[] = {
    0x56, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCE,  /* 0-7:   push rsi; sub rsp, 0x20; mov rsi, rcx */
    0xF6, 0xC2, 0x01, 0x74, 0x08, 0x48, 0x89, 0xF1,  /* 8-15:  test dl, 1; jz +8; mov rcx, rsi */
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xF0,  /* 16-23: call operator delete; mov rax, rsi */
    0x48, 0x83, 0xC4, 0x20, 0x5E, 0xC3               /* 24-29: add rsp, 0x20; pop rsi; ret */
};
static const uint8_t SIG_VTABLE_ENTRY0_MASK[] = {
    1, 1, 1, 1, 1, 1, 1, 1,  /* 0-7: must match */
    1, 1, 1, 1, 1, 1, 1, 1,  /* 8-15: must match */
    1, 0, 0, 0, 0, 1, 1, 1,  /* 16-23: call offset wildcard */
    1, 1, 1, 1, 1, 1         /* 24-29: must match */
};
#define SIG_VTABLE_ENTRY0_LEN 30

/* Signature for CreateForHttpServer (vtable[1]) - unique in both Chrome/Edge */
static const uint8_t SIG_VTABLE_ENTRY1[] = {
    0x48, 0x89, 0xD0,                                /* 0-2:   mov rax, rdx */
    0x0F, 0xB7, 0x51, 0x08,                          /* 3-6:   movzx edx, word [rcx+8] (port) */
    0x48, 0x89, 0xC1,                                /* 7-9:   mov rcx, rax */
    0xE9, 0x00, 0x00, 0x00, 0x00                     /* 10-14: jmp CreateLocalHostServerSocket */
};
static const uint8_t SIG_VTABLE_ENTRY1_MASK[] = {
    1, 1, 1,        /* mov rax, rdx */
    1, 1, 1, 1,     /* movzx edx, word [rcx+8] */
    1, 1, 1,        /* mov rcx, rax */
    1, 0, 0, 0, 0   /* jmp - offset wildcard */
};
#define SIG_VTABLE_ENTRY1_LEN 15

/* Debug logging (writes to file) */
#if DEBUG_ENABLED
static CRITICAL_SECTION g_log_cs;
static BOOL g_log_init = FALSE;
#define LOG_FILE "D:\\Temp\\Edge\\log.txt"
#endif

static void DebugLog(const char* fmt, ...) {
#if DEBUG_ENABLED
    char buf[512];
    char timebuf[64];
    va_list args;
    FILE* f;
    SYSTEMTIME st;

    if (!g_log_init) {
        InitializeCriticalSection(&g_log_cs);
        g_log_init = TRUE;
        /* Clear log file on first write */
        f = fopen(LOG_FILE, "w");
        if (f) {
            fprintf(f, "=== CDP Inject Log ===\n");
            fclose(f);
        }
    }

    GetLocalTime(&st);
    wsprintfA(timebuf, "[%02d:%02d:%02d.%03d] ",
              st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_start(args, fmt);
    wvsprintfA(buf, fmt, args);
    va_end(args);

    EnterCriticalSection(&g_log_cs);
    f = fopen(LOG_FILE, "a");
    if (f) {
        fprintf(f, "%s%s\n", timebuf, buf);
        fflush(f);
        fclose(f);
    }
    LeaveCriticalSection(&g_log_cs);

    /* Also output to debugger */
    OutputDebugStringA("[CDP_INJECT] ");
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
#else
    /* Debug logging disabled - no-op */
    (void)fmt;
#endif
}

/* Scan a memory region for a byte pattern with optional wildcards
 * mask: array of same length as sig. 1 = must match, 0 = wildcard (match any)
 *       If mask is NULL, all bytes must match exactly.
 */
static void* ScanForSignature(const uint8_t* start, size_t size,
                               const uint8_t* sig, const uint8_t* mask, size_t sig_len) {
    if (size < sig_len) return NULL;

    const uint8_t* end = start + size - sig_len;
    for (const uint8_t* p = start; p <= end; p++) {
        BOOL match = TRUE;
        for (size_t i = 0; i < sig_len && match; i++) {
            if (mask == NULL || mask[i]) {
                if (p[i] != sig[i]) match = FALSE;
            }
            /* else: wildcard, any byte matches */
        }
        if (match) return (void*)p;
    }
    return NULL;
}

/* Get PE section info */
static BOOL GetSectionInfo(HMODULE mod, const char* section_name,
                           uint8_t** out_start, size_t* out_size) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint8_t*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (strncmp((char*)section->Name, section_name, 8) == 0) {
            *out_start = (uint8_t*)mod + section->VirtualAddress;
            *out_size = section->Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

/* Collect all matches for a signature (for multi-match scenarios like destructor) */
static int ScanForAllSignatures(const uint8_t* start, size_t size,
                                 const uint8_t* sig, const uint8_t* mask, size_t sig_len,
                                 void** out_matches, int max_matches) {
    int count = 0;
    const uint8_t* end = start + size - sig_len;

    for (const uint8_t* p = start; p <= end && count < max_matches; p++) {
        BOOL match = TRUE;
        for (size_t i = 0; i < sig_len && match; i++) {
            if (mask == NULL || mask[i]) {
                if (p[i] != sig[i]) match = FALSE;
            }
        }
        if (match) {
            out_matches[count++] = (void*)p;
        }
    }
    return count;
}

/* Resolve symbols using signature scanning */
static BOOL ResolveSymbolsBySig(void** out_start_server,
                                 void** out_chrome_new,
                                 void** out_get_instance,
                                 void** out_vtable) {
    HMODULE browser_dll = NULL;
    uint8_t* text_start = NULL;
    uint8_t* rdata_start = NULL;
    size_t text_size = 0;
    size_t rdata_size = 0;
    void* addr;
    int found = 0;
    const char* dll_name = NULL;

    DebugLog("ResolveSymbolsBySig: Starting signature-based resolution...");

    browser_dll = GetModuleHandleA(TARGET_DLL);
    if (!browser_dll) {
        DebugLog("ResolveSymbolsBySig: Failed to get %s handle", TARGET_DLL);
        return FALSE;
    }
    dll_name = TARGET_DLL;
    DebugLog("ResolveSymbolsBySig: %s @ 0x%p", dll_name, browser_dll);

    /* Get .text section for code signatures */
    if (!GetSectionInfo(browser_dll, ".text", &text_start, &text_size)) {
        DebugLog("ResolveSymbolsBySig: Failed to find .text section");
        return FALSE;
    }
    DebugLog("ResolveSymbolsBySig: .text section @ 0x%p, size=0x%zX", text_start, text_size);

    /* Get .rdata section for vtable search */
    if (!GetSectionInfo(browser_dll, ".rdata", &rdata_start, &rdata_size)) {
        DebugLog("ResolveSymbolsBySig: Failed to find .rdata section");
        return FALSE;
    }
    DebugLog("ResolveSymbolsBySig: .rdata section @ 0x%p, size=0x%zX", rdata_start, rdata_size);

    /* Scan for StartRemoteDebuggingServer using mid-function pattern + backtrack */
    DebugLog("ResolveSymbolsBySig: Scanning for StartRemoteDebuggingServer...");
    addr = ScanForSignature(text_start, text_size, SIG_START_SERVER, SIG_START_SERVER_MASK, SIG_START_SERVER_LEN);
    if (addr) {
        void* func_start = NULL;
        uint8_t* pattern_addr = (uint8_t*)addr;

        DebugLog("ResolveSymbolsBySig: Found mid-function pattern @ 0x%p", addr);

        /* Try Chrome backtrack offset (63 bytes) */
        if (pattern_addr - SIG_START_SERVER_BACKTRACK_CHROME >= text_start) {
            uint8_t* candidate = pattern_addr - SIG_START_SERVER_BACKTRACK_CHROME;
            if (memcmp(candidate, SIG_START_SERVER_PROLOGUE, SIG_START_SERVER_PROLOGUE_LEN) == 0) {
                func_start = candidate;
                DebugLog("ResolveSymbolsBySig: Verified prologue at Chrome offset (-63)");
            }
        }

        /* Try Edge backtrack offset (55 bytes) if Chrome didn't match */
        if (!func_start && pattern_addr - SIG_START_SERVER_BACKTRACK_EDGE >= text_start) {
            uint8_t* candidate = pattern_addr - SIG_START_SERVER_BACKTRACK_EDGE;
            if (memcmp(candidate, SIG_START_SERVER_PROLOGUE, SIG_START_SERVER_PROLOGUE_LEN) == 0) {
                func_start = candidate;
                DebugLog("ResolveSymbolsBySig: Verified prologue at Edge offset (-55)");
            }
        }

        if (func_start) {
            DebugLog("ResolveSymbolsBySig: [SIG] StartRemoteDebuggingServer @ 0x%p", func_start);
            *out_start_server = func_start;
            found++;
        } else {
            DebugLog("ResolveSymbolsBySig: Pattern found but prologue verification failed!");
        }
    } else {
        DebugLog("ResolveSymbolsBySig: StartRemoteDebuggingServer NOT FOUND!");
    }

    /* Scan for operator new */
    DebugLog("ResolveSymbolsBySig: Scanning for operator new...");
    addr = ScanForSignature(text_start, text_size, SIG_OPERATOR_NEW, SIG_OPERATOR_NEW_MASK, SIG_OPERATOR_NEW_LEN);
    if (addr) {
        DebugLog("ResolveSymbolsBySig: [SIG] operator new @ 0x%p", addr);
        *out_chrome_new = addr;
        found++;
    } else {
        DebugLog("ResolveSymbolsBySig: operator new NOT FOUND!");
    }

    /* GetInstance will be derived later from StartRemoteDebuggingServer */
    *out_get_instance = NULL;

    /* Find TCPServerSocketFactory vtable by cross-referencing destructor candidates with CreateForHttpServer */
    {
        void* destr_candidates[32];
        int destr_count;
        void* entry1_fn = NULL;  /* CreateForHttpServer - unique */

        DebugLog("ResolveSymbolsBySig: Finding vtable via cross-reference...");

        /* Find all destructor candidates */
        destr_count = ScanForAllSignatures(text_start, text_size,
                                            SIG_VTABLE_ENTRY0, SIG_VTABLE_ENTRY0_MASK, SIG_VTABLE_ENTRY0_LEN,
                                            destr_candidates, 32);
        DebugLog("ResolveSymbolsBySig: Found %d destructor candidates", destr_count);

        /* Find CreateForHttpServer (unique) */
        entry1_fn = ScanForSignature(text_start, text_size, SIG_VTABLE_ENTRY1, SIG_VTABLE_ENTRY1_MASK, SIG_VTABLE_ENTRY1_LEN);
        if (entry1_fn) {
            DebugLog("ResolveSymbolsBySig: CreateForHttpServer @ 0x%p", entry1_fn);
        } else {
            DebugLog("ResolveSymbolsBySig: CreateForHttpServer NOT FOUND");
        }

        /* Search .rdata for vtable containing [destructor, CreateForHttpServer] */
        if (destr_count > 0 && entry1_fn) {
            const uint64_t* p = (const uint64_t*)rdata_start;
            const uint64_t* end = (const uint64_t*)(rdata_start + rdata_size - 16);
            void* found_vtable = NULL;

            DebugLog("ResolveSymbolsBySig: Searching .rdata for vtable...");

            for (int i = 0; i < destr_count && !found_vtable; i++) {
                uint64_t destr_addr = (uint64_t)destr_candidates[i];
                uint64_t http_addr = (uint64_t)entry1_fn;

                for (const uint64_t* q = p; q < end; q++) {
                    if (q[0] == destr_addr && q[1] == http_addr) {
                        found_vtable = (void*)q;
                        DebugLog("ResolveSymbolsBySig: Matched destructor[%d] @ 0x%p", i, destr_candidates[i]);
                        break;
                    }
                }
            }

            if (found_vtable) {
                DebugLog("ResolveSymbolsBySig: [SIG] Factory vtable @ 0x%p", found_vtable);
                *out_vtable = found_vtable;
                found++;
            } else {
                DebugLog("ResolveSymbolsBySig: Factory vtable NOT FOUND in .rdata");
            }
        }
    }

    /* We need 3 symbols (StartServer, operator new, vtable). GetInstance is derived separately. */
    DebugLog("ResolveSymbolsBySig: Found %d/3 required symbols via signature", found);
    return (found == 3);
}

/* Derive GetInstance from StartRemoteDebuggingServer
 * The function has different code paths in Chrome vs Edge:
 * - Chrome: mov r14, [rip+disp32] at offset +0x25 loads instance_ directly
 * - Edge: call GetInstance at offset +0x25, then mov r14, [rax+8]
 *
 * For Edge, we follow the call to find GetInstance.
 * For Chrome, GetInstance doesn't exist as a separate function (inlined), so we return NULL.
 */
static void* DeriveGetInstance(void* start_server) {
    uint8_t* func = (uint8_t*)start_server;

    /* Check what's at offset +0x25 (after prologue + security cookie setup) */
    uint8_t* check_addr = func + 0x25;

    /* Edge: E8 xx xx xx xx = call GetInstance */
    if (check_addr[0] == 0xE8) {
        int32_t rel_offset;
        void* target;

        memcpy(&rel_offset, check_addr + 1, sizeof(int32_t));
        target = check_addr + 5 + rel_offset;

        DebugLog("DeriveGetInstance: Found call at +0x25, target @ 0x%p", target);
        return target;
    }

    /* Chrome: 4C 8B 35 xx xx xx xx = mov r14, [rip+disp32] (inlined singleton access) */
    if (check_addr[0] == 0x4C && check_addr[1] == 0x8B && check_addr[2] == 0x35) {
        DebugLog("DeriveGetInstance: Chrome uses inlined singleton access, no GetInstance function");
        return NULL;
    }

    DebugLog("DeriveGetInstance: Unknown code at +0x25: %02X %02X %02X",
             check_addr[0], check_addr[1], check_addr[2]);
    return NULL;
}

/* Resolve required symbols using signature scanning */
static BOOL ResolveSymbols(void) {
    void* start_server = NULL;
    void* chrome_new = NULL;
    void* get_instance = NULL;
    void* vtable = NULL;

    DebugLog("ResolveSymbols: Starting signature-based resolution...");

    if (!ResolveSymbolsBySig(&start_server, &chrome_new, &get_instance, &vtable)) {
        DebugLog("ResolveSymbols: Signature resolution failed!");
        return FALSE;
    }

    /* Derive GetInstance from StartRemoteDebuggingServer */
    if (start_server) {
        get_instance = DeriveGetInstance(start_server);
        if (get_instance) {
            DebugLog("ResolveSymbols: Derived GetInstance @ 0x%p", get_instance);
        } else {
            DebugLog("ResolveSymbols: GetInstance not available (Chrome inlines it)");
        }
    }

    /* Set globals */
    g_start_server = (StartRemoteDebuggingServerFn)start_server;
    g_chrome_new = (ChromeNewFn)chrome_new;
    g_get_devtools_manager = (GetDevToolsManagerFn)get_instance;  /* May be NULL on Chrome */
    g_factory_vtable = vtable;

    DebugLog("ResolveSymbols: All required symbols resolved via signatures!");
    DebugLog("ResolveSymbols: StartRemoteDebuggingServer @ 0x%p", g_start_server);
    DebugLog("ResolveSymbols: operator new @ 0x%p", g_chrome_new);
    DebugLog("ResolveSymbols: DevToolsManager::GetInstance @ 0x%p (may be NULL)", g_get_devtools_manager);
    DebugLog("ResolveSymbols: TCPServerSocketFactory vtable @ 0x%p", g_factory_vtable);

    return TRUE;
}

/* Start the CDP server - MUST be called on UI thread */
static void StartCDPServer(void) {
    TCPServerSocketFactory* factory = NULL;
    void* factory_ptr = NULL;
    FilePath output_dir;      /* arg2: output directory (empty = default) */
    FilePath frontend_dir;    /* arg3: frontend directory (empty = default) */

    DebugLog("StartCDPServer: Entering...");

    /* Initialize FilePath structs as empty libc++ wstrings (all zeros) */
    InitEmptyFilePath(&output_dir);
    InitEmptyFilePath(&frontend_dir);
    DebugLog("StartCDPServer: FilePath size=%lu bytes (libc++ wstring)",
             (unsigned long)sizeof(FilePath));

    if (InterlockedCompareExchange(&g_cdp_started, 1, 0) != 0) {
        DebugLog("CDP already started, skipping");
        return;
    }

    DebugLog("StartCDPServer: g_start_server=0x%p, g_factory_vtable=0x%p",
             g_start_server, g_factory_vtable);

    if (!g_start_server || !g_factory_vtable) {
        DebugLog("StartCDPServer: Missing required symbols, aborting");
        InterlockedExchange(&g_cdp_started, 0);
        return;
    }

    /* Check DevToolsManager prerequisite */
    if (g_get_devtools_manager) {
        void* manager = g_get_devtools_manager();
        DebugLog("StartCDPServer: DevToolsManager @ 0x%p", manager);
        if (manager) {
            void* delegate = *(void**)((char*)manager + 8);
            DebugLog("StartCDPServer: DevToolsManager+8 (delegate) = 0x%p", delegate);
            if (!delegate) {
                DebugLog("StartCDPServer: WARNING - DevToolsManager delegate is NULL!");
                DebugLog("StartCDPServer: StartRemoteDebuggingServer will return early!");
            }
        } else {
            DebugLog("StartCDPServer: WARNING - DevToolsManager instance is NULL!");
        }
    } else {
        DebugLog("StartCDPServer: Cannot check DevToolsManager (symbol not found)");
    }

    /* Allocate factory using Chrome's allocator (Chrome takes ownership via unique_ptr) */
    if (g_chrome_new) {
        DebugLog("StartCDPServer: Using Chrome's operator new for allocation");
        factory = (TCPServerSocketFactory*)g_chrome_new(sizeof(TCPServerSocketFactory));
    } else {
        DebugLog("StartCDPServer: WARNING - Using HeapAlloc (may crash on free!)");
        factory = (TCPServerSocketFactory*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                      sizeof(TCPServerSocketFactory));
    }
    if (!factory) {
        DebugLog("StartCDPServer: Failed to allocate factory");
        InterlockedExchange(&g_cdp_started, 0);
        return;
    }
    /* Zero the memory if using Chrome's new (it doesn't zero) */
    if (g_chrome_new) {
        memset(factory, 0, sizeof(TCPServerSocketFactory));
    }

    /* Fill factory struct - only vtable and port (16 bytes total)
     * The CreateLocalHostServerSocket vtable function handles 127.0.0.1 binding internally
     */
    factory->vtable = g_factory_vtable;
    factory->port = CDP_PORT;
    /* Padding can be left uninitialized - matches working Edge behavior */

    DebugLog("Factory allocated @ 0x%p, vtable=0x%p, port=%u",
             factory, factory->vtable, factory->port);
    DebugLog("Factory struct: sizeof=%lu bytes (0x%lX)",
             (unsigned long)sizeof(TCPServerSocketFactory),
             (unsigned long)sizeof(TCPServerSocketFactory));

    /* Dump all 16 bytes of factory */
    DebugLog("Factory memory[0x00-0x0F]: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
             ((unsigned char*)factory)[0], ((unsigned char*)factory)[1],
             ((unsigned char*)factory)[2], ((unsigned char*)factory)[3],
             ((unsigned char*)factory)[4], ((unsigned char*)factory)[5],
             ((unsigned char*)factory)[6], ((unsigned char*)factory)[7],
             ((unsigned char*)factory)[8], ((unsigned char*)factory)[9],
             ((unsigned char*)factory)[10], ((unsigned char*)factory)[11],
             ((unsigned char*)factory)[12], ((unsigned char*)factory)[13],
             ((unsigned char*)factory)[14], ((unsigned char*)factory)[15]);

    /* unique_ptr is passed by pointer to the raw pointer */
    factory_ptr = factory;

    DebugLog("Calling StartRemoteDebuggingServer @ 0x%p ...", g_start_server);
    DebugLog("  rcx: &factory_ptr @ 0x%p (value=0x%p)", &factory_ptr, factory_ptr);
    DebugLog("  rdx: output_dir   @ 0x%p (empty)", &output_dir);
    DebugLog("  r8:  frontend_dir @ 0x%p (empty)", &frontend_dir);

    __try {
        /* Call the function - Chrome now owns factory memory */
        g_start_server(&factory_ptr, &output_dir, &frontend_dir);
        DebugLog("StartRemoteDebuggingServer returned successfully!");
        DebugLog("CDP server started on port %u", CDP_PORT);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        DebugLog("EXCEPTION in StartRemoteDebuggingServer! Code: 0x%08X", GetExceptionCode());
        InterlockedExchange(&g_cdp_started, 0);
    }
}

/* Subclassed window procedure */
static LRESULT CALLBACK SubclassWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_START_CDP) {
        DebugLog("SubclassWndProc: Received WM_START_CDP on thread %lu", GetCurrentThreadId());
        StartCDPServer();

        /* Restore original WndProc */
        if (g_original_wndproc) {
            SetWindowLongPtrA(hwnd, GWLP_WNDPROC, (LONG_PTR)g_original_wndproc);
            DebugLog("SubclassWndProc: Restored original WndProc");
        }

        return 0;
    }

    return CallWindowProcA(g_original_wndproc, hwnd, msg, wParam, lParam);
}

/* Find Edge's main browser window */
static HWND FindBrowserWindow(void) {
    HWND hwnd = NULL;
    DWORD our_pid = GetCurrentProcessId();
    int count = 0;

    DebugLog("FindBrowserWindow: Looking for Chrome_WidgetWin_1, our PID=%lu", our_pid);

    /* Enumerate all Chrome_WidgetWin_1 windows */
    hwnd = FindWindowA("Chrome_WidgetWin_1", NULL);
    while (hwnd) {
        DWORD window_pid = 0;
        DWORD window_tid = GetWindowThreadProcessId(hwnd, &window_pid);
        count++;

        DebugLog("FindBrowserWindow: Found hwnd=0x%p, pid=%lu, tid=%lu, parent=0x%p, visible=%d",
                 hwnd, window_pid, window_tid, GetParent(hwnd), IsWindowVisible(hwnd));

        if (window_pid == our_pid) {
            /* Verify it's a top-level window */
            if (GetParent(hwnd) == NULL && IsWindowVisible(hwnd)) {
                DebugLog("FindBrowserWindow: Selected hwnd=0x%p (tid=%lu)", hwnd, window_tid);
                return hwnd;
            }
        }

        hwnd = FindWindowExA(NULL, hwnd, "Chrome_WidgetWin_1", NULL);
    }

    DebugLog("FindBrowserWindow: Checked %d windows, none matched", count);
    return NULL;
}

/* Main injection worker thread */
static DWORD WINAPI InjectionThread(LPVOID param) {
    (void)param;

    DebugLog("===========================================");
    DebugLog("InjectionThread: Started on thread %lu", GetCurrentThreadId());
    DebugLog("InjectionThread: PID=%lu", GetCurrentProcessId());
    DebugLog("===========================================");

    /* Resolve symbols */
    DebugLog("InjectionThread: Calling ResolveSymbols...");
    if (!ResolveSymbols()) {
        DebugLog("InjectionThread: Symbol resolution failed!");
        return 1;
    }
    DebugLog("InjectionThread: Symbol resolution succeeded");

    /* Find browser window */
    DebugLog("InjectionThread: Calling FindBrowserWindow...");
    g_target_hwnd = FindBrowserWindow();
    if (!g_target_hwnd) {
        DebugLog("InjectionThread: Failed to find browser window!");
        return 1;
    }
    DebugLog("InjectionThread: Found browser window: 0x%p", g_target_hwnd);

    /* Subclass the window to intercept messages */
    DebugLog("InjectionThread: Subclassing window...");
    g_original_wndproc = (WNDPROC)SetWindowLongPtrA(g_target_hwnd, GWLP_WNDPROC,
                                                     (LONG_PTR)SubclassWndProc);
    if (!g_original_wndproc) {
        DebugLog("InjectionThread: SetWindowLongPtrA failed: %lu", GetLastError());
        return 1;
    }
    DebugLog("InjectionThread: Window subclassed, original WndProc: 0x%p", g_original_wndproc);

    /* Post message to trigger CDP start on UI thread */
    DebugLog("InjectionThread: Posting WM_START_CDP (0x%X) to hwnd 0x%p...", WM_START_CDP, g_target_hwnd);
    if (!PostMessageA(g_target_hwnd, WM_START_CDP, 0, 0)) {
        DebugLog("InjectionThread: PostMessage failed: %lu", GetLastError());
        /* Restore WndProc on failure */
        SetWindowLongPtrA(g_target_hwnd, GWLP_WNDPROC, (LONG_PTR)g_original_wndproc);
        return 1;
    }
    DebugLog("InjectionThread: Posted WM_START_CDP message successfully");
    DebugLog("InjectionThread: Exiting, waiting for UI thread to process message...");

    return 0;
}

/* DLL entry point */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    (void)reserved;
    HANDLE hThread;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_this_module = hModule;
        DisableThreadLibraryCalls(hModule);

        DebugLog("###############################################");
        DebugLog("DllMain: DLL_PROCESS_ATTACH");
        DebugLog("DllMain: Module=0x%p, PID=%lu", hModule, GetCurrentProcessId());
        DebugLog("###############################################");

        /* Start worker thread (don't block DllMain) */
        hThread = CreateThread(NULL, 0, InjectionThread, NULL, 0, NULL);
        if (hThread) {
            DebugLog("DllMain: Worker thread created");
            CloseHandle(hThread);
        } else {
            DebugLog("DllMain: CreateThread failed: %lu", GetLastError());
        }
        break;

    case DLL_PROCESS_DETACH:
        DebugLog("DllMain: DLL_PROCESS_DETACH");
        /* Restore WndProc if still subclassed */
        if (g_target_hwnd && g_original_wndproc) {
            SetWindowLongPtrA(g_target_hwnd, GWLP_WNDPROC, (LONG_PTR)g_original_wndproc);
            DebugLog("DllMain: Restored WndProc on detach");
        }
        break;
    }

    return TRUE;
}
