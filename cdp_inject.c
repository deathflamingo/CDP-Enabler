/*
 * CDP Injector DLL for Microsoft Edge
 * Enables Chrome DevTools Protocol on a running Edge browser process.
 * For security research purposes only.
 *
 * Build: cl /LD /O2 cdp_inject.c /Fe:cdp_inject.dll user32.lib
 *
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

/* Set this to 1 to enable debug logging, 0 to disable (no-op) */
#define DEBUG_ENABLED 1

#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")

/* Configuration */
#define CDP_PORT 8181
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
 * Signatures extracted from msedge.dll version 143.0.3650.96
 * These are the minimum unique byte sequences to identify each symbol.
 */

/* Signature for StartRemoteDebuggingServer (in .text section)
 * RVA: 0x02CED39A, 26 bytes minimum */
static const uint8_t SIG_START_SERVER[] = {
    0x41, 0x57, 0x41, 0x56, 0x41, 0x54, 0x56, 0x57,
    0x53, 0x48, 0x83, 0xEC, 0x48, 0x4C, 0x89, 0xC3,
    0x48, 0x89, 0xD7, 0x48, 0x89, 0xCE, 0x48, 0x8B,
    0x05, 0x89
};
#define SIG_START_SERVER_LEN 26

/* Signature for operator new (in .text section)
 * RVA: 0x03263588, 10 bytes minimum */
static const uint8_t SIG_OPERATOR_NEW[] = {
    0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B,
    0xD9, 0xEB
};
#define SIG_OPERATOR_NEW_LEN 10

/* Signature for DevToolsManager::GetInstance (in .text section)
 * RVA: 0x021B6B94, 16 bytes minimum */
static const uint8_t SIG_GET_INSTANCE[] = {
    0xE9, 0x01, 0x00, 0x00, 0x00, 0xCC, 0x56, 0x57,
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x35, 0x89
};
#define SIG_GET_INSTANCE_LEN 16

/* To find the TCPServerSocketFactory vtable, we:
 * 1. Find vtable entry functions by signature 
 * 2. Search .rdata for consecutive pointers to these functions
 *
 * vtable[0] = scalar deleting destructor
 * vtable[1] = CreateForHttpServer
 */

/* Signature for scalar deleting destructor (vtable[0])
 * Bytes 17-20 are a relative call offset (E8 xx xx xx xx) - use wildcards
 * Extended to include next function's prologue for uniqueness */
static const uint8_t SIG_VTABLE_ENTRY0[] = {
    0x56, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCE,  /* 0-7 */
    0xF6, 0xC2, 0x01, 0x74, 0x08, 0x48, 0x89, 0xF1,  /* 8-15 */
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xF0,  /* 16-23: E8=call opcode, 17-20=wildcard */
    0x48, 0x83, 0xC4, 0x20, 0x5E, 0xC3, 0xCC, 0xCC,  /* 24-31 */
    0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x89   /* 32-39: next function's prologue */
};
static const uint8_t SIG_VTABLE_ENTRY0_MASK[] = {
    1, 1, 1, 1, 1, 1, 1, 1,  /* 0-7: must match */
    1, 1, 1, 1, 1, 1, 1, 1,  /* 8-15: must match */
    1, 0, 0, 0, 0, 1, 1, 1,  /* 16-23: E8 must match, 17-20 wildcard, rest match */
    1, 1, 1, 1, 1, 1, 1, 1,  /* 24-31: must match */
    1, 1, 1, 1, 1, 1, 1, 1   /* 32-39: must match (next func prologue) */
};
#define SIG_VTABLE_ENTRY0_LEN 40

/* Signature for CreateForHttpServer (vtable[1]) */
static const uint8_t SIG_VTABLE_ENTRY1[] = {
    0x48, 0x89, 0xD0, 0x0F, 0xB7, 0x51, 0x08, 0x48,
    0x89, 0xC1, 0xE9
};
#define SIG_VTABLE_ENTRY1_LEN 11

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

/* Resolve symbols using signature scanning */
static BOOL ResolveSymbolsBySig(void** out_start_server,
                                 void** out_chrome_new,
                                 void** out_get_instance,
                                 void** out_vtable) {
    HMODULE msedge = NULL;
    uint8_t* text_start = NULL;
    uint8_t* rdata_start = NULL;
    size_t text_size = 0;
    size_t rdata_size = 0;
    void* addr;
    int found = 0;

    DebugLog("ResolveSymbolsBySig: Starting signature-based resolution...");

    msedge = GetModuleHandleA("msedge.dll");
    if (!msedge) {
        DebugLog("ResolveSymbolsBySig: Failed to get msedge.dll handle");
        return FALSE;
    }
    DebugLog("ResolveSymbolsBySig: msedge.dll @ 0x%p", msedge);

    /* Get .text section for code signatures */
    if (!GetSectionInfo(msedge, ".text", &text_start, &text_size)) {
        DebugLog("ResolveSymbolsBySig: Failed to find .text section");
        return FALSE;
    }
    DebugLog("ResolveSymbolsBySig: .text section @ 0x%p, size=0x%zX", text_start, text_size);

    /* Get .rdata section for vtable signature */
    if (!GetSectionInfo(msedge, ".rdata", &rdata_start, &rdata_size)) {
        DebugLog("ResolveSymbolsBySig: Failed to find .rdata section");
        return FALSE;
    }
    DebugLog("ResolveSymbolsBySig: .rdata section @ 0x%p, size=0x%zX", rdata_start, rdata_size);

    /* Scan for StartRemoteDebuggingServer */
    DebugLog("ResolveSymbolsBySig: Scanning for StartRemoteDebuggingServer...");
    addr = ScanForSignature(text_start, text_size, SIG_START_SERVER, NULL, SIG_START_SERVER_LEN);
    if (addr) {
        DebugLog("ResolveSymbolsBySig: [SIG] StartRemoteDebuggingServer @ 0x%p", addr);
        *out_start_server = addr;
        found++;
    } else {
        DebugLog("ResolveSymbolsBySig: StartRemoteDebuggingServer NOT FOUND!");
    }

    /* Scan for operator new */
    DebugLog("ResolveSymbolsBySig: Scanning for operator new...");
    addr = ScanForSignature(text_start, text_size, SIG_OPERATOR_NEW, NULL, SIG_OPERATOR_NEW_LEN);
    if (addr) {
        DebugLog("ResolveSymbolsBySig: [SIG] operator new @ 0x%p", addr);
        *out_chrome_new = addr;
        found++;
    } else {
        DebugLog("ResolveSymbolsBySig: operator new NOT FOUND!");
    }

    /* Scan for DevToolsManager::GetInstance */
    DebugLog("ResolveSymbolsBySig: Scanning for DevToolsManager::GetInstance...");
    addr = ScanForSignature(text_start, text_size, SIG_GET_INSTANCE, NULL, SIG_GET_INSTANCE_LEN);
    if (addr) {
        DebugLog("ResolveSymbolsBySig: [SIG] GetInstance @ 0x%p", addr);
        *out_get_instance = addr;
        found++;
    } else {
        DebugLog("ResolveSymbolsBySig: GetInstance NOT FOUND!");
    }

    /* Find TCPServerSocketFactory vtable by:
     * 1. Find vtable entry functions by signature
     * 2. Search .rdata for consecutive pointers to these functions
     */
    {
        void* entry0_fn = NULL;  /* scalar deleting destructor */
        void* entry1_fn = NULL;  /* CreateForHttpServer */

        DebugLog("ResolveSymbolsBySig: Finding vtable entry functions by signature...");

        /* Find vtable[0] - scalar deleting destructor (uses mask for wildcard call offset) */
        entry0_fn = ScanForSignature(text_start, text_size, SIG_VTABLE_ENTRY0, SIG_VTABLE_ENTRY0_MASK, SIG_VTABLE_ENTRY0_LEN);
        if (entry0_fn) {
            DebugLog("ResolveSymbolsBySig: vtable[0] (destructor) @ 0x%p", entry0_fn);
        } else {
            DebugLog("ResolveSymbolsBySig: vtable[0] NOT FOUND");
        }

        /* Find vtable[1] - CreateForHttpServer */
        entry1_fn = ScanForSignature(text_start, text_size, SIG_VTABLE_ENTRY1, NULL, SIG_VTABLE_ENTRY1_LEN);
        if (entry1_fn) {
            DebugLog("ResolveSymbolsBySig: vtable[1] (CreateForHttpServer) @ 0x%p", entry1_fn);
        } else {
            DebugLog("ResolveSymbolsBySig: vtable[1] NOT FOUND");
        }

        /* Search .rdata for consecutive pointers to these functions */
        if (entry0_fn && entry1_fn) {
            const uint64_t* p = (const uint64_t*)rdata_start;
            const uint64_t* end = (const uint64_t*)(rdata_start + rdata_size - 16);
            addr = NULL;

            DebugLog("ResolveSymbolsBySig: Searching .rdata for vtable...");
            while (p < end) {
                if (p[0] == (uint64_t)entry0_fn && p[1] == (uint64_t)entry1_fn) {
                    addr = (void*)p;
                    break;
                }
                p++;
            }

            if (addr) {
                DebugLog("ResolveSymbolsBySig: [SIG] Factory vtable @ 0x%p", addr);
                *out_vtable = addr;
                found++;
            } else {
                DebugLog("ResolveSymbolsBySig: Factory vtable NOT FOUND in .rdata");
            }
        }
    }

    DebugLog("ResolveSymbolsBySig: Found %d/4 symbols via signature", found);
    return (found == 4);
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

    /* Set globals */
    g_start_server = (StartRemoteDebuggingServerFn)start_server;
    g_chrome_new = (ChromeNewFn)chrome_new;
    g_get_devtools_manager = (GetDevToolsManagerFn)get_instance;
    g_factory_vtable = vtable;

    DebugLog("ResolveSymbols: All symbols resolved via signatures!");
    DebugLog("ResolveSymbols: StartRemoteDebuggingServer @ 0x%p", g_start_server);
    DebugLog("ResolveSymbols: operator new @ 0x%p", g_chrome_new);
    DebugLog("ResolveSymbols: DevToolsManager::GetInstance @ 0x%p", g_get_devtools_manager);
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
