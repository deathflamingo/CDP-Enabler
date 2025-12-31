@echo off
REM Build script for Edge CDP Injector
REM Run from x64 Native Tools Command Prompt for VS

echo === Building Edge CDP Injector ===
echo.

REM Check for cl.exe
where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: cl.exe not found. Run from x64 Native Tools Command Prompt
    exit /b 1
)

REM Check for x64 environment
if "%VSCMD_ARG_TGT_ARCH%"=="x86" (
    echo ERROR: You are in an x86 environment. Use "x64 Native Tools Command Prompt" instead.
    exit /b 1
)
if not "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    if not "%VSCMD_ARG_TGT_ARCH%"=="x64" (
        echo WARNING: May not be x64 environment. Ensure you use x64 Native Tools Command Prompt.
    )
)

REM Create output directory
if not exist bin mkdir bin

echo [1/2] Building cdp_inject.dll...
cl /nologo /LD /O2 /W3 /GS- cdp_inject.c /Fe:bin\cdp_inject.dll /link user32.lib /DEF:NUL
if %errorlevel% neq 0 (
    echo FAILED to build cdp_inject.dll
    exit /b 1
)

echo [2/2] Building injector.exe...
cl /nologo /O2 /W3 /D_CRT_SECURE_NO_WARNINGS injector.c /Fe:bin\injector.exe /link advapi32.lib user32.lib
if %errorlevel% neq 0 (
    echo FAILED to build injector.exe
    exit /b 1
)

REM Cleanup intermediate files
del /q *.obj 2>nul
del /q bin\*.obj 2>nul
del /q bin\*.lib 2>nul
del /q bin\*.exp 2>nul

echo.
echo === Build complete ===
echo Output: bin\cdp_inject.dll
echo         bin\injector.exe
echo.
echo Usage: bin\injector.exe [dll_path] [pid]
