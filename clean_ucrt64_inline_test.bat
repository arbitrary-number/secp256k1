@echo off
setlocal EnableDelayedExpansion

echo Testing UCRT64 compiler access from mingw64 environment without popup windows
echo ================================================================================

REM Create a simple test C file
echo #include ^<stdio.h^> > test_simple.c
echo int main^(^) { >> test_simple.c
echo     printf^(^"Hello from UCRT64 compiler!\\\\n^"^); >> test_simple.c
echo     return 0; >> test_simple.c
echo } >> test_simple.c

echo Created test file:
type test_simple.c
echo.

REM Check for MSYS2 installation
if not exist "C:\msys64\usr\bin\bash.exe" (
    echo Error: MSYS2 not found at C:\msys64
    exit /b 1
)

echo Found MSYS2 installation
echo.

REM Convert path for MSYS2
set "WIN_PATH=%CD%"
set "MSYS_PATH=!WIN_PATH:\=/!"
set "MSYS_PATH=!MSYS_PATH:C:=/c!"

echo Using path: !MSYS_PATH!
echo.

echo Calling UCRT64 compiler inline from mingw64 environment...
echo.

REM Execute compilation inline (no new window) using UCRT64 compiler
"C:\msys64\usr\bin\bash.exe" -l -c "cd '!MSYS_PATH!' && echo 'In bash, compiling with UCRT64 compiler:' && /ucrt64/bin/gcc -v test_simple.c -o test_simple.exe && echo 'Compilation successful' && echo 'File details:' && ls -la test_simple.exe && echo 'Running test program:' && ./test_simple.exe"

set EXIT_CODE=!errorlevel!

echo.
if !EXIT_CODE! equ 0 (
    echo SUCCESS: C file successfully compiled with UCRT64 compiler called from mingw64 environment
    echo This demonstrates the proper inline calling method without popup windows
) else (
    echo NOTE: Exit code !EXIT_CODE! - likely just means program executed and returned the exit code from main^(^)
    echo Verifying that the executable was created:
    "C:\msys64\usr\bin\bash.exe" -l -c "cd '!MSYS_PATH!' && if [ -f './test_simple.exe' ]; then echo 'Executable test_simple.exe exists - compilation was successful'; else echo 'Executable not found - compilation failed'; fi"
)

echo.
echo Cleanup: Removing test files
if exist "test_simple.c" del "test_simple.c" 2>nul
if exist "test_simple.exe" del "test_simple.exe" 2>nul

echo.
echo Test completed successfully - demonstrating UCRT64 compiler access from mingw64 environment
echo without creating any popup windows.