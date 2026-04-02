@echo off
REM ======================================
REM  C51CC 批量编译 single-exec 脚本
REM  编译 code/c-testsuite/tests/single-exec 中所有 .c 文件
REM  输出到 output/c51cc/single-exec
REM
REM  用法: build_c51cc_single_exec.bat [c51cc路径] [源目录] [输出目录]
REM ======================================
setlocal EnableExtensions EnableDelayedExpansion

call :resolve_path "%~dp0" SCRIPT_DIR
call :resolve_path "%SCRIPT_DIR%.." REPO_ROOT

if "%~1"=="" (
    set "C51CC=%SCRIPT_DIR%c51cc.exe"
) else (
    call :resolve_path "%~1" C51CC
)

if "%~2"=="" (
    call :resolve_path "%REPO_ROOT%\code\c-testsuite\tests\single-exec" SOURCE_DIR
) else (
    call :resolve_path "%~2" SOURCE_DIR
)

if "%~3"=="" (
    call :resolve_path "%REPO_ROOT%\output\c51cc\single-exec" OUTPUT_DIR
) else (
    call :resolve_path "%~3" OUTPUT_DIR
)

if not exist "%C51CC%" (
    echo [ERROR] c51cc not found: %C51CC%
    exit /b 1
)
if not exist "%SOURCE_DIR%" (
    echo [ERROR] Source directory not found: %SOURCE_DIR%
    exit /b 1
)

if exist "%OUTPUT_DIR%" rmdir /s /q "%OUTPUT_DIR%"
mkdir "%OUTPUT_DIR%"

set /a TOTAL=0
set /a OK=0
set /a FAIL=0

echo [INFO] c51cc   : %C51CC%
echo [INFO] Source  : %SOURCE_DIR%
echo [INFO] Output  : %OUTPUT_DIR%
echo.

for %%F in ("%SOURCE_DIR%\*.c") do (
    set /a TOTAL+=1
    set "SRC=%%~fF"
    set "NAME=%%~nF"
    set "DEST=%OUTPUT_DIR%\!NAME!"

    mkdir "!DEST!" >nul 2>nul

    "%C51CC%" -asm -hex -o "!DEST!\!NAME!" "!SRC!" >nul 2>"!DEST!\compile.log"
    set "CC_ERR=!ERRORLEVEL!"
    if "!CC_ERR!"=="0" (
        if exist "!DEST!\!NAME!.asm" (
            set /a OK+=1
            echo [OK  ] !NAME!
        ) else (
            set /a FAIL+=1
            echo [FAIL] !NAME! ^(no output^)
        )
    ) else (
        set /a FAIL+=1
        echo [FAIL] !NAME!
        type "!DEST!\compile.log"
    )
)

echo.
echo [SUMMARY] Total: %TOTAL%   OK: %OK%   FAIL: %FAIL%

if %FAIL% GTR 0 exit /b 1
exit /b 0

:resolve_path
for %%I in ("%~1") do set "%~2=%%~fI"
exit /b 0
