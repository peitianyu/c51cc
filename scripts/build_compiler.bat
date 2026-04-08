@echo off
REM ======================================
REM  C51CC 正式编译器构建脚本 (TCC)
REM  构建出 c51cc.exe 编译器本身
REM
REM  用法: build_compiler.bat [输出名称]
REM
REM  示例:
REM    build_compiler.bat
REM    build_compiler.bat my_c51cc.exe
REM ======================================
setlocal enabledelayedexpansion

set OUT=%~1
if "%OUT%"=="" set OUT=c51cc.exe

set SRCS=D:\ws\test\C51CC\src\main.c
for %%f in (D:\ws\test\C51CC\src\core\*.c) do set SRCS=!SRCS! %%f
for %%f in (D:\ws\test\C51CC\src\core\c51\*.c) do set SRCS=!SRCS! %%f

echo Building %OUT% ...
tcc %SRCS% -o %OUT%
if %ERRORLEVEL% NEQ 0 (
    echo Build FAILED.
    exit /b 1
)
echo Build OK: %OUT%
REM Also copy to scripts\c51cc.exe so that build_all.bat picks up the new compiler
if not "%OUT%"=="scripts\c51cc.exe" (
    if exist "%~dp0" (
        copy /Y "%OUT%" "%~dp0c51cc.exe" >nul 2>&1
    )
)
endlocal
