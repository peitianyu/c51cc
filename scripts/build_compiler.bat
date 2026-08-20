@echo off
REM ======================================
REM  C51CC / C251CC build script (TCC)
REM  Usage: build_compiler.bat [c51cc|c251cc|my.exe]
REM    c51cc.exe  (default) - link C51 backend
REM    c251cc.exe           - link C251 backend (-DC251CC_BUILD)
REM ======================================
setlocal enabledelayedexpansion
set OUT=%~1
if "%OUT%"=="" set OUT=c51cc.exe

REM 按文件名(非路径)判定后端分支: 允许 scripts\c251cc.exe 等带路径的 OUT
for %%F in ("%OUT%") do set OUTNAME=%%~nxF

set ROOT=%~dp0..
set SRCS=%ROOT%\src\main.c
for %%f in (%ROOT%\src\core\*.c) do set SRCS=!SRCS! %%f

if /i "%OUTNAME%"=="c251cc.exe" (
    for %%f in (%ROOT%\src\core\c251\*.c) do (
        REM c251_libc.c 是系统库源码 (供 c251cc 编译消费), 不链接进编译器二进制
        if /i not "%%~nxf"=="c251_libc.c" set SRCS=!SRCS! %%f
    )
    set EXTRA=-DC251CC_BUILD
) else (
    for %%f in (%ROOT%\src\core\c51\*.c) do set SRCS=!SRCS! %%f
    set EXTRA=
)
tcc %EXTRA% !SRCS! -o %OUT%
if %ERRORLEVEL% NEQ 0 (
    echo Build FAILED.
    exit /b 1
)
echo Build OK: %OUT%
