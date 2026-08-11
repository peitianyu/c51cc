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

set ROOT=%~dp0..
set SRCS=%ROOT%\src\main.c
for %%f in (%ROOT%\src\core\*.c) do set SRCS=!SRCS! %%f

if /i "%OUT%"=="c251cc.exe" (
    for %%f in (%ROOT%\src\core\c251\*.c) do set SRCS=!SRCS! %%f
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
