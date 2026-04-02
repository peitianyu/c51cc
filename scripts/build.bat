@echo off
REM ======================================
REM  C51CC Windows 构建脚本 (TCC)
REM  用法: build.bat
REM
REM  测试模式 (默认): 运行交互式 minitest
REM  正式编译器:      build_compiler.bat
REM ======================================
setlocal enabledelayedexpansion

REM main.c 必须第一个, minitest_end.c 必须最后一个 (section 顺序)
set SRCS=..\src\main.c
for %%f in (..\src\core\*.c) do set SRCS=!SRCS! %%f
for %%f in (..\src\core\c51\*.c) do set SRCS=!SRCS! %%f
set SRCS=!SRCS! ..\src\minitest_end.c

tcc %SRCS% -run -DMINITEST_IMPLEMENTATION %*
endlocal
