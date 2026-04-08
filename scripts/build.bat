@REM @echo off
@REM REM ======================================
@REM REM  C51CC Windows 构建脚本 (TCC)
@REM REM  用法: build.bat
@REM REM
@REM REM  测试模式 (默认): 运行交互式 minitest
@REM REM  正式编译器:      build_compiler.bat
@REM REM ======================================
@REM setlocal enabledelayedexpansion

@REM REM main.c 必须第一个, minitest_end.c 必须最后一个 (section 顺序)
@REM set SRCS=..\src\main.c
@REM for %%f in (..\src\core\*.c) do set SRCS=!SRCS! %%f
@REM for %%f in (..\src\core\c51\*.c) do set SRCS=!SRCS! %%f
@REM set SRCS=!SRCS! ..\src\minitest_end.c

@REM tcc %SRCS% -run -DMINITEST_IMPLEMENTATION %*
@REM endlocal

.\build_compiler.bat
.\c51cc.exe 
