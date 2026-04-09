call .\build_compiler.bat

@echo off
setlocal EnableExtensions EnableDelayedExpansion

call :resolve_path "%~dp0.." REPO_ROOT
if "%~1"=="" (
    call :resolve_path "%REPO_ROOT%\test" SOURCE_DIR
) else (
    call :resolve_path "%~1" SOURCE_DIR
)

:: [NEW] 检测单文件模式：如果第一个参数是 .c 文件，则记录并调整 SOURCE_DIR 为文件所在目录
set "SINGLE_FILE_MODE=0"
set "SINGLE_FILE_PATH="
if not "%~1"=="" (
    if exist "%~1" (
        if /I "%~x1"==".c" (
            set "SINGLE_FILE_MODE=1"
            set "SINGLE_FILE_PATH=!SOURCE_DIR!"
            for %%I in ("!SOURCE_DIR!") do set "SOURCE_DIR=%%~dpI"
            if "!SOURCE_DIR:~-1!"=="\" set "SOURCE_DIR=!SOURCE_DIR:~0,-1!"
        )
    )
)

if "%~2"=="" (
    call :resolve_path "%REPO_ROOT%\output" OUTPUT_ROOT
) else (
    call :resolve_path "%~2" OUTPUT_ROOT
)

set "KEIL_BIN=%REPO_ROOT%\_tools\keil\C51\BIN"
set "KEIL_LIB=%REPO_ROOT%\_tools\keil\C51\LIB"
set "KEIL_INC=%REPO_ROOT%\_tools\keil\C51\INC"
set "KEIL_INC_ATMEL=%REPO_ROOT%\_tools\keil\C51\INC\Atmel"
set "C51CC_EXE=%REPO_ROOT%\scripts\c51cc.exe"

if not exist "%SOURCE_DIR%" (
    echo [ERROR] Source directory not found: %SOURCE_DIR%
    exit /b 1
)

call :require_file "%KEIL_BIN%\C51.exe"
if errorlevel 1 exit /b 1
call :require_file "%KEIL_BIN%\A51.EXE"
if errorlevel 1 exit /b 1
call :require_file "%KEIL_BIN%\BL51.EXE"
if errorlevel 1 exit /b 1
call :require_file "%KEIL_BIN%\OH51.EXE"
if errorlevel 1 exit /b 1
call :require_file "%KEIL_LIB%\C51S.LIB"
if errorlevel 1 exit /b 1
call :require_file "%C51CC_EXE%"
if errorlevel 1 exit /b 1

for %%I in ("%SOURCE_DIR%") do set "SOURCE_TAG=%%~nxI"
set "KEIL_OUT=%OUTPUT_ROOT%\keil\%SOURCE_TAG%"
set "C51CC_OUT=%OUTPUT_ROOT%\c51cc\%SOURCE_TAG%"
set "TMP_ROOT=%REPO_ROOT%\.tmp\build_all\%SOURCE_TAG%"

if exist "%KEIL_OUT%" rmdir /s /q "%KEIL_OUT%"
if exist "%C51CC_OUT%" rmdir /s /q "%C51CC_OUT%"
if exist "%TMP_ROOT%" rmdir /s /q "%TMP_ROOT%"

mkdir "%KEIL_OUT%" >nul 2>nul
mkdir "%C51CC_OUT%" >nul 2>nul
mkdir "%TMP_ROOT%" >nul 2>nul

set /a PROJECT_COUNT=0
set /a KEIL_OK=0
set /a KEIL_FAIL=0
set /a C51CC_OK=0
set /a C51CC_FAIL=0

echo [INFO] Source : %SOURCE_DIR%
echo [INFO] Output : %OUTPUT_ROOT%
echo.

:: [NEW] 根据模式选择处理方式：单文件直接调用，否则遍历目录
if "%SINGLE_FILE_MODE%"=="1" (
    call :dispatch_project "%SINGLE_FILE_PATH%"
) else (
    for /r "%SOURCE_DIR%" %%F in (*.c) do call :dispatch_project "%%~fF"
)

echo.
echo [SUMMARY] Projects   : %PROJECT_COUNT%
echo [SUMMARY] Keil       : %KEIL_OK% success, %KEIL_FAIL% failed
echo [SUMMARY] C51CC      : %C51CC_OK% success, %C51CC_FAIL% failed

if %KEIL_FAIL% GTR 0 set "HAS_FAILURE=1"
if %C51CC_FAIL% GTR 0 set "HAS_FAILURE=1"

if exist "%TMP_ROOT%" rmdir /s /q "%TMP_ROOT%"

if defined HAS_FAILURE exit /b 1
exit /b 0

:dispatch_project
set "ENTRY_FILE=%~1"
for %%I in ("%ENTRY_FILE%") do (
    set "ENTRY_DIR=%%~dpI"
    set "ENTRY_NAME=%%~nI"
)

if "%ENTRY_DIR:~-1%"=="\" set "ENTRY_DIR=%ENTRY_DIR:~0,-1%"
set "PROJECT_NAME=%ENTRY_NAME%"
set "EXTRA_FILE="

if /I "%ENTRY_NAME:~-4%"=="_lib" (
    set "PAIRED_MAIN=%ENTRY_NAME:_lib=_main%"
    if exist "%ENTRY_DIR%\%PAIRED_MAIN%.c" exit /b 0
)

if /I "%ENTRY_NAME:~-5%"=="_main" (
    set "PROJECT_NAME=%ENTRY_NAME:~0,-5%"
    if exist "%ENTRY_DIR%\%PROJECT_NAME%_lib.c" set "EXTRA_FILE=%ENTRY_DIR%\%PROJECT_NAME%_lib.c"
)

if "%EXTRA_FILE%"=="" (
    call :has_main "%ENTRY_FILE%"
    if errorlevel 1 (
        echo [SKIP] %ENTRY_NAME%.c ^(no main found^)
        exit /b 0
    )
)

set /a PROJECT_COUNT+=1
echo [PROJECT %PROJECT_COUNT%] %PROJECT_NAME%
call :build_keil "%PROJECT_NAME%" "%ENTRY_FILE%" "%EXTRA_FILE%"
call :build_c51cc "%PROJECT_NAME%" "%ENTRY_FILE%" "%EXTRA_FILE%"
echo.
exit /b 0

:build_keil
set "PROJECT_NAME=%~1"
set "ENTRY_FILE=%~2"
set "EXTRA_FILE=%~3"

call :prepare_paths "%PROJECT_NAME%" "%ENTRY_FILE%" "%KEIL_OUT%" "keil"
call :stage_source_tree "%ENTRY_DIR%" "%WORK_DIR%\src"
if errorlevel 1 goto :keil_fail

REM Also stage include dir if it exists alongside source tree
set "PARENT_INCLUDE=%ENTRY_DIR%\..\include"
if exist "%PARENT_INCLUDE%\" (
    call :stage_source_tree "%PARENT_INCLUDE%" "%WORK_DIR%\include"

    if exist "%REPO_ROOT%\STARTUP.A51" (
        copy /y "%REPO_ROOT%\STARTUP.A51" "%WORK_DIR%\STARTUP.A51" >nul
    )
)

pushd "%WORK_DIR%\src" >nul

echo   [Keil] compiling %ENTRY_FILE_NAME%
call :keil_compile_one "%ENTRY_FILE_NAME%"
if errorlevel 1 goto :keil_fail_pop

set "EXTRA_BASE="
set "EXTRA_FILE_NAME="
if not "%EXTRA_FILE%"=="" (
    for %%I in ("%EXTRA_FILE%") do (
        set "EXTRA_BASE=%%~nI"
        set "EXTRA_FILE_NAME=%%~nxI"
    )
    echo   [Keil] compiling %EXTRA_FILE_NAME%
    call :keil_compile_one "%EXTRA_FILE_NAME%"
    if errorlevel 1 goto :keil_fail_pop
)

REM Auto-include delay.c from ../include if present and not already an EXTRA_FILE
if "%EXTRA_BASE%"=="" (
    @REM if exist "..\include\delay.c" (
    @REM     copy /y "..\include\delay.c" "delay.c" >nul
    @REM     set "EXTRA_BASE=delay"
    @REM     set "EXTRA_FILE_NAME=delay.c"
    @REM     echo   [Keil] compiling delay.c (from include)
    @REM     call :keil_compile_one "delay.c"
    @REM     if errorlevel 1 goto :keil_fail_pop
    @REM )
)

if exist "STARTUP.A51" (
    echo   [Keil] assembling STARTUP.A51
    "%KEIL_BIN%\A51.EXE" "STARTUP.A51" "OBJECT(STARTUP.obj)"
)
if not exist "STARTUP.obj" (
    copy /y "%KEIL_LIB%\STARTUP.A51" "STARTUP.A51" >nul
    echo   [Keil] assembling bundled STARTUP.A51
    "%KEIL_BIN%\A51.EXE" "STARTUP.A51" "OBJECT(STARTUP.obj)"
)
if not exist "STARTUP.obj" goto :keil_fail_pop

copy /y "%KEIL_LIB%\C51S.LIB" "C51S.LIB" >nul
set "LINK_INPUTS=%ENTRY_BASE%.obj"
if defined EXTRA_BASE set "LINK_INPUTS=%LINK_INPUTS%,%EXTRA_BASE%.obj"
set "LINK_INPUTS=%LINK_INPUTS%,STARTUP.obj,C51S.LIB"

echo   [Keil] linking %PROJECT_NAME%.hex
"%KEIL_BIN%\BL51.EXE" "%LINK_INPUTS%" "TO" "%PROJECT_NAME%.abs"
if errorlevel 1 goto :keil_fail_pop

"%KEIL_BIN%\OH51.EXE" "%PROJECT_NAME%.abs"
if errorlevel 1 goto :keil_fail_pop
if not exist "%PROJECT_NAME%.hex" goto :keil_fail_pop

mkdir "%DEST_DIR%" >nul 2>nul
copy /y "%ENTRY_BASE%.SRC" "%DEST_DIR%\%ENTRY_BASE%.asm" >nul
if defined EXTRA_BASE copy /y "%EXTRA_BASE%.SRC" "%DEST_DIR%\%EXTRA_BASE%.asm" >nul
copy /y "%PROJECT_NAME%.hex" "%DEST_DIR%\%PROJECT_NAME%.hex" >nul

popd >nul
set /a KEIL_OK+=1
echo   [Keil] done
exit /b 0

:keil_fail_pop
popd >nul
:keil_fail
set /a KEIL_FAIL+=1
echo   [Keil] failed
exit /b 0


:build_c51cc
set "PROJECT_NAME=%~1"
set "ENTRY_FILE=%~2"
set "EXTRA_FILE=%~3"

call :prepare_paths "%PROJECT_NAME%" "%ENTRY_FILE%" "%C51CC_OUT%" "c51cc"
call :stage_source_tree "%ENTRY_DIR%" "%WORK_DIR%\src"
if errorlevel 1 goto :c51cc_fail

set "PARENT_INCLUDE=%ENTRY_DIR%\..\include"
if exist "%PARENT_INCLUDE%\" (
    call :stage_source_tree "%PARENT_INCLUDE%" "%WORK_DIR%\include"
)

if exist "%REPO_ROOT%\STARTUP.A51" (
    copy /y "%REPO_ROOT%\STARTUP.A51" "%WORK_DIR%\src\STARTUP.A51" >nul
)

pushd "%WORK_DIR%\src" >nul

echo   [C51CC] compiling %PROJECT_NAME%

set "C51CC_IFLAGS=-I..\include"
if not exist "..\include\" set "C51CC_IFLAGS="

set "C51CC_EXTRA_SRC="
if not "%EXTRA_FILE%"=="" (
    for %%I in ("%EXTRA_FILE%") do set "C51CC_EXTRA_SRC=%%~nxI"
)

REM Check for delay.c in include dir when no extra file is given
if "%C51CC_EXTRA_SRC%"=="" (
    @REM if exist "..\include\delay.c" set "C51CC_EXTRA_SRC=..\include\delay.c"
)

if defined C51CC_EXTRA_SRC (
    "%C51CC_EXE%" -asm -hex %C51CC_EXTRA_FLAGS% -o "%PROJECT_NAME%" %C51CC_IFLAGS% "%ENTRY_FILE_NAME%" "%C51CC_EXTRA_SRC%"
) else (
    "%C51CC_EXE%" -asm -hex %C51CC_EXTRA_FLAGS% -o "%PROJECT_NAME%" %C51CC_IFLAGS% "%ENTRY_FILE_NAME%"
)
if errorlevel 1 goto :c51cc_fail_pop
if not exist "%PROJECT_NAME%.hex" goto :c51cc_fail_pop

mkdir "%DEST_DIR%" >nul 2>nul
copy /y "%PROJECT_NAME%.asm" "%DEST_DIR%\%PROJECT_NAME%.asm" >nul 2>nul
copy /y "%ENTRY_BASE%.asm" "%DEST_DIR%\%ENTRY_BASE%.asm" >nul 2>nul
copy /y "%PROJECT_NAME%.hex" "%DEST_DIR%\%PROJECT_NAME%.hex" >nul
if exist "..\include\" (
    robocopy "..\include" "%DEST_DIR%\include" /E /NFL /NDL /NJH /NJS /NC /NS >nul
)
if exist "STARTUP.A51" copy /y "STARTUP.A51" "%DEST_DIR%\STARTUP.A51" >nul

popd >nul
set /a C51CC_OK+=1
echo   [C51CC] done
exit /b 0

:c51cc_fail_pop
popd >nul
:c51cc_fail
set /a C51CC_FAIL+=1
echo   [C51CC] failed
exit /b 0

:prepare_paths
set "_PROJECT_NAME=%~1"
set "_ENTRY_FILE=%~2"
set "_OUTPUT_BASE=%~3"
set "_TOOL_TAG=%~4"

set "WORK_DIR="
set "DEST_DIR="
set "ENTRY_DIR="
set "ENTRY_BASE="
set "ENTRY_FILE_NAME="
set "REL_DIR="

for %%I in ("%_ENTRY_FILE%") do (
    set "_ENTRY_DIR=%%~dpI"
    set "_ENTRY_BASE=%%~nI"
    set "_ENTRY_FILE_NAME=%%~nxI"
)
if "%_ENTRY_DIR:~-1%"=="\" set "_ENTRY_DIR=%_ENTRY_DIR:~0,-1%"

set "_REL_DIR="
if /I not "%_ENTRY_DIR%"=="%SOURCE_DIR%" (
    call set "_REL_DIR=%%_ENTRY_DIR:%SOURCE_DIR%\=%%"
    if not defined _REL_DIR call set "_REL_DIR=%%_ENTRY_DIR:%SOURCE_DIR%=%%"
    if defined _REL_DIR if "!_REL_DIR:~0,1!"=="\" set "_REL_DIR=!_REL_DIR:~1!"
)

if defined _REL_DIR (
    set "_WORK_DIR=%TMP_ROOT%\%_TOOL_TAG%\%_REL_DIR%\%_PROJECT_NAME%"
    set "_DEST_DIR=%_OUTPUT_BASE%\%_REL_DIR%\%_PROJECT_NAME%"
) else (
    set "_WORK_DIR=%TMP_ROOT%\%_TOOL_TAG%\%_PROJECT_NAME%"
    set "_DEST_DIR=%_OUTPUT_BASE%\%_PROJECT_NAME%"
)

set "WORK_DIR=%_WORK_DIR%"
set "DEST_DIR=%_DEST_DIR%"
set "ENTRY_DIR=%_ENTRY_DIR%"
set "ENTRY_BASE=%_ENTRY_BASE%"
set "ENTRY_FILE_NAME=%_ENTRY_FILE_NAME%"
set "REL_DIR=%_REL_DIR%"
exit /b 0

:stage_source_tree
set "SRC_TREE=%~1"
set "DST_TREE=%~2"
if exist "%DST_TREE%" rmdir /s /q "%DST_TREE%"
mkdir "%DST_TREE%" >nul 2>nul
robocopy "%SRC_TREE%" "%DST_TREE%" /E /NFL /NDL /NJH /NJS /NC /NS >nul
if errorlevel 8 exit /b 1
exit /b 0

:keil_compile_one
set "SRC_FILE=%~1"
for %%I in ("%SRC_FILE%") do set "SRC_BASE=%%~nI"
set "KEIL_INCDIR=%KEIL_INC%;%KEIL_INC_ATMEL%"
if exist "..\include\" set "KEIL_INCDIR=..\include;%KEIL_INC%;%KEIL_INC_ATMEL%"
"%KEIL_BIN%\C51.exe" "%SRC_FILE%" "INCDIR(%KEIL_INCDIR%)" "OBJECT(%SRC_BASE%.obj)" "SRC"
if not exist "%SRC_BASE%.SRC" exit /b 1
"%KEIL_BIN%\A51.EXE" "%SRC_BASE%.SRC" "OBJECT(%SRC_BASE%.obj)"
if not exist "%SRC_BASE%.obj" exit /b 1
exit /b 0

:has_main
powershell -NoProfile -Command "$text = Get-Content -LiteralPath '%~1' -Raw; $text = [regex]::Replace($text, '/\*.*?\*/', '', 'Singleline'); $text = [regex]::Replace($text, '//.*', ''); if ($text -match '(?m)\bmain\s*\(') { exit 0 } else { exit 1 }" >nul
if errorlevel 1 exit /b 1
exit /b 0

:resolve_path
for %%I in ("%~1") do set "%~2=%%~fI"
exit /b 0

:require_file
if exist "%~1" exit /b 0
echo [ERROR] Missing required file: %~1
exit /b 1