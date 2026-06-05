@echo off
:: ============================================================
:: build.cmd -- git-crypt Windows build wrapper
::
:: Produces x64 git-crypt.exe with static CRT and the BCrypt
:: crypto backend (no MSVC runtime, no OpenSSL required).
:: Output lands in win-build\dist\git-crypt.exe.
::
:: Usage:
::   build              Release build
::   build debug        Debug build
::   build clean        Wipe build\ first, then Release build
::   build debug clean  Debug build, clean first
:: ============================================================

setlocal
set "SCRIPT_DIR=%~dp0"
set "MODE=Release"
set "CLEAN="

:parse
if "%~1"=="" goto run
if /I "%~1"=="release" ( set "MODE=Release" & shift & goto parse )
if /I "%~1"=="debug"   ( set "MODE=Debug"   & shift & goto parse )
if /I "%~1"=="clean"   ( set "CLEAN=-Clean" & shift & goto parse )
echo Unknown argument: %~1
echo Usage: build [release^|debug] [clean]
exit /b 1

:run
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%build.ps1" -Mode %MODE% %CLEAN%
exit /b %ERRORLEVEL%
