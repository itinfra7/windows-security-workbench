:: itinfra7 on GitHub
@echo off
setlocal EnableExtensions

set "BASE=%~dpn0"
set "PS1=%BASE%.ps1"
set "VBS=%BASE%.vbs"

if not exist "%PS1%" exit /b 1
if not exist "%VBS%" exit /b 1

>nul 2>&1 net session
if "%ERRORLEVEL%"=="0" (
    set "VERB=open"
) else (
    set "VERB=runas"
)

wscript.exe //nologo "%VBS%" "%PS1%" "%VERB%" %*
exit /b 0
