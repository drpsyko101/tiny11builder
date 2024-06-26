## This script install apps listed in .\AppList.json
## For example: [{"PackageName":"foo","Argument":"bar"}]
Start-Transcript "$env:PROGRAMDATA\appinstall.log"
Write-Host "Running app install script..."

Write-Host "Registering App Installer..."
try {
    $appInstallerPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "Microsoft.DesktopAppInstaller" }
    Add-AppxPackage -RegisterByFamilyName -MainPackage $appInstallerPackage.PackageName
}
catch {
    Write-Error "Failed to register App Installer. $_"
    Stop-Transcript
    exit 1
}

Write-Host "Updating installed apps..."
winget upgrade --all --accept-package-agreements --accept-source-agreements

$apps = Get-Content "$PSScriptRoot\AppList.json" | ConvertFrom-Json
foreach ($app in $apps) {
    Write-Host "Installing $($app.PackageName)..."
    $arg = $app.Arguments
    winget install $app.PackageName @arg
}

Write-Host "Powershell script done."
Stop-Transcript