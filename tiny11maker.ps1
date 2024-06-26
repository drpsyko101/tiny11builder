<#
    .SYNOPSIS
    Scripts to build a trimmed-down Windows 11 image - now in PowerShell!

    .DESCRIPTION
    You can now use it on ANY Windows 11 release (not just a specific build), as well as ANY language or architecture.
    This is made possible thanks to the much-improved scripting capabilities of PowerShell, compared to the older Batch release.

    Since it is written in PowerShell, you need to set the execution policy to  `Unrestricted`, so that you could run the script.
    If you haven't done this before, make sure to run `Set-ExecutionPolicy unrestricted` as administrator in PowerShell before 
    running the script, otherwise it would just crash.

    This is a script created to automate the build of a streamlined Windows 11 image, similar to tiny11. My main goal is to use
    only Microsoft utilities like DISM, and no utilities from external sources. The only executable included is **oscdimg.exe**,
    which is provided in the Windows ADK and it is used to create bootable ISO images. Also included is an unattended answer file,
    which is used to bypass the Microsoft Account on OOBE and to deploy the image with the `/compact` flag.

    .EXAMPLE
    .\tiny11maker.ps1 -Path E:\
#>

[CmdletBinding()]
param (
    # Path to mounted Windows installation media
    [string]$Path,

    # Windows variant index, which can be obtained with Get-WindowsImage
    [int]$Variant = 0,

    # Manually specify temporary file location
    [string]$ScratchDir,

    # Override username. User will be prompted with a password
    [ValidatePattern("^[a-z]{1}[a-z0-9-]+[a-z0-9]$")]
    [ValidateLength(3, 64)]
    [string]$Username
)

# Enable debugging
if ($PSBoundParameters["Debug"]) {
    Set-PSDebug -Trace 1
    $ErrorActionPreference = 'Inquire'
}

# Import configurations
$config = Get-Content "$PSScriptRoot\config.json" | ConvertFrom-Json
$logPath = "$PSScriptRoot\tiny11_$(Get-Date -Format 'yyyyMMddHHmm').log"

# Import functions
Import-Module "$PSScriptRoot\tools\Utils.psm1"

# Check if PowerShell execution is restricted
if ((Get-ExecutionPolicy) -eq 'Restricted') {
    Write-Output "Your current PowerShell Execution Policy is set to Restricted, which prevents scripts from running."
    $response = CreateChoice -Description "Do you want to change it to RemoteSigned?" -Choices @("&Yes", "&No")
    if ($response -eq 0) {
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false
    }
    else {
        Write-Error "The script cannot be run without changing the execution policy. Exiting..." -ErrorAction Stop
    }
}

# Check and run the script as admin if required
$adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (! $myWindowsPrincipal.IsInRole($adminRole)) {
    Write-Output "Restarting Tiny11 image creator as admin in a new window, you can close this one."
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
    $newProcess.Arguments = $myInvocation.MyCommand.Definition;
    $newProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($newProcess);
    exit
}

# Modify unattended.xml if applicable
$unattend = Get-Content "$PSScriptRoot\autounattend.xml" -Raw
if ($Username) {
    $password = Read-Host "Create a new password for user ${Username}:" -MaskInput
    $encodedPw = ConvertTo-Base64 "${password}Password"
    $unattend = $unattend -replace "<Password>`r`n([ ]+)<Value>.*<\/Value>", "<Password>`r`n`$1<Value>$encodedPw</Value>"
}
else {
    $Username = $config.username
}
$unattend = $unattend -replace "<(Name|Username)>.*<\/(Name|Username)>", "<`$1>$Username</`$2>"
Set-Content -Path "$PSScriptRoot\autounattend.xml" -Value $unattend

# Create temporary directory if not specified
if ($ScratchDir) {
    $tmpDir = $ScratchDir
}
else {
    $tmpDir = New-TemporaryDirectory
}

$Host.UI.RawUI.WindowTitle = "Tiny11 image creator"
Clear-Host
& {
    Write-Output "Welcome to the tiny11 image creator! Release: 05-06-24"

    # Check for source installation media
    $hostArchitecture = $Env:PROCESSOR_ARCHITECTURE
    New-Item -ItemType Directory -Force -Path "$tmpDir\tiny11\sources" | Out-Null
    [string]$driveLetter
    if ($Path) {
        $driveLetter = $Path.TrimEnd("\")
    }
    else {
        $mountDrive = Get-Volume | Where-Object { $_.DriveType -eq "CD-ROM" }
        if (-not($mountDrive)) {
            Write-Error "Failed to find any mounted Windows 11 installation media. For custom unmounted path, define the value in the -Path argument." -ErrorAction Stop
        }
        $choices = $mountDrive | ForEach-Object { "&$($_.DriveLetter): $($_.FileSystemLabel)" }
        $response = CreateChoice -Description "Please enter the path to the mounted Windows 11 image:" -Choices $choices
        $driveLetter = $mountDrive[$response].DriveLetter
        if (-not(Test-Path "${driveLetter}:\")) {
            Write-Error "Invalid drive selection." -ErrorAction Stop
        }
        $driveLetter = $driveLetter + ":"
    }

    if ((Test-Path "$driveLetter\sources\boot.wim") -eq $false -or (Test-Path "$driveLetter\sources\install.wim") -eq $false) {
        if ((Test-Path "$driveLetter\sources\install.esd") -eq $true) {
            Write-Output "Found install.esd, converting to install.wim..."
            if (-not($Variant)) {
                $variants = Get-WindowsImage -ImagePath "$driveLetter\sources\install.esd"
                $Variant = (CreateMenu -MenuTitle "Select Windows variant:" -MenuOptions $($variants | ForEach-Object { $_.ImageName })) + 1
            }
            Write-Output 'Converting install.esd to install.wim. This may take a while...'
            Export-WindowsImage -SourceImagePath "$driveLetter\sources\install.esd" -SourceIndex $Variant -DestinationImagePath "$tmpDir\tiny11\sources\install.wim" -CompressionType "max" -CheckIntegrity
        }
        else {
            Write-Error "Can't find Windows OS Installation files in the specified Drive Letter. Please enter the correct DVD Drive Letter." -ErrorAction Stop
        }
    }

    # Prepare Windows install image
    Write-Output "Copying Windows image..."
    Copy-Item -Path "$driveLetter\*" -Destination "$tmpDir\tiny11" -Recurse -Force | Out-Null
    if (Test-Path "$tmpDir\tiny11\sources\install.esd") {
        Set-ItemProperty -Path "$tmpDir\tiny11\sources\install.esd" -Name IsReadOnly -Value $false | Out-Null
        Remove-Item "$tmpDir\tiny11\sources\install.esd" | Out-Null
    }
    Write-Output "Copy complete!"
    Write-Output "Getting image information..."
    $variants = Get-WindowsImage -ImagePath "$driveLetter\sources\install.wim"
    if (-not($Variant)) {
        $Variant = (CreateMenu -MenuTitle "Select Windows variant:" -MenuOptions $($variants | ForEach-Object { $_.ImageName })) + 1
    }
    Write-Output "Selected variant: $($variants[$Variant - 1].ImageName)"
    Write-Output "Mounting Windows image. This may take a while."
    $wimFilePath = "$tmpDir\tiny11\sources\install.wim"
    $Account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList 'BUILTIN\Administrators';
    $Acl = Get-Acl "$wimFilePath"
    $Acl.SetOwner($Account)
    Set-Acl -Path "$wimFilePath" -AclObject $Acl
    Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false -ErrorAction "Continue"
    New-Item -ItemType Directory -Force -Path "$tmpDir\scratchdir" | Out-Null
    $mount = Mount-WindowsImage -ImagePath "$tmpDir\tiny11\sources\install.wim" -Index $Variant -Path "$tmpDir\scratchdir" -ErrorAction Stop
    Write-Output "Windows install image mounted on $($mount.Path)"
    
    $architecture = (Get-WindowsImage -ImagePath "$tmpDir\tiny11\sources\install.wim" -Index $Variant).Architecture
    if ($architecture -eq 'x64') {
        $architecture = 'amd64'
        Write-Verbose "Architecture: $architecture"
    }

    if (-not $architecture) {
        Write-Warning "Architecture information not found."
    }

    # Remove provisioned apps from the image
    Write-Output "Performing removal of applications:"
    $appPrefixes = [System.Collections.ArrayList]$config.appsToRemove
    $apps = Get-AppxProvisionedPackage -Path "$tmpDir\scratchdir"
    Write-Verbose "Found $($apps.Count) provisioned app(s)."
    $removedApps = [System.Collections.ArrayList]::new()
    foreach ($app in $apps) {
        foreach ($prefix in $appPrefixes) {
            if ($app.PackageName -match $prefix) {
                Write-Verbose "  Found app: $($app.PackageName)"
                try {
                    Remove-AppxProvisionedPackage -Path "$tmpDir\scratchdir" -PackageName $app.PackageName | Out-Null
                    Write-Output "  $($app.PackageName) removed"
                }
                catch {
                    Write-Warning "Failed to remove app: $($app.PackageName). $_"
                }
                $removedApps += $app
                $appPrefixes.Remove($prefix)
                break
            }
        }
    }
    Write-Verbose "Removed $($removedApps.Count) apps(s)."

    $packagePrefixes = [System.Collections.ArrayList]$config.packagesToRemove
    $packages = Get-WindowsPackage -Path "$tmpDir\scratchdir"
    Write-Verbose "Found $($packages.Count) Windows package(s)."
    $removedPackages = [System.Collections.ArrayList]::new()
    foreach ($package in $packages) {
        foreach ($prefix in $packagePrefixes) {
            if ($package.PackageName -match $prefix) {
                Write-Verbose "  Found package: $($package.PackageName)"
                try {
                    Remove-WindowsPackage -Path "$tmpDir\scratchdir" -PackageName $package.PackageName | Out-Null
                    Write-Output "  $($package.PackageName) removed"
                }
                catch {
                    Write-Warning "Failed to remove package: $($package.PackageName). $_"
                }
                $removedPackages += $package
                $packagePrefixes.Remove($prefix)
                break
            }
        }
    }
    Write-Verbose "Removed $($removedPackages.Count) package(s)."

    # Remove Edge and its related components
    Write-Output "Removing Edge:"
    Remove-Item -Path "$tmpDir\scratchdir\Program Files (x86)\Microsoft\Edge" -Recurse -Force | Out-Null
    Remove-Item -Path "$tmpDir\scratchdir\Program Files (x86)\Microsoft\EdgeUpdate" -Recurse -Force | Out-Null
    Remove-Item -Path "$tmpDir\scratchdir\Program Files (x86)\Microsoft\EdgeCore" -Recurse -Force | Out-Null
    [string]$edgeDir
    if ($architecture -eq 'amd64') {
        $edgeDir = Get-ChildItem -Path "$tmpDir\scratchdir\Windows\WinSxS" -Filter "amd64_microsoft-edge-webview_31bf3856ad364e35*" -Directory | Select-Object -ExpandProperty FullName
    }
    elseif ($architecture -eq 'arm64') {
        $edgeDir = Get-ChildItem -Path "$tmpDir\scratchdir\Windows\WinSxS" -Filter "arm64_microsoft-edge-webview_31bf3856ad364e35*" -Directory | Select-Object -ExpandProperty FullName | Out-Null
    }

    if ($edgeDir) {
        Remove-PathOverride "$edgeDir" -Recurse
    }
    else {
        Write-Warning "Edge directory not found."
    }

    Remove-PathOverride "$tmpDir\scratchdir\Windows\System32\Microsoft-Edge-Webview" -Recurse

    # Remove OneDrive
    Write-Output "Removing OneDrive:"
    Remove-PathOverride "$tmpDir\scratchdir\Windows\System32\OneDriveSetup.exe"
    Write-Output "Removal complete!"

    # Tweaking registry
    Write-Output "Tweaking install registry..."
    Write-Verbose "Mounting install registry point..."
    reg load HKLM\zCOMPONENTS $tmpDir\scratchdir\Windows\System32\config\COMPONENTS | Out-Null
    reg load HKLM\zDEFAULT $tmpDir\scratchdir\Windows\System32\config\default | Out-Null
    reg load HKLM\zNTUSER $tmpDir\scratchdir\Users\Default\ntuser.dat | Out-Null
    reg load HKLM\zSOFTWARE $tmpDir\scratchdir\Windows\System32\config\SOFTWARE | Out-Null
    reg load HKLM\zSYSTEM $tmpDir\scratchdir\Windows\System32\config\SYSTEM | Out-Null
    Write-Verbose "Patching install registry..."
    reg import "$PSScriptRoot\tools\boot.reg" 2>&1 | Out-Null
    reg import "$PSScriptRoot\tools\install.reg" 2>&1 | Out-Null
    Write-Verbose "Unmounting install registry..."
    reg unload HKLM\zCOMPONENTS | Out-Null
    reg unload HKLM\zDEFAULT | Out-Null
    reg unload HKLM\zNTUSER | Out-Null
    reg unload HKLM\zSOFTWARE | Out-Null
    reg unload HKLM\zSYSTEM | Out-Null
    Write-Output "Install registry tweaked."
    
    ## Install additional apps
    if (Test-Path("$PSScriptRoot\apps")) {
        Write-Output "Installing apps..."
        $appDirs = Get-ChildItem -Directory "$PSScriptRoot\apps"
        foreach ($appDir in $appDirs) {
            $app = Get-ChildItem -File -Include "*.msixbundle", "*.appxbundle" -Path "$($appDir.FullName)\*"
            $appDeps = (Get-ChildItem -File -Include "*.msix", "*.appx" -Path "$($appDir.FullName)\*").FullName
            if ($app) {
                Write-Verbose "Installing $($app.BaseName)"
                try {
                    Add-AppxProvisionedPackage -Path "$tmpDir\scratchdir" -PackagePath "$($app[0].FullName)" -DependencyPackagePath $appDeps -SkipLicense -Regions "all" | Out-Null
                }
                catch {
                    Write-Error "Failed to install $($app.BaseName)"
                }
            }
        }
    }

    ## Install additional drivers if present
    if (Test-Path("$PSScriptRoot\drivers\install")) {
        Write-Output "Installing drivers..."
        $drivers = Add-WindowsDriver -Path "$tmpDir\scratchdir" -Driver "$PSScriptRoot\drivers\install" -Recurse -ForceUnsigned
        Write-Output "Installed $($drivers.Count) driver(s)."
        Write-Debug $drivers
    }

    ## Add setup scripts
    if (Test-Path("$PSScriptRoot\scripts")) {
        Write-Output "Copying setup scripts..."
        Copy-Item -Path "$PSScriptRoot\scripts" -Destination "$tmpDir\scratchdir\Windows\Setup\Scripts" -Recurse -Force | Out-Null
    }

    # Finalizing install image
    Write-Output "Optimizing image..."
    Optimize-AppXProvisionedPackages -Path "$tmpDir\scratchdir" | Out-Null
    Write-Output "Cleaning up image..."
    $repair = Repair-WindowsImage -Path "$tmpDir\scratchdir" -ResetBase -RestoreHealth -StartComponentCleanup
    Write-Verbose "Image health: $($repair.ImageHealthState)"
    Write-Output "Cleanup complete."
    Write-Output "Unmounting image..."
    Write-Verbose "This might take a while due to integrity check before unmounting."
    Dismount-WindowsImage -Path "$tmpDir\scratchdir" -Save | Out-Null
    Write-Output "Exporting image..."
    # Export-WindowsImage currently does not support recovery compress type
    # Therefore a slight increase in size is expected
    Export-WindowsImage -SourceImagePath "$tmpDir\tiny11\sources\install.wim" -SourceIndex $Variant -DestinationImagePath "$tmpDir\tiny11\sources\install2.wim" -CompressionType "max" | Out-Null
    # & 'dism' '/English' '/Export-Image' "/SourceImageFile:$tmpDir\tiny11\sources\install.wim" "/SourceIndex:$($Variant + 1)" "/DestinationImageFile:$tmpDir\tiny11\sources\install2.wim" '/compress:recovery' | Out-Null
    Remove-Item -Path "$tmpDir\tiny11\sources\install.wim" -Force | Out-Null
    Rename-Item -Path "$tmpDir\tiny11\sources\install2.wim" -NewName "install.wim" | Out-Null
    Write-Output "Windows image completed. Continuing with boot.wim."

    # Prepare boot image
    Write-Output "Mounting boot image:"
    $wimFilePath = "$tmpDir\tiny11\sources\boot.wim"
    $Acl = Get-Acl "$wimFilePath"
    $Acl.SetOwner($Account)
    Set-Acl -Path "$wimFilePath" -AclObject $Acl
    Set-ItemProperty -Path $wimFilePath -Name IsReadOnly -Value $false
    $mount = Mount-WindowsImage -ImagePath "$tmpDir\tiny11\sources\boot.wim" -Index 2 -Path "$tmpDir\scratchdir"
    Write-Verbose "Windows boot image mounted on $($mount.Path)"
    
    Write-Output "Tweaking boot registry..."
    Write-Verbose "Mounting boot registry point..."
    reg load HKLM\zCOMPONENTS $tmpDir\scratchdir\Windows\System32\config\COMPONENTS | Out-Null
    reg load HKLM\zDEFAULT $tmpDir\scratchdir\Windows\System32\config\default | Out-Null
    reg load HKLM\zNTUSER $tmpDir\scratchdir\Users\Default\ntuser.dat | Out-Null
    reg load HKLM\zSOFTWARE $tmpDir\scratchdir\Windows\System32\config\SOFTWARE | Out-Null
    reg load HKLM\zSYSTEM $tmpDir\scratchdir\Windows\System32\config\SYSTEM | Out-Null
    Write-Verbose "Patching boot registry..."
    reg import "$PSScriptRoot\tools\boot.reg" 2>&1 | Out-Null
    Write-Verbose "Unmounting boot registry..."
    reg unload HKLM\zCOMPONENTS | Out-Null
    reg unload HKLM\zDEFAULT | Out-Null
    reg unload HKLM\zNTUSER | Out-Null
    reg unload HKLM\zSOFTWARE | Out-Null
    reg unload HKLM\zSYSTEM | Out-Null
    Write-Output "Boot registry tweaked."

    ## Install additional boot drivers if present
    if (Test-Path("$PSScriptRoot\drivers\boot")) {
        Write-Output "Installing drivers..."
        Add-WindowsDriver -Path "$tmpDir\scratchdir" -Driver "$PSScriptRoot\drivers\boot" -Recurse -ForceUnsigned
    }

    Write-Output "Unmounting image..."
    Dismount-WindowsImage -Path "$tmpDir\scratchdir" -Save | Out-Null
    Export-WindowsImage -SourceImagePath "$tmpDir\tiny11\sources\boot.wim" -SourceIndex 2 -DestinationImagePath "$tmpDir\tiny11\sources\boot2.wim" -CompressionType "max" | Out-Null
    Remove-Item -Path "$tmpDir\tiny11\sources\boot.wim" -Force | Out-Null
    Rename-Item -Path "$tmpDir\tiny11\sources\boot2.wim" -NewName "boot.wim" | Out-Null

    # Finalizing ISO build
    Write-Output "The tiny11 image is now completed. Proceeding with the making of the ISO..."
    Write-Output "Copying unattended file for bypassing MS account on OOBE..."
    Copy-Item -Path "$PSScriptRoot\autounattend.xml" -Destination "$tmpDir\tiny11\autounattend.xml" -Force | Out-Null
    Write-Output "Creating ISO image..."
    $ADKDepTools = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\$hostarchitecture\Oscdimg"
    $localOSCDIMGPath = "$PSScriptRoot\oscdimg.exe"

    if ([System.IO.Directory]::Exists($ADKDepTools)) {
        Write-Output "Will be using oscdimg.exe from system ADK."
        $OSCDIMG = "$ADKDepTools\oscdimg.exe"
    }
    else {
        Write-Output "ADK folder not found. Will be using bundled oscdimg.exe."
    
        $url = "https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe"

        if (-not (Test-Path -Path $localOSCDIMGPath)) {
            Write-Output "Downloading oscdimg.exe..."
            Invoke-WebRequest -Uri $url -OutFile $localOSCDIMGPath

            if (Test-Path $localOSCDIMGPath) {
                Write-Output "oscdimg.exe downloaded successfully."
            }
            else {
                Write-Error "Failed to download oscdimg.exe." -ErrorAction Stop
            }
        }
        else {
            Write-Output "oscdimg.exe already exists locally."
        }

        $OSCDIMG = $localOSCDIMGPath
    }

    # Package new image, error stream redirected to stdout
    & "$OSCDIMG" '-m' '-o' '-u2' '-udfver102' "-bootdata:2#p0,e,b$tmpDir\tiny11\boot\etfsboot.com#pEF,e,b$tmpDir\tiny11\efi\microsoft\boot\efisys.bin" "$tmpDir\tiny11" "$PSScriptRoot\tiny11.iso" 2>&1 | Out-String -Stream

    # Finishing up
    Write-Output "Performing Cleanup..."
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Output "Creation completed!"
} *>&1 | Logger -Path $logPath -Verbose:$VerbosePreference

Remove-Module Utils -ErrorAction SilentlyContinue
Read-Host "Press Enter to continue"