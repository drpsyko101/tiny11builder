
## this function allows PowerShell to take ownership of the Scheduled Tasks registry key from TrustedInstaller. Based on Jose Espitia's script.
function Enable-Privilege {
    param(
        [ValidateSet(
            "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
            "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
            "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
            "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
            "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
            "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
            "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
            "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
        $Privilege,
        ## The process on which to adjust the privilege. Defaults to the current process.
        $ProcessId = $pid,
        ## Switch to disable the privilege, rather than enable it.
        [Switch] $Disable
    )
    $definition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

    $processHandle = (Get-Process -id $ProcessId).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}

Function CreateMenu() {
    <#
    .SYNOPSIS
        Create a simple menu from an array of string.
    .DESCRIPTION
        Create a menu that can be navigated by using arrow keys.
        The items are populated by the input string array.
        The selection index will be returned by pressing the Enter key.
    .NOTES
        The menu does not support pagination, nor populating list larger than the terminal vertical height.
        Using transcript may also flood the logs. Use with caution and cleanup whenever neccessary.
    .LINK
        https://community.spiceworks.com/t/powershell-create-menu-easily-add-arrow-key-driven-menu-to-scripts/975525
    .EXAMPLE
        CreateMenu -MenuTitle "Foo" -MenuOptions @("bar", "baz")
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)][String]$MenuTitle,
        [Parameter(Mandatory = $True)][array]$MenuOptions
    )

    $MaxValue = $MenuOptions.count - 1
    $Selection = 0
    $EnterPressed = $False
    
    Clear-Host

    While ($EnterPressed -eq $False) {
        Write-Host "$MenuTitle"
        For ($i = 0; $i -le $MaxValue; $i++) {
            If ($i -eq $Selection) {
                $null = Write-Host -BackgroundColor Cyan -ForegroundColor Black "[ $($MenuOptions[$i]) ]"
            }
            Else {
                $null = Write-Host "  $($MenuOptions[$i])  "
            }

        }

        $KeyInput = $host.ui.rawui.readkey("NoEcho,IncludeKeyDown").virtualkeycode
        Switch ($KeyInput) {
            13 {
                $EnterPressed = $True
                Clear-Host
                Return $Selection
                break
            }

            38 {
                If ($Selection -eq 0) {
                    $Selection = $MaxValue
                }
                Else {
                    $Selection -= 1
                }
                Clear-Host
                break
            }

            40 {
                If ($Selection -eq $MaxValue) {
                    $Selection = 0
                }
                Else {
                    $Selection += 1
                }
                Clear-Host
                break
            }
            Default {
                Clear-Host
            }
        }
    }
}

function ConvertFrom-Repeating() {
    <#
    .SYNOPSIS
        Convert string with repeating pattern to a hashtable.
    .DESCRIPTION
        String with a repeating pattern like:

        Name: John
        Age: 26

        Name: Anna
        Age: 24

        will be parsed into a hashtable.
    .NOTES
        This function expects the input string to contains identical key across all objects.
        Any odd keys may be inserted to the first object not containing the said key.
    .EXAMPLE
        @'
        Name: John
        Age: 26

        Name: Anna
        Age: 24
        '@ | ConvertFrom-Repeating -Delimiter ":"
        Convert multiline with delimiter :.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline)]
        [string[]]$Entries,

        # Character delimiter for param/value separation
        [string]$Delimiter = ":"
    )
    begin { $variants = @() }
    process {
        foreach ($entry in $Entries) {
            if ($entry) {
                if (-not($entry.Contains($Delimiter))) {
                    continue
                }
                $params = $entry.Split($Delimiter)
                $rawParam = $params[0].Trim()
                $rawValue = $params[1].Trim()
                # Try parsing to int
                [Int64]$valueNum = 0;
                $isValNum = [int64]::TryParse($rawValue, [ref]$valueNum)
                if (-not($isValNum)) {
                    # Try parsing from humann readable bytes
                    $parsedValue = $rawValue -replace '[, bytes]+', ''
                    $isValNum = [int64]::TryParse($parsedValue, [ref]$valueNum)
                }
                $tmpVariant = @{$rawParam = $isValNum ? $valueNum : $rawValue }
                $lastIndex = $variants.Count - 1 
                if ($variants[$lastIndex]) {
                    if (-not($variants[$lastIndex].ContainsKey($rawParam))) {
                        $variants[$lastIndex][$rawParam] = $isValNum ? $valueNum : $rawValue
                        continue
                    }
                }
                $variants += $tmpVariant
            }
        }
    }
    end { $variants }
}

function HumanReadableByteSize ($size) {
    switch ($size) {
        { $_ -gt 1TB } { ($size / 1TB).ToString("n2") + " TB"; break }
        { $_ -gt 1GB } { ($size / 1GB).ToString("n2") + " GB"; break }
        { $_ -gt 1MB } { ($size / 1MB).ToString("n2") + " MB"; break }
        { $_ -gt 1KB } { ($size / 1KB).ToString("n2") + " KB"; break }
        default { "$size B" }
    }
}

function Logger {
    <#
    .SYNOPSIS
        Parse output streams into human readable format
    .DESCRIPTION
        Split all output stream into respective formatting. The level of the streams are:

        +-----------+---------------------+-----------------+-------------------------------+
        | Stream #  |    Description      | Introduced in   |         Write Cmdlet          |
        +-----------+---------------------+-----------------+-------------------------------+
        | 1         | Success Stream      | PowerShell 2.0  | Write-Output                  |
        | 2         | Error Stream        | PowerShell 2.0  | Write-Error                   |
        | 3         | Warning Stream      | PowerShell 3.0  | Write-Warning                 |
        | 4         | Verbose Stream      | PowerShell 3.0  | Write-Verbose                 |
        | 5         | Debug Stream        | PowerShell 3.0  | Write-Debug                   |
        | 6         | Information Stream  | PowerShell 5.0  | Write-Information, Write-Host |
        | *         | All Streams         | PowerShell 3.0  |                               |
        +-----------+---------------------+-----------------+-------------------------------+

    .NOTES
        Filter can only be set before piping it to this function. Native cmd progress bar is not supported yet.
    .LINK
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_redirection?view=powershell-7.4
    .EXAMPLE
        $Myfunction *>&1 | Logger
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline)]
        [System.Object[]]$Logs,
        [string]$Path,
        [int]$FilterLevel = 5,
        [switch]$NoClobber
    )
    begin {
        [string]$progressActivity
        [string]$previousLog
        if ($Path -and $(Test-Path $Path) -and $NoClobber) {
            Write-Error "Found existing log file at $Path." -ErrorAction Stop
        }
    }
    process {
        foreach ($log in $Logs) {
            if (-not($log)) {
                if (-not($progressActivity)) { Write-Host "" }
                continue
            }

            $parsedLog = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fffffff')] "
            $saveToLog = $true

            $progressRegex = '^\[?.*?([0-9\.]+)%.*[\]|complete] ?$'
            if ($progressActivity -and -not($previousLog -match $progressRegex)) {
                Write-Progress -Activity $progressActivity -Completed
                Clear-Variable progressActivity
            }

            Write-Debug "LogType: $($log.GetType())" 

            switch ($log) {
                { $_ -is [System.Management.Automation.ErrorRecord] } { 
                    Write-Error $_
                    $parsedLog += "ERROR: " + $_
                    break
                }
                { $_ -is [System.Management.Automation.WarningRecord] } { 
                    Write-Warning $_
                    $parsedLog += "WARNING: " + $_
                    break
                }
                { $_ -is [System.Management.Automation.VerboseRecord] } { 
                    Write-Verbose $_
                    $parsedLog += "VERBOSE: " + $_
                    break
                }
                { $_ -is [System.Management.Automation.DebugRecord] } { 
                    Write-Debug $_
                    $parsedLog += "DEBUG: " + $_
                    break
                }
                { $_ -is [System.Management.Automation.InformationRecord] } { 
                    $_ | Out-String -Stream
                    $saveToLog = $false
                    if ($FilterLevel -ge 6) {
                        $parsedLog += "INFO: " + $_
                        $saveToLog = $true
                    }
                    break
                }
                { $_ -match "$progressRegex" } {
                    $saveToLog = $false
                    if (-not($progressActivity)) {
                        $progressActivity = $previousLog
                    }
                    $progress = [regex]::Match($_, $progressRegex).Groups[1].Value
                    Write-Progress -Activity $progressActivity -Status "Progress: $progress%" -PercentComplete $progress
                    break
                }
                { $_ -is [System.Management.Automation.ProgressRecord] } { 
                    break
                }
                Default {
                    $_ | Out-String -Stream
                    $parsedLog += $($_ | Out-String -Stream)
                }
            }
            if ($Path -and $saveToLog) {
                $parsedLog >> $Path
            }
            $previousLog = $log
        }
    }
}

function CreateChoice {
    [CmdletBinding()]
    param (
        # Choice description
        [Parameter(Mandatory, Position = 0)]
        [string]$Description,

        # Choices
        [Parameter(Mandatory, Position = 1)]
        [string[]]$Choices,

        [string]$Title,
        [int]$DefaultOption = 0
    )
    [System.Management.Automation.Host.ChoiceDescription[]] $_choices = $Choices | ForEach-Object {
        [System.Management.Automation.Host.ChoiceDescription]::new($_)
    }
    return $Host.UI.PromptForChoice($Title, $Description, $_choices, $DefaultOption)
}

function New-TemporaryDirectory {
    [CmdletBinding()]
    param (
        # Custom GUID
        [string]$Guid = [System.Guid]::NewGuid()
    )
    $parent = [System.IO.Path]::GetTempPath()
    $dir = New-Item -ItemType Directory -Path (Join-Path $parent $Guid)
    Write-Verbose "Created a new temporary directory at $($dir.FullName)"
    return $dir
}

function Remove-PathOverride {
    param (
        # Path to take ownership and remove
        [Parameter(ValueFromPipeline)]
        [string]$Path,
        
        [switch]$Recurse
    )
    if (Test-Path $Path) {
        $fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList "BUILTIN\Administrators", "FullControl", "Allow"
        if ($Recurse) {
            $itemList = Get-ChildItem $Path -Recurse
            foreach ($item in $itemList) {
                $acl = Get-Acl -Path $item
                $acl.SetAccessRule($fileSystemAccessRule)
                Set-Acl -Path $item -AclObject $acl
            }
        }
        else {
            $item = Get-Item -Path $Path
            $acl = Get-Acl -Path $item
            $acl.SetAccessRule($fileSystemAccessRule)
            Set-Acl -Path $item -AclObject $acl
        }
        Remove-Item -Path $Path -Recurse:$Recurse -Force
    }
}

function ConvertTo-Base64 {
    [CmdletBinding()]
    param (
        # Input to convert to base64
        [Parameter(Position = 0, ValueFromPipeline)]
        [string]$StringInput
    )
    if ($StringInput.GetType() -eq [System.String]) {
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($StringInput)
        return [System.Convert]::ToBase64String($bytes)
    }
    Write-Debug "Input is not type of string."
}

function ConvertFrom-Base64 {
    [CmdletBinding()]
    param (
        # Input to convert from base64
        [Parameter(Position = 0, ValueFromPipeline)]
        [string]$StringInput
    )
    $bytes = [System.Convert]::FromBase64String($StringInput)
    return [System.Text.Encoding]::Unicode.GetString($bytes)
}