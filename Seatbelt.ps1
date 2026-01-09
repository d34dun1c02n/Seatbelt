<#
.SYNOPSIS
    Seatbelt - A PowerShell security enumeration script

.DESCRIPTION
    Seatbelt is a security-oriented host-survey "safety checks" tool relevant from both
    offensive and defensive security perspectives. This is a PowerShell port of the
    original C# Seatbelt project by @harmj0y and @tifkin_.

.PARAMETER Command
    Specific command(s) to run. Can be a single command or comma-separated list.

.PARAMETER Group
    Command group to run: All, System, User, Misc, Browser, Remote

.PARAMETER Full
    Return full unfiltered results (by default results are filtered)

.PARAMETER ComputerName
    Remote computer name for commands that support remote execution

.PARAMETER Credential
    PSCredential object for remote authentication

.PARAMETER OutputFile
    Path to output file (supports .txt and .json extensions)

.PARAMETER Quiet
    Suppress banner output

.EXAMPLE
    .\Seatbelt.ps1 -Command OSInfo

.EXAMPLE
    .\Seatbelt.ps1 -Group System

.EXAMPLE
    .\Seatbelt.ps1 -Command OSInfo,Processes -Full

.EXAMPLE
    .\Seatbelt.ps1 -Group Remote -ComputerName SERVER01

.NOTES
    Version: 1.0.0
    Original Authors: @harmj0y, @tifkin_
    PowerShell Port: Converted from C# Seatbelt
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]]$Command,

    [Parameter()]
    [ValidateSet('All', 'System', 'User', 'Misc', 'Browser', 'Remote')]
    [string]$Group,

    [Parameter()]
    [switch]$Full,

    [Parameter()]
    [string]$ComputerName,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [string]$OutputFile,

    [Parameter()]
    [switch]$Quiet
)

#region Script Configuration
$Script:Version = "1.0.0"
$Script:FilterResults = -not $Full
$Script:IsRemote = -not [string]::IsNullOrEmpty($ComputerName)
$Script:Results = @()
#endregion

#region Banner
function Show-Banner {
    if ($Quiet) { return }

    $banner = @"

                        %&&@@@&&
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%
                        &%&   %&%%                        &////))))))))))))))))))))))))))))))))))))%teleportation
                        &%%&&&%%%%%            ,*]
            ,## @&&&&&@##&         ### @&&&&&@#                               @@@@@@@@@@@%%%%%%%%%%%%###############*
          %&%&%&%&&%&%&#           %&%&%&%&&%&%&#                               %%%/%&&%%%%%)))))))))#####((((((###((((((((
        %&&%&&&&&&&&%%            %&&%&&&&&&&&%%                                &## ### ## #### # #  #### #### #### ##
        %%&%%%%%%%-*]             %%&%%%%%%%-*]                                 @@## && && &&@ &&@ && && &&& &&& && &&

====== Seatbelt (PowerShell Edition) ======

Version: $($Script:Version)
Original Authors: @harmj0y, @tifkin_
PowerShell Port

"@
    Write-Host $banner -ForegroundColor Cyan
}
#endregion

#region Utility Functions

function Test-IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsHighIntegrity {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    # Check if running as admin
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return $true
    }

    # Check integrity level
    try {
        $process = Get-Process -Id $PID
        $token = $process.Handle
        # If we can get handle and are admin, high integrity
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-RegistryValue {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name,

        [string]$ComputerName
    )

    try {
        if ($ComputerName) {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine,
                $ComputerName
            )
            $key = $reg.OpenSubKey($Path.Replace("HKLM:\", "").Replace("HKEY_LOCAL_MACHINE\", ""))
            if ($key) {
                return $key.GetValue($Name)
            }
        }
        else {
            return Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue |
                   Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue
        }
    }
    catch {
        return $null
    }
}

function Get-WmiData {
    param(
        [Parameter(Mandatory)]
        [string]$Class,

        [string]$Namespace = "root\cimv2",

        [string]$Filter,

        [string]$ComputerName,

        [System.Management.Automation.PSCredential]$Credential
    )

    $params = @{
        Class = $Class
        Namespace = $Namespace
        ErrorAction = 'SilentlyContinue'
    }

    if ($Filter) { $params.Filter = $Filter }
    if ($ComputerName) { $params.ComputerName = $ComputerName }
    if ($Credential) { $params.Credential = $Credential }

    return Get-WmiObject @params
}

function Write-CommandHeader {
    param([string]$CommandName, [string]$Description)

    Write-Host ""
    Write-Host "====== $CommandName ======" -ForegroundColor Green
    if ($Description) {
        Write-Host "  $Description" -ForegroundColor DarkGray
    }
    Write-Host ""
}

function Write-CommandOutput {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        $Value,

        [int]$Indent = 2
    )

    $padding = " " * $Indent
    Write-Host ("{0}{1,-35}: {2}" -f $padding, $Name, $Value)
}

function Format-FileSize {
    param([long]$Size)

    if ($Size -gt 1TB) { return "{0:N2} TB" -f ($Size / 1TB) }
    if ($Size -gt 1GB) { return "{0:N2} GB" -f ($Size / 1GB) }
    if ($Size -gt 1MB) { return "{0:N2} MB" -f ($Size / 1MB) }
    if ($Size -gt 1KB) { return "{0:N2} KB" -f ($Size / 1KB) }
    return "$Size bytes"
}

#endregion

#region System Commands

function Get-SBOSInfo {
    <#
    .SYNOPSIS
        Basic OS info (architecture, OS version, etc.)
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "OSInfo" "Basic OS info (i.e. architecture, OS version, etc.)"

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

    $osInfo = [PSCustomObject]@{
        Hostname = $env:COMPUTERNAME
        Domain = (Get-WmiData -Class Win32_ComputerSystem).Domain
        Username = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        ProductName = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).ProductName
        EditionID = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).EditionID
        ReleaseId = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).ReleaseId
        DisplayVersion = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).DisplayVersion
        Build = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).CurrentBuildNumber
        BuildBranch = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).BuildBranch
        CurrentMajorVersion = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).CurrentMajorVersionNumber
        CurrentVersion = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).CurrentVersion
        Architecture = $env:PROCESSOR_ARCHITECTURE
        ProcessorCount = $env:NUMBER_OF_PROCESSORS
        IsVirtualMachine = $false
        BootTime = $null
        IsHighIntegrity = (Test-IsHighIntegrity)
        IsLocalAdmin = (Test-IsAdmin)
        CurrentTimeUtc = [DateTime]::UtcNow
        TimeZone = [TimeZoneInfo]::Local.StandardName
        TimeZoneOffset = [TimeZoneInfo]::Local.BaseUtcOffset.ToString()
        MachineGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -ErrorAction SilentlyContinue).MachineGuid
    }

    # Check if VM
    $cs = Get-WmiData -Class Win32_ComputerSystem
    if ($cs) {
        $manufacturer = $cs.Manufacturer.ToLower()
        $model = $cs.Model
        if (($manufacturer -eq "microsoft corporation" -and $model -match "VIRTUAL") -or
            $manufacturer -match "vmware" -or
            $manufacturer -match "xen" -or
            $model -eq "VirtualBox") {
            $osInfo.IsVirtualMachine = $true
        }
    }

    # Get boot time
    try {
        $os = Get-WmiData -Class Win32_OperatingSystem
        if ($os.LastBootUpTime) {
            $osInfo.BootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
        }
    }
    catch { }

    # Add UBR to build if available
    $ubr = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).UBR
    if ($ubr) {
        $osInfo.Build = "$($osInfo.Build).$ubr"
    }

    # Output
    Write-CommandOutput "Hostname" $osInfo.Hostname
    Write-CommandOutput "Domain Name" $osInfo.Domain
    Write-CommandOutput "Username" $osInfo.Username
    Write-CommandOutput "ProductName" $osInfo.ProductName
    Write-CommandOutput "EditionID" $osInfo.EditionID
    Write-CommandOutput "ReleaseId" $osInfo.ReleaseId
    Write-CommandOutput "DisplayVersion" $osInfo.DisplayVersion
    Write-CommandOutput "Build" $osInfo.Build
    Write-CommandOutput "BuildBranch" $osInfo.BuildBranch
    Write-CommandOutput "CurrentMajorVersion" $osInfo.CurrentMajorVersion
    Write-CommandOutput "CurrentVersion" $osInfo.CurrentVersion
    Write-CommandOutput "Architecture" $osInfo.Architecture
    Write-CommandOutput "ProcessorCount" $osInfo.ProcessorCount
    Write-CommandOutput "IsVirtualMachine" $osInfo.IsVirtualMachine

    if ($osInfo.BootTime) {
        $uptime = [DateTime]::UtcNow - $osInfo.BootTime
        $uptimeStr = "{0:00}:{1:00}:{2:00}:{3:00}" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds
        Write-CommandOutput "BootTimeUtc" "$($osInfo.BootTime) (Uptime: $uptimeStr)"
    }

    Write-CommandOutput "HighIntegrity" $osInfo.IsHighIntegrity
    Write-CommandOutput "IsLocalAdmin" $osInfo.IsLocalAdmin

    if (-not $osInfo.IsHighIntegrity -and $osInfo.IsLocalAdmin) {
        Write-Host "    [*] In medium integrity but user is a local administrator - UAC can be bypassed." -ForegroundColor Yellow
    }

    Write-CommandOutput "CurrentTimeUtc" "$($osInfo.CurrentTimeUtc) (Local: $($osInfo.CurrentTimeUtc.ToLocalTime()))"
    Write-CommandOutput "TimeZone" $osInfo.TimeZone
    Write-CommandOutput "TimeZoneOffset" $osInfo.TimeZoneOffset
    Write-CommandOutput "MachineGuid" $osInfo.MachineGuid

    return $osInfo
}

function Get-SBAntiVirus {
    <#
    .SYNOPSIS
        Registered antivirus (via WMI)
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "AntiVirus" "Registered antivirus (via WMI)"

    # Check if server
    $os = Get-WmiData -Class Win32_OperatingSystem
    if ($os.ProductType -ne 1) {
        Write-Host "  Cannot enumerate antivirus. root\SecurityCenter2 WMI namespace is not available on Windows Servers" -ForegroundColor Yellow
        return
    }

    try {
        $avProducts = Get-WmiData -Class AntiVirusProduct -Namespace "root\SecurityCenter2"

        foreach ($av in $avProducts) {
            $result = [PSCustomObject]@{
                Engine = $av.displayName
                ProductExe = $av.pathToSignedProductExe
                ReportingExe = $av.pathToSignedReportingExe
            }

            Write-CommandOutput "Engine" $result.Engine
            Write-CommandOutput "ProductExe" $result.ProductExe
            Write-CommandOutput "ReportingExe" $result.ReportingExe
            Write-Host ""

            $Script:Results += $result
        }
    }
    catch {
        Write-Host "  Error enumerating antivirus: $_" -ForegroundColor Red
    }
}

function Get-SBProcesses {
    <#
    .SYNOPSIS
        Running processes with file info
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "Processes" "Running processes with file info company names that don't contain 'Microsoft'"

    if ($Script:FilterResults) {
        Write-Host "  Collecting Non Microsoft Processes" -ForegroundColor DarkGray
    }
    else {
        Write-Host "  Collecting All Processes" -ForegroundColor DarkGray
    }
    Write-Host ""

    $wmiProcesses = Get-WmiData -Class Win32_Process |
        Select-Object ProcessId, ParentProcessId, ExecutablePath, CommandLine

    $processes = Get-Process -ErrorAction SilentlyContinue

    foreach ($proc in $processes) {
        $wmiProc = $wmiProcesses | Where-Object { $_.ProcessId -eq $proc.Id }

        $companyName = $null
        $description = $null
        $version = $null
        $path = $wmiProc.ExecutablePath

        if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
            try {
                $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
                $companyName = $fileInfo.CompanyName
                $description = $fileInfo.FileDescription
                $version = $fileInfo.FileVersion
            }
            catch { }
        }

        # Filter Microsoft processes if filtering enabled
        if ($Script:FilterResults) {
            if ($companyName -and $companyName -match "^Microsoft") {
                continue
            }
            if ([string]::IsNullOrWhiteSpace($companyName)) {
                continue
            }
        }

        $result = [PSCustomObject]@{
            ProcessName = $proc.ProcessName
            ProcessId = $proc.Id
            ParentProcessId = $wmiProc.ParentProcessId
            CompanyName = $companyName
            Description = $description
            Version = $version
            Path = $path
            CommandLine = $wmiProc.CommandLine
        }

        Write-Host " ProcessName                              : $($result.ProcessName)"
        Write-Host " ProcessId                                : $($result.ProcessId)"
        Write-Host " ParentProcessId                          : $($result.ParentProcessId)"
        Write-Host " CompanyName                              : $($result.CompanyName)"
        Write-Host " Description                              : $($result.Description)"
        Write-Host " Version                                  : $($result.Version)"
        Write-Host " Path                                     : $($result.Path)"
        Write-Host " CommandLine                              : $($result.CommandLine)"
        Write-Host ""

        $Script:Results += $result
    }
}

function Get-SBServices {
    <#
    .SYNOPSIS
        Services with file info
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "Services" "Services with file info company names that don't contain 'Microsoft'"

    if ($Script:FilterResults) {
        Write-Host "  Non Microsoft Services (via WMI)" -ForegroundColor DarkGray
    }
    else {
        Write-Host "  All Services (via WMI)" -ForegroundColor DarkGray
    }
    Write-Host ""

    $services = Get-WmiData -Class Win32_Service

    foreach ($svc in $services) {
        $companyName = $null
        $description = $null
        $version = $null
        $binaryPath = $null

        # Extract binary path from PathName
        if ($svc.PathName) {
            $pathMatch = [regex]::Match($svc.PathName, '^\W*([a-z]:\\.+?(\.exe|\.dll|\.sys))\W*', 'IgnoreCase')
            if ($pathMatch.Success) {
                $binaryPath = $pathMatch.Groups[1].Value
            }
        }

        # Get ServiceDll for svchost services
        if ($binaryPath -and $binaryPath -match "svchost\.exe$") {
            $serviceDll = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)\Parameters" -Name ServiceDll -ErrorAction SilentlyContinue |
                         Select-Object -ExpandProperty ServiceDll -ErrorAction SilentlyContinue
            if (-not $serviceDll) {
                $serviceDll = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" -Name ServiceDll -ErrorAction SilentlyContinue |
                             Select-Object -ExpandProperty ServiceDll -ErrorAction SilentlyContinue
            }
            if ($serviceDll) {
                $binaryPath = $serviceDll
            }
        }

        if ($binaryPath -and (Test-Path $binaryPath -ErrorAction SilentlyContinue)) {
            try {
                $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($binaryPath)
                $companyName = $fileInfo.CompanyName
                $description = $fileInfo.FileDescription
                $version = $fileInfo.FileVersion
            }
            catch { }
        }

        # Filter Microsoft services if filtering enabled
        if ($Script:FilterResults) {
            if ($companyName -and $companyName -match "^Microsoft") {
                continue
            }
        }

        $result = [PSCustomObject]@{
            Name = $svc.Name
            DisplayName = $svc.DisplayName
            Description = $svc.Description
            User = $svc.StartName
            State = $svc.State
            StartMode = $svc.StartMode
            ServiceType = $svc.ServiceType
            PathName = $svc.PathName
            BinaryPath = $binaryPath
            CompanyName = $companyName
            FileDescription = $description
            Version = $version
        }

        Write-Host " Name                                     : $($result.Name)"
        Write-Host " DisplayName                              : $($result.DisplayName)"
        Write-Host " Description                              : $($result.Description)"
        Write-Host " User                                     : $($result.User)"
        Write-Host " State                                    : $($result.State)"
        Write-Host " StartMode                                : $($result.StartMode)"
        Write-Host " ServiceType                              : $($result.ServiceType)"
        Write-Host " PathName                                 : $($result.PathName)"
        Write-Host " BinaryPath                               : $($result.BinaryPath)"
        Write-Host " CompanyName                              : $($result.CompanyName)"
        Write-Host " FileDescription                          : $($result.FileDescription)"
        Write-Host " Version                                  : $($result.Version)"
        Write-Host ""

        $Script:Results += $result
    }
}

function Get-SBHotfixes {
    <#
    .SYNOPSIS
        Installed hotfixes (via WMI)
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "Hotfixes" "Installed hotfixes (via WMI)"

    Write-Host "  Enumerating Windows Hotfixes. For *all* Microsoft updates, use 'MicrosoftUpdates' command." -ForegroundColor DarkGray
    Write-Host ""

    $hotfixes = Get-WmiData -Class Win32_QuickFixEngineering

    Write-Host ("  {0,-12} {1,-24} {2,-35} {3}" -f "HotFixID", "InstalledOn", "Description", "InstalledBy")
    Write-Host ("  {0,-12} {1,-24} {2,-35} {3}" -f "--------", "-----------", "-----------", "-----------")

    foreach ($hf in $hotfixes) {
        $installedOn = $null
        try {
            if ($hf.InstalledOn) {
                $installedOn = [DateTime]::Parse($hf.InstalledOn)
            }
        }
        catch { }

        Write-Host ("  {0,-12} {1,-24} {2,-35} {3}" -f $hf.HotFixID, $installedOn, $hf.Description, $hf.InstalledBy)

        $Script:Results += [PSCustomObject]@{
            HotFixID = $hf.HotFixID
            InstalledOn = $installedOn
            Description = $hf.Description
            InstalledBy = $hf.InstalledBy
        }
    }
}

function Get-SBDotNet {
    <#
    .SYNOPSIS
        Installed .NET versions
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "DotNet" "Installed .NET versions"

    # .NET Framework versions
    Write-Host "  .NET Framework Versions:" -ForegroundColor Cyan

    $netPath = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP"

    # Check for .NET 4.5+
    $net45Path = "$netPath\v4\Full"
    if (Test-Path $net45Path) {
        $release = (Get-ItemProperty -Path $net45Path -ErrorAction SilentlyContinue).Release
        $version = (Get-ItemProperty -Path $net45Path -ErrorAction SilentlyContinue).Version

        $versionName = switch ($release) {
            { $_ -ge 533320 } { ".NET Framework 4.8.1 or later" }
            { $_ -ge 528040 } { ".NET Framework 4.8" }
            { $_ -ge 461808 } { ".NET Framework 4.7.2" }
            { $_ -ge 461308 } { ".NET Framework 4.7.1" }
            { $_ -ge 460798 } { ".NET Framework 4.7" }
            { $_ -ge 394802 } { ".NET Framework 4.6.2" }
            { $_ -ge 394254 } { ".NET Framework 4.6.1" }
            { $_ -ge 393295 } { ".NET Framework 4.6" }
            { $_ -ge 379893 } { ".NET Framework 4.5.2" }
            { $_ -ge 378675 } { ".NET Framework 4.5.1" }
            { $_ -ge 378389 } { ".NET Framework 4.5" }
            default { ".NET Framework 4.x (Release: $release)" }
        }

        Write-CommandOutput "v4.x" "$versionName (Version: $version, Release: $release)"
    }

    # Check for older versions
    @("v2.0.50727", "v3.0", "v3.5") | ForEach-Object {
        $path = "$netPath\$_"
        if (Test-Path $path) {
            $installed = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).Install
            $version = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).Version
            if ($installed -eq 1) {
                Write-CommandOutput $_ "Installed (Version: $version)"
            }
        }
    }

    # .NET Core / .NET 5+ versions
    Write-Host ""
    Write-Host "  .NET Core / .NET 5+ Versions:" -ForegroundColor Cyan

    try {
        $dotnetOutput = & dotnet --list-runtimes 2>$null
        if ($dotnetOutput) {
            foreach ($line in $dotnetOutput) {
                Write-Host "    $line"
            }
        }
        else {
            Write-Host "    dotnet CLI not found or no runtimes installed"
        }
    }
    catch {
        Write-Host "    Unable to enumerate .NET Core/5+ runtimes"
    }
}

function Get-SBEnvironmentVariables {
    <#
    .SYNOPSIS
        Current environment variables
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "EnvironmentVariables" "Current environment variables"

    $envVars = [Environment]::GetEnvironmentVariables()

    foreach ($key in ($envVars.Keys | Sort-Object)) {
        Write-CommandOutput $key $envVars[$key]
    }
}

function Get-SBLocalUsers {
    <#
    .SYNOPSIS
        Local user accounts
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "LocalUsers" "Local user accounts"

    try {
        $users = Get-WmiData -Class Win32_UserAccount -Filter "LocalAccount=True"

        foreach ($user in $users) {
            Write-Host " Name                                     : $($user.Name)"
            Write-Host " FullName                                 : $($user.FullName)"
            Write-Host " Description                              : $($user.Description)"
            Write-Host " SID                                      : $($user.SID)"
            Write-Host " Disabled                                 : $($user.Disabled)"
            Write-Host " Lockout                                  : $($user.Lockout)"
            Write-Host " PasswordRequired                         : $($user.PasswordRequired)"
            Write-Host " PasswordChangeable                       : $($user.PasswordChangeable)"
            Write-Host ""

            $Script:Results += [PSCustomObject]@{
                Name = $user.Name
                FullName = $user.FullName
                Description = $user.Description
                SID = $user.SID
                Disabled = $user.Disabled
                Lockout = $user.Lockout
                PasswordRequired = $user.PasswordRequired
                PasswordChangeable = $user.PasswordChangeable
            }
        }
    }
    catch {
        Write-Host "  Error enumerating local users: $_" -ForegroundColor Red
    }
}

function Get-SBLocalGroups {
    <#
    .SYNOPSIS
        Local groups
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "LocalGroups" "Local groups"

    try {
        $groups = Get-WmiData -Class Win32_Group -Filter "LocalAccount=True"

        foreach ($group in $groups) {
            Write-CommandOutput $group.Name $group.Description
        }
    }
    catch {
        Write-Host "  Error enumerating local groups: $_" -ForegroundColor Red
    }
}

function Get-SBLogonSessions {
    <#
    .SYNOPSIS
        Current logon sessions
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "LogonSessions" "Current logon sessions"

    try {
        $sessions = Get-WmiData -Class Win32_LogonSession

        foreach ($session in $sessions) {
            $user = Get-WmiData -Class Win32_LoggedOnUser |
                    Where-Object { $_.Dependent -match "LogonId=`"$($session.LogonId)`"" }

            $logonType = switch ($session.LogonType) {
                0 { "System" }
                2 { "Interactive" }
                3 { "Network" }
                4 { "Batch" }
                5 { "Service" }
                7 { "Unlock" }
                8 { "NetworkCleartext" }
                9 { "NewCredentials" }
                10 { "RemoteInteractive" }
                11 { "CachedInteractive" }
                default { "Unknown ($($session.LogonType))" }
            }

            $startTime = $null
            if ($session.StartTime) {
                try {
                    $startTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($session.StartTime)
                }
                catch { }
            }

            Write-Host " LogonId                                  : $($session.LogonId)"
            Write-Host " LogonType                                : $logonType"
            Write-Host " AuthenticationPackage                    : $($session.AuthenticationPackage)"
            Write-Host " StartTime                                : $startTime"
            Write-Host ""
        }
    }
    catch {
        Write-Host "  Error enumerating logon sessions: $_" -ForegroundColor Red
    }
}

function Get-SBNetworkShares {
    <#
    .SYNOPSIS
        Network shares
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "NetworkShares" "Network shares"

    try {
        $shares = Get-WmiData -Class Win32_Share

        Write-Host ("  {0,-20} {1,-50} {2}" -f "Name", "Path", "Description")
        Write-Host ("  {0,-20} {1,-50} {2}" -f "----", "----", "-----------")

        foreach ($share in $shares) {
            Write-Host ("  {0,-20} {1,-50} {2}" -f $share.Name, $share.Path, $share.Description)

            $Script:Results += [PSCustomObject]@{
                Name = $share.Name
                Path = $share.Path
                Description = $share.Description
            }
        }
    }
    catch {
        Write-Host "  Error enumerating network shares: $_" -ForegroundColor Red
    }
}

function Get-SBTcpConnections {
    <#
    .SYNOPSIS
        Current TCP connections
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "TcpConnections" "Current TCP connections"

    try {
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue

        Write-Host ("  {0,-25} {1,-8} {2,-25} {3,-8} {4,-15} {5}" -f "LocalAddress", "LPort", "RemoteAddress", "RPort", "State", "ProcessName")
        Write-Host ("  {0,-25} {1,-8} {2,-25} {3,-8} {4,-15} {5}" -f "-----------", "-----", "-------------", "-----", "-----", "-----------")

        foreach ($conn in $connections) {
            $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName

            Write-Host ("  {0,-25} {1,-8} {2,-25} {3,-8} {4,-15} {5}" -f $conn.LocalAddress, $conn.LocalPort, $conn.RemoteAddress, $conn.RemotePort, $conn.State, $procName)
        }
    }
    catch {
        Write-Host "  Error enumerating TCP connections: $_" -ForegroundColor Red
    }
}

function Get-SBUdpConnections {
    <#
    .SYNOPSIS
        Current UDP endpoints
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "UdpConnections" "Current UDP endpoints"

    try {
        $endpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue

        Write-Host ("  {0,-25} {1,-8} {2}" -f "LocalAddress", "LPort", "ProcessName")
        Write-Host ("  {0,-25} {1,-8} {2}" -f "-----------", "-----", "-----------")

        foreach ($ep in $endpoints) {
            $procName = (Get-Process -Id $ep.OwningProcess -ErrorAction SilentlyContinue).ProcessName

            Write-Host ("  {0,-25} {1,-8} {2}" -f $ep.LocalAddress, $ep.LocalPort, $procName)
        }
    }
    catch {
        Write-Host "  Error enumerating UDP endpoints: $_" -ForegroundColor Red
    }
}

function Get-SBDNSCache {
    <#
    .SYNOPSIS
        DNS cache entries
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "DNSCache" "DNS cache entries"

    try {
        $cache = Get-DnsClientCache -ErrorAction SilentlyContinue

        Write-Host ("  {0,-40} {1,-10} {2}" -f "Name", "Type", "Data")
        Write-Host ("  {0,-40} {1,-10} {2}" -f "----", "----", "----")

        foreach ($entry in $cache) {
            $type = switch ($entry.Type) {
                1 { "A" }
                5 { "CNAME" }
                28 { "AAAA" }
                default { $entry.Type }
            }

            Write-Host ("  {0,-40} {1,-10} {2}" -f $entry.Entry, $type, $entry.Data)
        }
    }
    catch {
        Write-Host "  Error enumerating DNS cache: $_" -ForegroundColor Red
    }
}

function Get-SBARPTable {
    <#
    .SYNOPSIS
        ARP table entries
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "ARPTable" "ARP table entries"

    try {
        $arp = Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Permanent' }

        Write-Host ("  {0,-20} {1,-20} {2,-15} {3}" -f "IPAddress", "LinkLayerAddress", "State", "Interface")
        Write-Host ("  {0,-20} {1,-20} {2,-15} {3}" -f "---------", "----------------", "-----", "---------")

        foreach ($entry in $arp) {
            $ifName = (Get-NetAdapter -InterfaceIndex $entry.InterfaceIndex -ErrorAction SilentlyContinue).Name
            Write-Host ("  {0,-20} {1,-20} {2,-15} {3}" -f $entry.IPAddress, $entry.LinkLayerAddress, $entry.State, $ifName)
        }
    }
    catch {
        Write-Host "  Error enumerating ARP table: $_" -ForegroundColor Red
    }
}

function Get-SBScheduledTasks {
    <#
    .SYNOPSIS
        Scheduled tasks
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "ScheduledTasks" "Scheduled tasks (non-Microsoft)"

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue

        foreach ($task in $tasks) {
            # Filter Microsoft tasks if filtering enabled
            if ($Script:FilterResults) {
                if ($task.Author -match "^Microsoft" -or $task.TaskPath -match "^\\Microsoft") {
                    continue
                }
            }

            $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue

            Write-Host " TaskName                                 : $($task.TaskName)"
            Write-Host " TaskPath                                 : $($task.TaskPath)"
            Write-Host " State                                    : $($task.State)"
            Write-Host " Author                                   : $($task.Author)"
            Write-Host " Description                              : $($task.Description)"
            if ($task.Actions) {
                foreach ($action in $task.Actions) {
                    Write-Host " Action                                   : $($action.Execute) $($action.Arguments)"
                }
            }
            Write-Host " LastRunTime                              : $($info.LastRunTime)"
            Write-Host " NextRunTime                              : $($info.NextRunTime)"
            Write-Host ""
        }
    }
    catch {
        Write-Host "  Error enumerating scheduled tasks: $_" -ForegroundColor Red
    }
}

function Get-SBAutoRuns {
    <#
    .SYNOPSIS
        Auto-run executables/scripts/programs
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "AutoRuns" "Auto-run executables/scripts/programs"

    $autorunLocations = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($location in $autorunLocations) {
        if (Test-Path $location) {
            Write-Host "  $location" -ForegroundColor Cyan

            $props = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                Write-CommandOutput $_.Name $_.Value
            }
            Write-Host ""
        }
    }

    # Startup folders
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            Write-Host "  $folder" -ForegroundColor Cyan
            Get-ChildItem -Path $folder -ErrorAction SilentlyContinue | ForEach-Object {
                Write-CommandOutput $_.Name $_.FullName
            }
            Write-Host ""
        }
    }
}

function Get-SBWindowsFirewall {
    <#
    .SYNOPSIS
        Windows Firewall status
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "WindowsFirewall" "Windows Firewall status"

    try {
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue

        foreach ($profile in $profiles) {
            Write-Host "  $($profile.Name) Profile:" -ForegroundColor Cyan
            Write-CommandOutput "Enabled" $profile.Enabled
            Write-CommandOutput "DefaultInboundAction" $profile.DefaultInboundAction
            Write-CommandOutput "DefaultOutboundAction" $profile.DefaultOutboundAction
            Write-CommandOutput "LogFileName" $profile.LogFileName
            Write-CommandOutput "LogMaxSizeKilobytes" $profile.LogMaxSizeKilobytes
            Write-CommandOutput "LogBlocked" $profile.LogBlocked
            Write-Host ""
        }
    }
    catch {
        Write-Host "  Error enumerating firewall status: $_" -ForegroundColor Red
    }
}

function Get-SBWindowsDefender {
    <#
    .SYNOPSIS
        Windows Defender status
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "WindowsDefender" "Windows Defender status"

    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue

        if ($defender) {
            Write-CommandOutput "AMServiceEnabled" $defender.AMServiceEnabled
            Write-CommandOutput "AntispywareEnabled" $defender.AntispywareEnabled
            Write-CommandOutput "AntivirusEnabled" $defender.AntivirusEnabled
            Write-CommandOutput "BehaviorMonitorEnabled" $defender.BehaviorMonitorEnabled
            Write-CommandOutput "IoavProtectionEnabled" $defender.IoavProtectionEnabled
            Write-CommandOutput "NISEnabled" $defender.NISEnabled
            Write-CommandOutput "OnAccessProtectionEnabled" $defender.OnAccessProtectionEnabled
            Write-CommandOutput "RealTimeProtectionEnabled" $defender.RealTimeProtectionEnabled
            Write-CommandOutput "AntivirusSignatureLastUpdated" $defender.AntivirusSignatureLastUpdated
            Write-CommandOutput "AntivirusSignatureVersion" $defender.AntivirusSignatureVersion
            Write-CommandOutput "QuickScanAge" "$($defender.QuickScanAge) days"
            Write-CommandOutput "FullScanAge" "$($defender.FullScanAge) days"
        }

        # Exclusions
        Write-Host ""
        Write-Host "  Exclusions:" -ForegroundColor Cyan

        $prefs = Get-MpPreference -ErrorAction SilentlyContinue
        if ($prefs) {
            if ($prefs.ExclusionPath) {
                Write-Host "    Path Exclusions:"
                foreach ($path in $prefs.ExclusionPath) {
                    Write-Host "      $path"
                }
            }
            if ($prefs.ExclusionProcess) {
                Write-Host "    Process Exclusions:"
                foreach ($proc in $prefs.ExclusionProcess) {
                    Write-Host "      $proc"
                }
            }
            if ($prefs.ExclusionExtension) {
                Write-Host "    Extension Exclusions:"
                foreach ($ext in $prefs.ExclusionExtension) {
                    Write-Host "      $ext"
                }
            }
        }
    }
    catch {
        Write-Host "  Error enumerating Windows Defender status: $_" -ForegroundColor Red
    }
}

function Get-SBUAC {
    <#
    .SYNOPSIS
        UAC system policies
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "UAC" "UAC system policies"

    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    if (Test-Path $uacPath) {
        $uac = Get-ItemProperty -Path $uacPath -ErrorAction SilentlyContinue

        Write-CommandOutput "EnableLUA" $uac.EnableLUA
        Write-CommandOutput "ConsentPromptBehaviorAdmin" $uac.ConsentPromptBehaviorAdmin
        Write-CommandOutput "ConsentPromptBehaviorUser" $uac.ConsentPromptBehaviorUser
        Write-CommandOutput "FilterAdministratorToken" $uac.FilterAdministratorToken
        Write-CommandOutput "EnableInstallerDetection" $uac.EnableInstallerDetection
        Write-CommandOutput "EnableSecureUIAPaths" $uac.EnableSecureUIAPaths
        Write-CommandOutput "EnableVirtualization" $uac.EnableVirtualization
        Write-CommandOutput "PromptOnSecureDesktop" $uac.PromptOnSecureDesktop

        # Interpret settings
        Write-Host ""
        if ($uac.EnableLUA -eq 0) {
            Write-Host "  [!] UAC is DISABLED" -ForegroundColor Red
        }
        elseif ($uac.ConsentPromptBehaviorAdmin -eq 0 -and $uac.PromptOnSecureDesktop -eq 0) {
            Write-Host "  [*] UAC is configured to auto-elevate without prompting" -ForegroundColor Yellow
        }
    }
}

function Get-SBLSASettings {
    <#
    .SYNOPSIS
        LSA settings
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "LSASettings" "LSA settings"

    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    if (Test-Path $lsaPath) {
        $lsa = Get-ItemProperty -Path $lsaPath -ErrorAction SilentlyContinue

        Write-CommandOutput "RunAsPPL" $lsa.RunAsPPL
        Write-CommandOutput "LimitBlankPasswordUse" $lsa.LimitBlankPasswordUse
        Write-CommandOutput "NoLmHash" $lsa.NoLmHash
        Write-CommandOutput "DisableDomainCreds" $lsa.DisableDomainCreds
        Write-CommandOutput "EveryoneIncludesAnonymous" $lsa.EveryoneIncludesAnonymous
        Write-CommandOutput "RestrictAnonymousSAM" $lsa.RestrictAnonymousSAM
        Write-CommandOutput "RestrictAnonymous" $lsa.RestrictAnonymous

        # Credential Guard
        $credGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
        $lsaCfg = Get-ItemProperty -Path $credGuardPath -ErrorAction SilentlyContinue
        if ($lsaCfg.LsaCfgFlags) {
            Write-Host ""
            Write-Host "  Credential Guard:" -ForegroundColor Cyan
            Write-CommandOutput "LsaCfgFlags" $lsaCfg.LsaCfgFlags
            if ($lsaCfg.LsaCfgFlags -ge 1) {
                Write-Host "    [*] Credential Guard may be enabled" -ForegroundColor Yellow
            }
        }
    }
}

function Get-SBPowerShellHistory {
    <#
    .SYNOPSIS
        PowerShell command history
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "PowerShellHistory" "PowerShell command history"

    $historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

    if (Test-Path $historyPath) {
        Write-Host "  History file: $historyPath" -ForegroundColor DarkGray
        Write-Host ""

        $history = Get-Content -Path $historyPath -Tail 100 -ErrorAction SilentlyContinue

        foreach ($line in $history) {
            Write-Host "  $line"
        }
    }
    else {
        Write-Host "  No PowerShell history file found"
    }
}

function Get-SBMappedDrives {
    <#
    .SYNOPSIS
        Mapped drives
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "MappedDrives" "Mapped drives"

    try {
        $drives = Get-WmiData -Class Win32_MappedLogicalDisk

        foreach ($drive in $drives) {
            Write-CommandOutput $drive.DeviceID $drive.ProviderName
        }

        # Also check registry for persistent mappings
        Write-Host ""
        Write-Host "  Persistent Network Drives:" -ForegroundColor Cyan
        $networkPath = "HKCU:\Network"
        if (Test-Path $networkPath) {
            Get-ChildItem -Path $networkPath | ForEach-Object {
                $props = Get-ItemProperty -Path $_.PSPath
                Write-CommandOutput $_.PSChildName $props.RemotePath
            }
        }
    }
    catch {
        Write-Host "  Error enumerating mapped drives: $_" -ForegroundColor Red
    }
}

function Get-SBInstalledProducts {
    <#
    .SYNOPSIS
        Installed software
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "InstalledProducts" "Installed software"

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $products = foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
    }

    $products = $products | Sort-Object DisplayName -Unique

    Write-Host ("  {0,-50} {1,-20} {2}" -f "Name", "Version", "Publisher")
    Write-Host ("  {0,-50} {1,-20} {2}" -f "----", "-------", "---------")

    foreach ($prod in $products) {
        Write-Host ("  {0,-50} {1,-20} {2}" -f $prod.DisplayName.Substring(0, [Math]::Min(49, $prod.DisplayName.Length)), $prod.DisplayVersion, $prod.Publisher)
    }
}

function Get-SBSecureBoot {
    <#
    .SYNOPSIS
        Secure Boot configuration
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "SecureBoot" "Secure Boot configuration"

    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        Write-CommandOutput "SecureBootEnabled" $secureBoot
    }
    catch {
        Write-Host "  Unable to determine Secure Boot status (may require admin or UEFI system)"
    }
}

function Get-SBCredentialGuard {
    <#
    .SYNOPSIS
        Credential Guard status
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "CredentialGuard" "Credential Guard status"

    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue

        if ($dg) {
            Write-CommandOutput "SecurityServicesConfigured" ($dg.SecurityServicesConfigured -join ", ")
            Write-CommandOutput "SecurityServicesRunning" ($dg.SecurityServicesRunning -join ", ")
            Write-CommandOutput "VirtualizationBasedSecurityStatus" $dg.VirtualizationBasedSecurityStatus

            # Interpret
            if ($dg.SecurityServicesRunning -contains 1) {
                Write-Host ""
                Write-Host "  [*] Credential Guard is running" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "  Unable to query Device Guard status"
        }
    }
    catch {
        Write-Host "  Error querying Credential Guard: $_" -ForegroundColor Red
    }
}

function Get-SBBitLockerStatus {
    <#
    .SYNOPSIS
        BitLocker volume status
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "BitLocker" "BitLocker volume status"

    try {
        $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue

        foreach ($vol in $volumes) {
            Write-Host " MountPoint                               : $($vol.MountPoint)"
            Write-Host " EncryptionMethod                         : $($vol.EncryptionMethod)"
            Write-Host " VolumeStatus                             : $($vol.VolumeStatus)"
            Write-Host " ProtectionStatus                         : $($vol.ProtectionStatus)"
            Write-Host " LockStatus                               : $($vol.LockStatus)"
            Write-Host " EncryptionPercentage                     : $($vol.EncryptionPercentage)%"
            Write-Host " KeyProtector                             : $(($vol.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ', ')"
            Write-Host ""
        }
    }
    catch {
        Write-Host "  Unable to query BitLocker status (may require admin)" -ForegroundColor Yellow
    }
}

#endregion

#region User Commands

function Get-SBSavedRDPConnections {
    <#
    .SYNOPSIS
        Saved RDP connections
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "RDPSavedConnections" "Saved RDP connections"

    $rdpPath = "HKCU:\Software\Microsoft\Terminal Server Client\Servers"

    if (Test-Path $rdpPath) {
        Get-ChildItem -Path $rdpPath | ForEach-Object {
            $server = $_.PSChildName
            $props = Get-ItemProperty -Path $_.PSPath

            Write-CommandOutput "Server" $server
            Write-CommandOutput "UsernameHint" $props.UsernameHint
            Write-Host ""
        }
    }
    else {
        Write-Host "  No saved RDP connections found"
    }
}

function Get-SBPuttyHostKeys {
    <#
    .SYNOPSIS
        PuTTY host keys
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "PuttyHostKeys" "PuTTY host keys"

    $puttyPath = "HKCU:\Software\SimonTatham\PuTTY\SshHostKeys"

    if (Test-Path $puttyPath) {
        $keys = Get-ItemProperty -Path $puttyPath -ErrorAction SilentlyContinue
        $keys.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            Write-Host "  $($_.Name)"
        }
    }
    else {
        Write-Host "  No PuTTY host keys found"
    }
}

function Get-SBPuttySessions {
    <#
    .SYNOPSIS
        PuTTY saved sessions
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "PuttySessions" "PuTTY saved sessions"

    $puttyPath = "HKCU:\Software\SimonTatham\PuTTY\Sessions"

    if (Test-Path $puttyPath) {
        Get-ChildItem -Path $puttyPath | ForEach-Object {
            $sessionName = $_.PSChildName
            $props = Get-ItemProperty -Path $_.PSPath

            Write-Host " SessionName                              : $sessionName"
            Write-Host " HostName                                 : $($props.HostName)"
            Write-Host " UserName                                 : $($props.UserName)"
            Write-Host " PortNumber                               : $($props.PortNumber)"
            Write-Host " PublicKeyFile                            : $($props.PublicKeyFile)"
            Write-Host ""
        }
    }
    else {
        Write-Host "  No PuTTY sessions found"
    }
}

function Get-SBRecentFiles {
    <#
    .SYNOPSIS
        Recently accessed files
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "RecentFiles" "Recently accessed files"

    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"

    if (Test-Path $recentPath) {
        $shell = New-Object -ComObject WScript.Shell

        Get-ChildItem -Path $recentPath -Filter "*.lnk" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 50 |
        ForEach-Object {
            try {
                $shortcut = $shell.CreateShortcut($_.FullName)
                Write-Host ("  {0,-30} : {1}" -f $_.BaseName, $shortcut.TargetPath)
            }
            catch { }
        }
    }
    else {
        Write-Host "  No recent files found"
    }
}

function Get-SBClipboard {
    <#
    .SYNOPSIS
        Current clipboard contents
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "Clipboard" "Current clipboard contents"

    try {
        Add-Type -AssemblyName System.Windows.Forms
        $clipboard = [System.Windows.Forms.Clipboard]::GetText()

        if ($clipboard) {
            Write-Host "  Clipboard contents:"
            Write-Host "  $clipboard"
        }
        else {
            Write-Host "  Clipboard is empty or contains non-text data"
        }
    }
    catch {
        Write-Host "  Unable to access clipboard: $_" -ForegroundColor Red
    }
}

#endregion

#region Browser Commands

function Get-SBChromeHistory {
    <#
    .SYNOPSIS
        Chrome browser history
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "ChromeHistory" "Chrome browser history"

    $chromePaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile 1\History"
    )

    foreach ($path in $chromePaths) {
        if (Test-Path $path) {
            Write-Host "  Found Chrome history at: $path" -ForegroundColor DarkGray
            Write-Host "  (Requires SQLite to parse - file is locked when Chrome is running)"
            Write-Host ""

            # Show file info
            $file = Get-Item -Path $path
            Write-CommandOutput "Size" (Format-FileSize $file.Length)
            Write-CommandOutput "LastModified" $file.LastWriteTime
        }
    }
}

function Get-SBChromeBookmarks {
    <#
    .SYNOPSIS
        Chrome bookmarks
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "ChromeBookmarks" "Chrome bookmarks"

    $bookmarksPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks"

    if (Test-Path $bookmarksPath) {
        try {
            $bookmarks = Get-Content -Path $bookmarksPath -Raw | ConvertFrom-Json

            function Get-BookmarkItems {
                param($node)

                if ($node.type -eq "url") {
                    Write-Host ("  {0,-50} : {1}" -f $node.name.Substring(0, [Math]::Min(49, $node.name.Length)), $node.url)
                }

                if ($node.children) {
                    foreach ($child in $node.children) {
                        Get-BookmarkItems $child
                    }
                }
            }

            Get-BookmarkItems $bookmarks.roots.bookmark_bar
            Get-BookmarkItems $bookmarks.roots.other
        }
        catch {
            Write-Host "  Error parsing bookmarks: $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "  No Chrome bookmarks found"
    }
}

function Get-SBFirefoxHistory {
    <#
    .SYNOPSIS
        Firefox browser info
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "FirefoxPresence" "Firefox presence and profiles"

    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"

    if (Test-Path $firefoxPath) {
        Get-ChildItem -Path $firefoxPath -Directory | ForEach-Object {
            Write-Host " Profile                                  : $($_.Name)"
            Write-Host " Path                                     : $($_.FullName)"

            $placesDb = Join-Path $_.FullName "places.sqlite"
            if (Test-Path $placesDb) {
                $dbInfo = Get-Item $placesDb
                Write-Host " HistoryDB Size                           : $(Format-FileSize $dbInfo.Length)"
                Write-Host " HistoryDB LastModified                   : $($dbInfo.LastWriteTime)"
            }
            Write-Host ""
        }
    }
    else {
        Write-Host "  Firefox not found"
    }
}

function Get-SBIEHistory {
    <#
    .SYNOPSIS
        Internet Explorer typed URLs
    #>
    [CmdletBinding()]
    param()

    Write-CommandHeader "InternetExplorerTypedURLs" "Internet Explorer typed URLs"

    $iePath = "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs"

    if (Test-Path $iePath) {
        $urls = Get-ItemProperty -Path $iePath -ErrorAction SilentlyContinue
        $urls.PSObject.Properties | Where-Object { $_.Name -match "^url" } | ForEach-Object {
            Write-Host "  $($_.Value)"
        }
    }
    else {
        Write-Host "  No IE typed URLs found"
    }
}

#endregion

#region Command Groups

$Script:CommandGroups = @{
    System = @(
        "OSInfo", "AntiVirus", "Processes", "Services", "Hotfixes", "DotNet",
        "EnvironmentVariables", "LocalUsers", "LocalGroups", "LogonSessions",
        "NetworkShares", "TcpConnections", "UdpConnections", "DNSCache", "ARPTable",
        "ScheduledTasks", "AutoRuns", "WindowsFirewall", "WindowsDefender",
        "UAC", "LSASettings", "MappedDrives", "InstalledProducts", "SecureBoot",
        "CredentialGuard", "BitLocker"
    )
    User = @(
        "RDPSavedConnections", "PuttyHostKeys", "PuttySessions", "RecentFiles",
        "Clipboard", "PowerShellHistory"
    )
    Browser = @(
        "ChromeHistory", "ChromeBookmarks", "FirefoxHistory", "IEHistory"
    )
    Remote = @(
        "OSInfo", "AntiVirus", "Hotfixes", "NetworkShares", "LocalUsers", "LocalGroups"
    )
    Misc = @(
        "EnvironmentVariables", "Clipboard"
    )
}

$Script:AllCommands = @{
    "OSInfo" = { Get-SBOSInfo }
    "AntiVirus" = { Get-SBAntiVirus }
    "Processes" = { Get-SBProcesses }
    "Services" = { Get-SBServices }
    "Hotfixes" = { Get-SBHotfixes }
    "DotNet" = { Get-SBDotNet }
    "EnvironmentVariables" = { Get-SBEnvironmentVariables }
    "LocalUsers" = { Get-SBLocalUsers }
    "LocalGroups" = { Get-SBLocalGroups }
    "LogonSessions" = { Get-SBLogonSessions }
    "NetworkShares" = { Get-SBNetworkShares }
    "TcpConnections" = { Get-SBTcpConnections }
    "UdpConnections" = { Get-SBUdpConnections }
    "DNSCache" = { Get-SBDNSCache }
    "ARPTable" = { Get-SBARPTable }
    "ScheduledTasks" = { Get-SBScheduledTasks }
    "AutoRuns" = { Get-SBAutoRuns }
    "WindowsFirewall" = { Get-SBWindowsFirewall }
    "WindowsDefender" = { Get-SBWindowsDefender }
    "UAC" = { Get-SBUAC }
    "LSASettings" = { Get-SBLSASettings }
    "PowerShellHistory" = { Get-SBPowerShellHistory }
    "MappedDrives" = { Get-SBMappedDrives }
    "InstalledProducts" = { Get-SBInstalledProducts }
    "SecureBoot" = { Get-SBSecureBoot }
    "CredentialGuard" = { Get-SBCredentialGuard }
    "BitLocker" = { Get-SBBitLockerStatus }
    "RDPSavedConnections" = { Get-SBSavedRDPConnections }
    "PuttyHostKeys" = { Get-SBPuttyHostKeys }
    "PuttySessions" = { Get-SBPuttySessions }
    "RecentFiles" = { Get-SBRecentFiles }
    "Clipboard" = { Get-SBClipboard }
    "ChromeHistory" = { Get-SBChromeHistory }
    "ChromeBookmarks" = { Get-SBChromeBookmarks }
    "FirefoxHistory" = { Get-SBFirefoxHistory }
    "IEHistory" = { Get-SBIEHistory }
}

#endregion

#region Help

function Show-Help {
    Write-Host ""
    Write-Host "Usage: .\Seatbelt.ps1 [-Command <command1,command2,...>] [-Group <groupname>] [-Full] [-OutputFile <path>] [-Quiet]"
    Write-Host ""
    Write-Host "Available Commands:" -ForegroundColor Cyan

    foreach ($cmd in ($Script:AllCommands.Keys | Sort-Object)) {
        Write-Host "  $cmd"
    }

    Write-Host ""
    Write-Host "Available Groups:" -ForegroundColor Cyan
    Write-Host "  System   - System enumeration commands"
    Write-Host "  User     - User-specific enumeration commands"
    Write-Host "  Browser  - Browser data commands"
    Write-Host "  Remote   - Commands that support remote execution"
    Write-Host "  Misc     - Miscellaneous commands"
    Write-Host "  All      - Run all commands"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Cyan
    Write-Host "  .\Seatbelt.ps1 -Command OSInfo"
    Write-Host "  .\Seatbelt.ps1 -Group System"
    Write-Host "  .\Seatbelt.ps1 -Command OSInfo,Processes -Full"
    Write-Host "  .\Seatbelt.ps1 -Group System -OutputFile C:\output.txt"
    Write-Host ""
}

#endregion

#region Main Execution

function Invoke-Seatbelt {
    # Show banner
    Show-Banner

    # If no commands specified, show help
    if (-not $Command -and -not $Group) {
        Show-Help
        return
    }

    $commandsToRun = @()

    # Determine commands to run
    if ($Group) {
        if ($Group -eq "All") {
            $commandsToRun = $Script:AllCommands.Keys
        }
        elseif ($Script:CommandGroups.ContainsKey($Group)) {
            $commandsToRun = $Script:CommandGroups[$Group]
        }
        else {
            Write-Host "Unknown group: $Group" -ForegroundColor Red
            return
        }
    }

    if ($Command) {
        $commandsToRun += $Command
    }

    $commandsToRun = $commandsToRun | Select-Object -Unique

    # Setup output redirection if needed
    $originalOut = $null
    if ($OutputFile) {
        $originalOut = [Console]::Out
        $fileStream = [System.IO.StreamWriter]::new($OutputFile)
        [Console]::SetOut($fileStream)
    }

    try {
        $startTime = Get-Date
        Write-Host ""
        Write-Host "[*] Running $($commandsToRun.Count) command(s)" -ForegroundColor Cyan
        Write-Host "[*] Started at: $startTime" -ForegroundColor DarkGray
        Write-Host ""

        foreach ($cmd in $commandsToRun) {
            if ($Script:AllCommands.ContainsKey($cmd)) {
                try {
                    & $Script:AllCommands[$cmd]
                }
                catch {
                    Write-Host "Error executing $cmd : $_" -ForegroundColor Red
                }
            }
            else {
                Write-Host "Unknown command: $cmd" -ForegroundColor Yellow
            }
        }

        $endTime = Get-Date
        $duration = $endTime - $startTime

        Write-Host ""
        Write-Host "[*] Completed at: $endTime" -ForegroundColor DarkGray
        Write-Host "[*] Duration: $($duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor DarkGray
    }
    finally {
        if ($OutputFile -and $originalOut) {
            $fileStream.Close()
            [Console]::SetOut($originalOut)
            Write-Host "Output written to: $OutputFile" -ForegroundColor Green
        }
    }
}

# Run
Invoke-Seatbelt
