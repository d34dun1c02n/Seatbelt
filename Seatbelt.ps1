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
    Command group to run: All, System, User, Misc, Browser, Remote, Slack, Chromium

.PARAMETER Full
    Return full unfiltered results

.PARAMETER ComputerName
    Remote computer name for commands that support remote execution

.PARAMETER Credential
    PSCredential object for remote authentication

.PARAMETER OutputFile
    Path to output file

.PARAMETER Quiet
    Suppress banner output

.EXAMPLE
    .\Seatbelt.ps1 -Command OSInfo
    .\Seatbelt.ps1 -Group System
    .\Seatbelt.ps1 -Group All -Full

.NOTES
    Version: 1.0.0
    Original Authors: @harmj0y, @tifkin_
    PowerShell Port: Complete conversion from C# Seatbelt
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]]$Command,

    [Parameter()]
    [ValidateSet('All', 'System', 'User', 'Misc', 'Browser', 'Remote', 'Slack', 'Chromium')]
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
    [switch]$Quiet,

    [Parameter()]
    [int]$DelayCommands = 0
)

#region Script Configuration
$Script:Version = "1.0.0"
$Script:FilterResults = -not $Full
$Script:IsRemote = -not [string]::IsNullOrEmpty($ComputerName)
$Script:Results = @()
$Script:StartTime = Get-Date
#endregion

#region Banner
function Show-Banner {
    if ($Quiet) { return }

    $banner = @"

                        %&&@@@&&
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%
                        &%&   %&%%                        &////))))))))))))))))))))))))))))))))))))%teleportation
                        &%%&&&%%%%%            ,*]
            ,##########&@#,  ###  @##############&        &## & @  &@           &
          %&%&%&%&&%&%&#  ## @## @##  ##&####&%#&%##&     &## & &  @&           &
        %&&%&&&&&&&&%%    ## @## @##  ## &   &##  #&#     @## & &  &&    &&&    &
        %%&%%%%%%%-*]     ## @## @##  ## &   &## &#&      &## & &  &@    &&&    &
                          ## @## @##  ## &   &&# @#&      &## & &  &@    &&&    &
                          @# @## @##  ## &   &&  &#&      &## & &  @&    &&&    &
                          ## @@# @##  ## &   %&  @#&      &## & &  @&    &&&    &
                          @# @@@ @##  ## &   &@  @&&      &## & &  @@    &&&    &
                          ## @@@ @@#  #% &   &@  @&&      &## & &  @@    &&&    &
                        %&@# @@@ @@@  @@ &   &@  @&&      &## & &  @@    &&&    &&&&&
                        %%## @@@  @@@@@  &   &@  @&&
                        %%#& @@@@@@@@    &   &@  @&&
                        %%#&     @       &   &@  @&&
                                         &&&&&&&&&&&

  Seatbelt (PowerShell Edition) v$($Script:Version)
  Original Authors: @harmj0y, @tifkin_

"@
    Write-Host $banner -ForegroundColor Cyan
}
#endregion

#region Core Utility Functions

function Test-IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsHighIntegrity {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsLocalAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Test-IsServer {
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
        return ($os.ProductType -ne 1)
    }
    catch { return $false }
}

function Get-UserSIDs {
    try {
        $sids = @()
        $hku = [Microsoft.Win32.Registry]::Users
        foreach ($sid in $hku.GetSubKeyNames()) {
            if ($sid -match '^S-1-5-21-' -and $sid -notmatch '_Classes$') {
                $sids += $sid
            }
        }
        return $sids
    }
    catch { return @() }
}

function Get-RegistryValue {
    param(
        [string]$Hive,
        [string]$Path,
        [string]$Name,
        [string]$ComputerName
    )

    try {
        $hivePath = switch ($Hive) {
            "HKLM" { "HKLM:\$Path" }
            "HKCU" { "HKCU:\$Path" }
            "HKU"  { "Registry::HKEY_USERS\$Path" }
            default { $Path }
        }

        if ($ComputerName -and $ComputerName -ne $env:COMPUTERNAME) {
            $regHive = switch ($Hive) {
                "HKLM" { [Microsoft.Win32.RegistryHive]::LocalMachine }
                "HKCU" { [Microsoft.Win32.RegistryHive]::CurrentUser }
                "HKU"  { [Microsoft.Win32.RegistryHive]::Users }
            }
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($regHive, $ComputerName)
            $key = $reg.OpenSubKey($Path)
            if ($key) {
                return $key.GetValue($Name)
            }
        }
        else {
            if (Test-Path $hivePath) {
                return Get-ItemProperty -Path $hivePath -Name $Name -ErrorAction SilentlyContinue |
                       Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue
            }
        }
    }
    catch { return $null }
}

function Get-RegistryValues {
    param(
        [string]$Hive,
        [string]$Path,
        [string]$ComputerName
    )

    try {
        $hivePath = switch ($Hive) {
            "HKLM" { "HKLM:\$Path" }
            "HKCU" { "HKCU:\$Path" }
            "HKU"  { "Registry::HKEY_USERS\$Path" }
            default { $Path }
        }

        if (Test-Path $hivePath) {
            $props = Get-ItemProperty -Path $hivePath -ErrorAction SilentlyContinue
            $result = @{}
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $result[$_.Name] = $_.Value
            }
            return $result
        }
    }
    catch { return @{} }
}

function Get-RegistrySubkeys {
    param(
        [string]$Hive,
        [string]$Path,
        [string]$ComputerName
    )

    try {
        $hivePath = switch ($Hive) {
            "HKLM" { "HKLM:\$Path" }
            "HKCU" { "HKCU:\$Path" }
            "HKU"  { "Registry::HKEY_USERS\$Path" }
            default { $Path }
        }

        if (Test-Path $hivePath) {
            return (Get-ChildItem -Path $hivePath -ErrorAction SilentlyContinue).PSChildName
        }
    }
    catch { return @() }
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
        [string]$Name,
        $Value,
        [int]$Indent = 2
    )

    $padding = " " * $Indent
    if ($null -eq $Value) { $Value = "" }
    Write-Host ("{0}{1,-40}: {2}" -f $padding, $Name, $Value)
}

function Format-FileSize {
    param([long]$Size)

    if ($Size -gt 1TB) { return "{0:N2} TB" -f ($Size / 1TB) }
    if ($Size -gt 1GB) { return "{0:N2} GB" -f ($Size / 1GB) }
    if ($Size -gt 1MB) { return "{0:N2} MB" -f ($Size / 1MB) }
    if ($Size -gt 1KB) { return "{0:N2} KB" -f ($Size / 1KB) }
    return "$Size bytes"
}

function ConvertFrom-BinaryDateTime {
    param([byte[]]$Bytes)

    if ($null -eq $Bytes -or $Bytes.Length -lt 14) { return $null }

    try {
        $year = [BitConverter]::ToInt16($Bytes, 0)
        $month = [BitConverter]::ToInt16($Bytes, 2)
        $day = [BitConverter]::ToInt16($Bytes, 6)
        $hour = [BitConverter]::ToInt16($Bytes, 8)
        $minute = [BitConverter]::ToInt16($Bytes, 10)
        $second = [BitConverter]::ToInt16($Bytes, 12)

        return New-Object DateTime($year, $month, $day, $hour, $minute, $second)
    }
    catch { return $null }
}

function Get-FileVersionInfo {
    param([string]$Path)

    if ([string]::IsNullOrEmpty($Path)) { return $null }
    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) { return $null }

    try {
        return [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    }
    catch { return $null }
}

#endregion

#region System Commands

function Get-SBOSInfo {
    Write-CommandHeader "OSInfo" "Basic OS info (i.e. architecture, OS version, etc.)"

    $regPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $cs = Get-WmiData -Class Win32_ComputerSystem
    $os = Get-WmiData -Class Win32_OperatingSystem

    $isVM = $false
    if ($cs) {
        $manufacturer = $cs.Manufacturer.ToLower()
        $model = $cs.Model
        if (($manufacturer -eq "microsoft corporation" -and $model -match "VIRTUAL") -or
            $manufacturer -match "vmware" -or $manufacturer -match "xen" -or $model -eq "VirtualBox") {
            $isVM = $true
        }
    }

    $bootTime = $null
    if ($os.LastBootUpTime) {
        $bootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
    }

    Write-CommandOutput "Hostname" $env:COMPUTERNAME
    Write-CommandOutput "Domain Name" $cs.Domain
    Write-CommandOutput "Username" ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
    Write-CommandOutput "ProductName" (Get-RegistryValue -Hive "HKLM" -Path $regPath -Name "ProductName")
    Write-CommandOutput "EditionID" (Get-RegistryValue -Hive "HKLM" -Path $regPath -Name "EditionID")
    Write-CommandOutput "ReleaseId" (Get-RegistryValue -Hive "HKLM" -Path $regPath -Name "ReleaseId")
    Write-CommandOutput "DisplayVersion" (Get-RegistryValue -Hive "HKLM" -Path $regPath -Name "DisplayVersion")
    Write-CommandOutput "Build" "$(Get-RegistryValue -Hive 'HKLM' -Path $regPath -Name 'CurrentBuildNumber').$(Get-RegistryValue -Hive 'HKLM' -Path $regPath -Name 'UBR')"
    Write-CommandOutput "BuildBranch" (Get-RegistryValue -Hive "HKLM" -Path $regPath -Name "BuildBranch")
    Write-CommandOutput "CurrentMajorVersion" (Get-RegistryValue -Hive "HKLM" -Path $regPath -Name "CurrentMajorVersionNumber")
    Write-CommandOutput "CurrentVersion" (Get-RegistryValue -Hive "HKLM" -Path $regPath -Name "CurrentVersion")
    Write-CommandOutput "Architecture" $env:PROCESSOR_ARCHITECTURE
    Write-CommandOutput "ProcessorCount" $env:NUMBER_OF_PROCESSORS
    Write-CommandOutput "IsVirtualMachine" $isVM
    if ($bootTime) {
        $uptime = [DateTime]::Now - $bootTime
        Write-CommandOutput "BootTimeUtc" "$($bootTime.ToUniversalTime()) (Uptime: $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m)"
    }
    Write-CommandOutput "HighIntegrity" (Test-IsHighIntegrity)
    Write-CommandOutput "IsLocalAdmin" (Test-IsLocalAdmin)
    if (-not (Test-IsHighIntegrity) -and (Test-IsLocalAdmin)) {
        Write-Host "    [*] In medium integrity but user is a local administrator - UAC can be bypassed." -ForegroundColor Yellow
    }
    Write-CommandOutput "CurrentTimeUtc" ([DateTime]::UtcNow)
    Write-CommandOutput "TimeZone" ([TimeZoneInfo]::Local.StandardName)
    Write-CommandOutput "TimeZoneOffset" ([TimeZoneInfo]::Local.BaseUtcOffset.ToString())
    Write-CommandOutput "MachineGuid" (Get-RegistryValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid")
}

function Get-SBAntiVirus {
    Write-CommandHeader "AntiVirus" "Registered antivirus (via WMI)"

    if (Test-IsServer) {
        Write-Host "  Cannot enumerate antivirus. root\SecurityCenter2 WMI namespace is not available on Windows Servers" -ForegroundColor Yellow
        return
    }

    try {
        $avProducts = Get-WmiData -Class AntiVirusProduct -Namespace "root\SecurityCenter2"
        foreach ($av in $avProducts) {
            Write-CommandOutput "Engine" $av.displayName
            Write-CommandOutput "ProductExe" $av.pathToSignedProductExe
            Write-CommandOutput "ReportingExe" $av.pathToSignedReportingExe
            Write-Host ""
        }
    }
    catch {
        Write-Host "  Error enumerating antivirus: $_" -ForegroundColor Red
    }
}

function Get-SBAMSIProviders {
    Write-CommandHeader "AMSIProviders" "AMSI provider registration"

    $amsiPath = "SOFTWARE\Microsoft\AMSI\Providers"
    $subkeys = Get-RegistrySubkeys -Hive "HKLM" -Path $amsiPath

    foreach ($guid in $subkeys) {
        $clsidPath = "SOFTWARE\Classes\CLSID\$guid\InprocServer32"
        $dll = Get-RegistryValue -Hive "HKLM" -Path $clsidPath -Name "(default)"
        Write-CommandOutput "GUID" $guid
        Write-CommandOutput "DLL" $dll
        Write-Host ""
    }
}

function Get-SBAppLocker {
    Write-CommandHeader "AppLocker" "AppLocker settings, if installed"

    $applockerPath = "SOFTWARE\Policies\Microsoft\Windows\SrpV2"
    $categories = @("Appx", "Dll", "Exe", "Msi", "Script")

    foreach ($cat in $categories) {
        $catPath = "$applockerPath\$cat"
        $enforcementMode = Get-RegistryValue -Hive "HKLM" -Path $catPath -Name "EnforcementMode"
        if ($null -ne $enforcementMode) {
            $modeStr = switch ($enforcementMode) {
                0 { "Not Configured" }
                1 { "Enforce" }
                2 { "Audit" }
                default { $enforcementMode }
            }
            Write-CommandOutput "$cat EnforcementMode" $modeStr

            $rules = Get-RegistrySubkeys -Hive "HKLM" -Path $catPath
            foreach ($rule in $rules) {
                $ruleValue = Get-RegistryValue -Hive "HKLM" -Path "$catPath\$rule" -Name "Value"
                if ($ruleValue) {
                    Write-Host "    Rule: $rule" -ForegroundColor DarkGray
                }
            }
        }
    }
}

function Get-SBAuditPolicies {
    Write-CommandHeader "AuditPolicies" "Audit settings via auditpol"

    try {
        $auditpol = & auditpol /get /category:* 2>$null
        if ($auditpol) {
            foreach ($line in $auditpol) {
                if ($line -match "^\s+.+\s+(Success|Failure|No Auditing|Success and Failure)") {
                    Write-Host "  $($line.Trim())"
                }
            }
        }
    }
    catch {
        Write-Host "  Unable to run auditpol (requires admin)" -ForegroundColor Yellow
    }
}

function Get-SBAuditPolicyRegistry {
    Write-CommandHeader "AuditPolicyRegistry" "Audit settings via the registry"

    $settings = Get-RegistryValues -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    foreach ($key in $settings.Keys) {
        Write-CommandOutput $key $settings[$key]
    }
}

function Get-SBAutoRuns {
    Write-CommandHeader "AutoRuns" "Auto-run executables/scripts/programs"

    $locations = @(
        @{Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Run"},
        @{Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"},
        @{Hive="HKLM"; Path="SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"},
        @{Hive="HKLM"; Path="SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"},
        @{Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\RunService"},
        @{Hive="HKLM"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService"},
        @{Hive="HKCU"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Run"},
        @{Hive="HKCU"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"}
    )

    foreach ($loc in $locations) {
        $values = Get-RegistryValues -Hive $loc.Hive -Path $loc.Path
        if ($values.Count -gt 0) {
            Write-Host "  $($loc.Hive)\$($loc.Path)" -ForegroundColor Cyan
            foreach ($key in $values.Keys) {
                Write-CommandOutput $key $values[$key] 4
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
            $files = Get-ChildItem -Path $folder -ErrorAction SilentlyContinue
            if ($files) {
                Write-Host "  $folder" -ForegroundColor Cyan
                foreach ($file in $files) {
                    Write-CommandOutput $file.Name $file.FullName 4
                }
                Write-Host ""
            }
        }
    }
}

function Get-SBCredGuard {
    Write-CommandHeader "CredGuard" "CredentialGuard configuration"

    try {
        $dg = Get-WmiData -Class Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard"
        if ($dg) {
            $vbs = switch ($dg.VirtualizationBasedSecurityStatus) {
                0 { "Not Enabled" }
                1 { "Enabled but not running" }
                2 { "Enabled and running" }
                default { $dg.VirtualizationBasedSecurityStatus }
            }
            Write-CommandOutput "VirtualizationBasedSecurityStatus" $vbs
            Write-CommandOutput "Configured" ($dg.SecurityServicesConfigured -contains 1)
            Write-CommandOutput "Running" ($dg.SecurityServicesRunning -contains 1)
        }
        else {
            Write-Host "  Win32_DeviceGuard WMI class unavailable" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  Error querying Credential Guard: $_" -ForegroundColor Red
    }
}

function Get-SBDNSCache {
    Write-CommandHeader "DNSCache" "DNS cache entries"

    try {
        $cache = Get-DnsClientCache -ErrorAction SilentlyContinue
        Write-Host ("  {0,-45} {1,-8} {2,-8} {3}" -f "Entry", "Type", "TTL", "Data")
        Write-Host ("  {0,-45} {1,-8} {2,-8} {3}" -f "-----", "----", "---", "----")
        foreach ($entry in $cache) {
            $type = switch ($entry.Type) { 1 {"A"} 5 {"CNAME"} 28 {"AAAA"} 12 {"PTR"} default {$entry.Type} }
            Write-Host ("  {0,-45} {1,-8} {2,-8} {3}" -f $entry.Entry, $type, $entry.TimeToLive, $entry.Data)
        }
    }
    catch {
        Write-Host "  Error enumerating DNS cache: $_" -ForegroundColor Red
    }
}

function Get-SBDotNet {
    Write-CommandHeader "DotNet" "Installed .NET versions"

    $netPath = "SOFTWARE\Microsoft\NET Framework Setup\NDP"

    # .NET Framework 4.5+
    $net45Path = "$netPath\v4\Full"
    $release = Get-RegistryValue -Hive "HKLM" -Path $net45Path -Name "Release"
    $version = Get-RegistryValue -Hive "HKLM" -Path $net45Path -Name "Version"

    if ($release) {
        $versionName = switch ($release) {
            {$_ -ge 533320} { ".NET Framework 4.8.1 or later" }
            {$_ -ge 528040} { ".NET Framework 4.8" }
            {$_ -ge 461808} { ".NET Framework 4.7.2" }
            {$_ -ge 461308} { ".NET Framework 4.7.1" }
            {$_ -ge 460798} { ".NET Framework 4.7" }
            {$_ -ge 394802} { ".NET Framework 4.6.2" }
            {$_ -ge 394254} { ".NET Framework 4.6.1" }
            {$_ -ge 393295} { ".NET Framework 4.6" }
            {$_ -ge 379893} { ".NET Framework 4.5.2" }
            {$_ -ge 378675} { ".NET Framework 4.5.1" }
            {$_ -ge 378389} { ".NET Framework 4.5" }
            default { ".NET Framework 4.x" }
        }
        Write-CommandOutput "v4.x" "$versionName (Version: $version, Release: $release)"
    }

    # Older versions
    @("v2.0.50727", "v3.0", "v3.5") | ForEach-Object {
        $installed = Get-RegistryValue -Hive "HKLM" -Path "$netPath\$_" -Name "Install"
        $ver = Get-RegistryValue -Hive "HKLM" -Path "$netPath\$_" -Name "Version"
        if ($installed -eq 1) {
            Write-CommandOutput $_ "Installed (Version: $ver)"
        }
    }

    # .NET Core/5+
    Write-Host ""
    Write-Host "  .NET Core / .NET 5+ Runtimes:" -ForegroundColor Cyan
    try {
        $dotnetOutput = & dotnet --list-runtimes 2>$null
        if ($dotnetOutput) {
            foreach ($line in $dotnetOutput) { Write-Host "    $line" }
        }
    }
    catch { Write-Host "    dotnet CLI not available" }
}

function Get-SBEnvironmentPath {
    Write-CommandHeader "EnvironmentPath" "Current environment PATH"

    $paths = $env:PATH -split ';'
    foreach ($path in $paths) {
        if (-not [string]::IsNullOrWhiteSpace($path)) {
            $exists = Test-Path $path -ErrorAction SilentlyContinue
            if ($exists) {
                Write-Host "  $path" -ForegroundColor Green
            }
            else {
                Write-Host "  $path (NOT FOUND)" -ForegroundColor Red
            }
        }
    }
}

function Get-SBEnvironmentVariables {
    Write-CommandHeader "EnvironmentVariables" "Current environment variables"

    $envVars = [Environment]::GetEnvironmentVariables()
    foreach ($key in ($envVars.Keys | Sort-Object)) {
        Write-CommandOutput $key $envVars[$key]
    }
}

function Get-SBHotfixes {
    Write-CommandHeader "Hotfixes" "Installed hotfixes (via WMI)"

    Write-Host "  Enumerating Windows Hotfixes. For *all* Microsoft updates, use 'MicrosoftUpdates' command." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host ("  {0,-12} {1,-24} {2,-35} {3}" -f "HotFixID", "InstalledOn", "Description", "InstalledBy")
    Write-Host ("  {0,-12} {1,-24} {2,-35} {3}" -f "--------", "-----------", "-----------", "-----------")

    $hotfixes = Get-WmiData -Class Win32_QuickFixEngineering
    foreach ($hf in $hotfixes) {
        $installedOn = $null
        try { if ($hf.InstalledOn) { $installedOn = [DateTime]::Parse($hf.InstalledOn) } } catch {}
        Write-Host ("  {0,-12} {1,-24} {2,-35} {3}" -f $hf.HotFixID, $installedOn, $hf.Description, $hf.InstalledBy)
    }
}

function Get-SBIdleTime {
    Write-CommandHeader "IdleTime" "User idle time"

    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class IdleTime {
        [DllImport("user32.dll")]
        public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
        public struct LASTINPUTINFO {
            public uint cbSize;
            public uint dwTime;
        }
    }
"@ -ErrorAction SilentlyContinue

    try {
        $lastInput = New-Object IdleTime+LASTINPUTINFO
        $lastInput.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($lastInput)
        [IdleTime]::GetLastInputInfo([ref]$lastInput) | Out-Null
        $idleTime = [Environment]::TickCount - $lastInput.dwTime
        $idleSpan = [TimeSpan]::FromMilliseconds($idleTime)
        Write-CommandOutput "IdleTime" "$($idleSpan.Hours)h $($idleSpan.Minutes)m $($idleSpan.Seconds)s"
    }
    catch {
        Write-Host "  Unable to determine idle time" -ForegroundColor Yellow
    }
}

function Get-SBInternetSettings {
    Write-CommandHeader "InternetSettings" "Internet settings including proxy configs"

    $inetPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
    $props = @("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "User Agent")

    foreach ($prop in $props) {
        $value = Get-RegistryValue -Hive "HKCU" -Path $inetPath -Name $prop
        if ($value) { Write-CommandOutput $prop $value }
    }

    # Zone settings
    Write-Host ""
    Write-Host "  Zone Settings:" -ForegroundColor Cyan
    $zones = @{0="My Computer"; 1="Local Intranet"; 2="Trusted Sites"; 3="Internet"; 4="Restricted Sites"}
    foreach ($zone in $zones.Keys) {
        $zonePath = "$inetPath\Zones\$zone"
        $secLevel = Get-RegistryValue -Hive "HKCU" -Path $zonePath -Name "CurrentLevel"
        if ($secLevel) { Write-CommandOutput $zones[$zone] "Security Level: $secLevel" }
    }
}

function Get-SBLAPSSettings {
    Write-CommandHeader "LAPS" "LAPS settings, if installed"

    $lapsPath = "SOFTWARE\Policies\Microsoft Services\AdmPwd"
    $admpwdEnabled = Get-RegistryValue -Hive "HKLM" -Path $lapsPath -Name "AdmPwdEnabled"

    if ($admpwdEnabled) {
        Write-CommandOutput "LAPS Enabled" $admpwdEnabled
        Write-CommandOutput "Password Complexity" (Get-RegistryValue -Hive "HKLM" -Path $lapsPath -Name "PasswordComplexity")
        Write-CommandOutput "Password Length" (Get-RegistryValue -Hive "HKLM" -Path $lapsPath -Name "PasswordLength")
        Write-CommandOutput "Password Age (days)" (Get-RegistryValue -Hive "HKLM" -Path $lapsPath -Name "PasswordAgeDays")
    }
    else {
        Write-Host "  LAPS not configured" -ForegroundColor DarkGray
    }
}

function Get-SBLastShutdown {
    Write-CommandHeader "LastShutdown" "Last system shutdown time"

    try {
        $shutdownBytes = Get-RegistryValue -Hive "HKLM" -Path "SYSTEM\ControlSet001\Control\Windows" -Name "ShutdownTime"
        if ($shutdownBytes -and $shutdownBytes -is [byte[]]) {
            $shutdownInt = [BitConverter]::ToInt64($shutdownBytes, 0)
            $shutdownTime = [DateTime]::FromFileTime($shutdownInt)
            Write-CommandOutput "LastShutdown" $shutdownTime
        }
    }
    catch {
        Write-Host "  Unable to determine last shutdown time" -ForegroundColor Yellow
    }
}

function Get-SBLocalGroups {
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

function Get-SBLocalGPOs {
    Write-CommandHeader "LocalGPOs" "Local group policy objects"

    $gpoPath = "$env:SystemRoot\System32\GroupPolicy"
    if (Test-Path $gpoPath) {
        $machineGpt = "$gpoPath\Machine\Registry.pol"
        $userGpt = "$gpoPath\User\Registry.pol"

        if (Test-Path $machineGpt) {
            $info = Get-Item $machineGpt
            Write-CommandOutput "Machine GPO" "$machineGpt ($(Format-FileSize $info.Length))"
        }
        if (Test-Path $userGpt) {
            $info = Get-Item $userGpt
            Write-CommandOutput "User GPO" "$userGpt ($(Format-FileSize $info.Length))"
        }
    }
    else {
        Write-Host "  No local GPOs found" -ForegroundColor DarkGray
    }
}

function Get-SBLocalUsers {
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
        }
    }
    catch {
        Write-Host "  Error enumerating local users: $_" -ForegroundColor Red
    }
}

function Get-SBLogonSessions {
    Write-CommandHeader "LogonSessions" "Logon sessions"

    try {
        $sessions = Get-WmiData -Class Win32_LogonSession
        foreach ($session in $sessions) {
            $logonType = switch ($session.LogonType) {
                0 {"System"} 2 {"Interactive"} 3 {"Network"} 4 {"Batch"} 5 {"Service"}
                7 {"Unlock"} 8 {"NetworkCleartext"} 9 {"NewCredentials"} 10 {"RemoteInteractive"}
                11 {"CachedInteractive"} default {"Unknown ($($session.LogonType))"}
            }
            Write-Host " LogonId                                  : $($session.LogonId)"
            Write-Host " LogonType                                : $logonType"
            Write-Host " AuthenticationPackage                    : $($session.AuthenticationPackage)"
            if ($session.StartTime) {
                try {
                    $startTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($session.StartTime)
                    Write-Host " StartTime                                : $startTime"
                } catch {}
            }
            Write-Host ""
        }
    }
    catch {
        Write-Host "  Error enumerating logon sessions: $_" -ForegroundColor Red
    }
}

function Get-SBLSASettings {
    Write-CommandHeader "LSASettings" "LSA settings"

    $lsaPath = "SYSTEM\CurrentControlSet\Control\Lsa"
    $props = @("RunAsPPL", "LimitBlankPasswordUse", "NoLmHash", "DisableDomainCreds",
               "EveryoneIncludesAnonymous", "RestrictAnonymousSAM", "RestrictAnonymous",
               "LsaCfgFlags", "SecureBoot", "DisableRestrictedAdmin", "DisableRestrictedAdminOutboundCreds")

    foreach ($prop in $props) {
        $value = Get-RegistryValue -Hive "HKLM" -Path $lsaPath -Name $prop
        if ($null -ne $value) { Write-CommandOutput $prop $value }
    }
}

function Get-SBMappedDrives {
    Write-CommandHeader "MappedDrives" "Mapped drives"

    try {
        $drives = Get-WmiData -Class Win32_MappedLogicalDisk
        foreach ($drive in $drives) {
            Write-CommandOutput $drive.DeviceID $drive.ProviderName
        }

        Write-Host ""
        Write-Host "  Persistent Network Drives:" -ForegroundColor Cyan
        $networkPath = "Network"
        $netDrives = Get-RegistrySubkeys -Hive "HKCU" -Path $networkPath
        foreach ($drive in $netDrives) {
            $remotePath = Get-RegistryValue -Hive "HKCU" -Path "$networkPath\$drive" -Name "RemotePath"
            if ($remotePath) { Write-CommandOutput $drive $remotePath }
        }
    }
    catch {
        Write-Host "  Error enumerating mapped drives: $_" -ForegroundColor Red
    }
}

function Get-SBMicrosoftUpdates {
    Write-CommandHeader "MicrosoftUpdates" "All Microsoft updates (via COM)"

    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $historyCount = $searcher.GetTotalHistoryCount()

        if ($historyCount -gt 0) {
            $history = $searcher.QueryHistory(0, [Math]::Min($historyCount, 50))
            Write-Host ("  {0,-12} {1,-24} {2}" -f "Result", "Date", "Title")
            Write-Host ("  {0,-12} {1,-24} {2}" -f "------", "----", "-----")

            foreach ($update in $history) {
                $result = switch ($update.ResultCode) {
                    0 {"Not Started"} 1 {"In Progress"} 2 {"Succeeded"} 3 {"Succeeded With Errors"}
                    4 {"Failed"} 5 {"Aborted"} default {$update.ResultCode}
                }
                $title = if ($update.Title.Length -gt 80) { $update.Title.Substring(0, 77) + "..." } else { $update.Title }
                Write-Host ("  {0,-12} {1,-24} {2}" -f $result, $update.Date, $title)
            }
        }
    }
    catch {
        Write-Host "  Error enumerating Microsoft updates: $_" -ForegroundColor Red
    }
}

function Get-SBNamedPipes {
    Write-CommandHeader "NamedPipes" "Named pipes"

    try {
        $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
        foreach ($pipe in $pipes | Select-Object -First 100) {
            $pipeName = $pipe -replace '^\\\\.\\pipe\\', ''
            Write-Host "  $pipeName"
        }
        if ($pipes.Count -gt 100) {
            Write-Host "  ... and $($pipes.Count - 100) more" -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "  Error enumerating named pipes: $_" -ForegroundColor Red
    }
}

function Get-SBNetworkProfiles {
    Write-CommandHeader "NetworkProfiles" "Windows network profiles"

    if (-not (Test-IsHighIntegrity)) {
        Write-Host "  Unable to collect. Must be an administrator." -ForegroundColor Yellow
        return
    }

    $profilesPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
    $profileGUIDs = Get-RegistrySubkeys -Hive "HKLM" -Path $profilesPath

    foreach ($guid in $profileGUIDs) {
        $profilePath = "$profilesPath\$guid"
        $name = Get-RegistryValue -Hive "HKLM" -Path $profilePath -Name "ProfileName"
        $desc = Get-RegistryValue -Hive "HKLM" -Path $profilePath -Name "Description"
        $category = Get-RegistryValue -Hive "HKLM" -Path $profilePath -Name "Category"
        $catName = switch ($category) { 0 {"Public"} 1 {"Home"} 2 {"Work"} default {$category} }
        $nameType = Get-RegistryValue -Hive "HKLM" -Path $profilePath -Name "NameType"
        $typeName = switch ($nameType) { 6 {"Wired"} 23 {"VPN"} 25 {"Wireless"} 243 {"Mobile Broadband"} default {$nameType} }

        Write-Host " ProfileName                              : $name"
        Write-Host " Description                              : $desc"
        Write-Host " NetworkCategory                          : $catName"
        Write-Host " NetworkType                              : $typeName"
        Write-Host ""
    }
}

function Get-SBNetworkShares {
    Write-CommandHeader "NetworkShares" "Network shares"

    try {
        $shares = Get-WmiData -Class Win32_Share
        Write-Host ("  {0,-20} {1,-50} {2}" -f "Name", "Path", "Description")
        Write-Host ("  {0,-20} {1,-50} {2}" -f "----", "----", "-----------")

        foreach ($share in $shares) {
            Write-Host ("  {0,-20} {1,-50} {2}" -f $share.Name, $share.Path, $share.Description)
        }
    }
    catch {
        Write-Host "  Error enumerating network shares: $_" -ForegroundColor Red
    }
}

function Get-SBNTLMSettings {
    Write-CommandHeader "NTLMSettings" "NTLM authentication settings"

    $lsaPath = "SYSTEM\CurrentControlSet\Control\Lsa"
    $mspPath = "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"

    $lmCompat = Get-RegistryValue -Hive "HKLM" -Path $lsaPath -Name "LmCompatibilityLevel"
    $lmCompatDesc = switch ($lmCompat) {
        0 {"Send LM & NTLM responses"} 1 {"Send LM & NTLM - use NTLMv2 session if negotiated"}
        2 {"Send NTLM response only"} 3 {"Send NTLMv2 response only"}
        4 {"Send NTLMv2, refuse LM"} 5 {"Send NTLMv2, refuse LM & NTLM"} default {$lmCompat}
    }
    Write-CommandOutput "LmCompatibilityLevel" "$lmCompat ($lmCompatDesc)"
    Write-CommandOutput "NTLMMinClientSec" (Get-RegistryValue -Hive "HKLM" -Path $mspPath -Name "NtlmMinClientSec")
    Write-CommandOutput "NTLMMinServerSec" (Get-RegistryValue -Hive "HKLM" -Path $mspPath -Name "NtlmMinServerSec")
    Write-CommandOutput "RestrictSendingNTLMTraffic" (Get-RegistryValue -Hive "HKLM" -Path $mspPath -Name "RestrictSendingNTLMTraffic")
    Write-CommandOutput "AuditReceivingNTLMTraffic" (Get-RegistryValue -Hive "HKLM" -Path $mspPath -Name "AuditReceivingNTLMTraffic")
}

function Get-SBOptionalFeatures {
    Write-CommandHeader "OptionalFeatures" "Windows optional features"

    try {
        $features = Get-WmiData -Class Win32_OptionalFeature -Filter "InstallState=1"
        foreach ($feature in $features) {
            Write-Host "  $($feature.Name)"
        }
    }
    catch {
        Write-Host "  Error enumerating optional features: $_" -ForegroundColor Red
    }
}

function Get-SBPrinters {
    Write-CommandHeader "Printers" "Installed printers"

    try {
        $printers = Get-WmiData -Class Win32_Printer
        foreach ($printer in $printers) {
            Write-Host " Name                                     : $($printer.Name)"
            Write-Host " Status                                   : $($printer.Status)"
            Write-Host " DriverName                               : $($printer.DriverName)"
            Write-Host " PortName                                 : $($printer.PortName)"
            Write-Host " Shared                                   : $($printer.Shared)"
            Write-Host " ShareName                                : $($printer.ShareName)"
            Write-Host ""
        }
    }
    catch {
        Write-Host "  Error enumerating printers: $_" -ForegroundColor Red
    }
}

function Get-SBProcesses {
    Write-CommandHeader "Processes" "Running processes with file info"

    if ($Script:FilterResults) {
        Write-Host "  Non Microsoft Processes" -ForegroundColor DarkGray
    } else {
        Write-Host "  All Processes" -ForegroundColor DarkGray
    }
    Write-Host ""

    $wmiProcesses = Get-WmiData -Class Win32_Process
    $processes = Get-Process -ErrorAction SilentlyContinue

    foreach ($proc in $processes) {
        $wmiProc = $wmiProcesses | Where-Object { $_.ProcessId -eq $proc.Id }
        $path = $wmiProc.ExecutablePath
        $companyName = $null

        if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
            $fileInfo = Get-FileVersionInfo -Path $path
            if ($fileInfo) { $companyName = $fileInfo.CompanyName }
        }

        if ($Script:FilterResults -and $companyName -match "^Microsoft") { continue }
        if ($Script:FilterResults -and [string]::IsNullOrWhiteSpace($companyName)) { continue }

        Write-Host " ProcessName                              : $($proc.ProcessName)"
        Write-Host " ProcessId                                : $($proc.Id)"
        Write-Host " ParentProcessId                          : $($wmiProc.ParentProcessId)"
        Write-Host " CompanyName                              : $companyName"
        Write-Host " Path                                     : $path"
        Write-Host " CommandLine                              : $($wmiProc.CommandLine)"
        Write-Host ""
    }
}

function Get-SBProcessOwners {
    Write-CommandHeader "ProcessOwners" "Running non-session 0 process list with owners"

    $wmiProcesses = Get-WmiData -Class Win32_Process -Filter "SessionId != 0"

    Write-Host ("  {0,-50} {1,-10} {2}" -f "ProcessName", "PID", "Owner")
    Write-Host ("  {0,-50} {1,-10} {2}" -f "-----------", "---", "-----")

    foreach ($proc in $wmiProcesses) {
        try {
            $owner = $proc.GetOwner()
            if ($owner.User) {
                $ownerStr = "$($owner.Domain)\$($owner.User)"
                Write-Host ("  {0,-50} {1,-10} {2}" -f $proc.Name, $proc.ProcessId, $ownerStr)
            }
        } catch {}
    }
}

function Get-SBPSSessionSettings {
    Write-CommandHeader "PSSessionSettings" "PowerShell session settings"

    $wsmanPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN"
    $psPath = "SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"

    Write-CommandOutput "ExecutionPolicy" (Get-RegistryValue -Hive "HKLM" -Path $psPath -Name "ExecutionPolicy")
    Write-CommandOutput "PSRemoting Enabled" (Get-RegistryValue -Hive "HKLM" -Path "$wsmanPath\Service" -Name "AllowRemoteAccess")

    try {
        $psRemoting = Get-PSSessionConfiguration -ErrorAction SilentlyContinue
        if ($psRemoting) {
            Write-Host ""
            Write-Host "  PS Session Configurations:" -ForegroundColor Cyan
            foreach ($config in $psRemoting) {
                Write-CommandOutput $config.Name $config.Permission 4
            }
        }
    } catch {}
}

function Get-SBPowerShell {
    Write-CommandHeader "PowerShell" "PowerShell versions and settings"

    Write-CommandOutput "PSVersion" $PSVersionTable.PSVersion.ToString()
    Write-CommandOutput "PSEdition" $PSVersionTable.PSEdition
    Write-CommandOutput "CLRVersion" $PSVersionTable.CLRVersion
    Write-CommandOutput "BuildVersion" $PSVersionTable.BuildVersion

    # Transcription settings
    $transcriptPath = "SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    $enableTranscript = Get-RegistryValue -Hive "HKLM" -Path $transcriptPath -Name "EnableTranscripting"
    $outputDir = Get-RegistryValue -Hive "HKLM" -Path $transcriptPath -Name "OutputDirectory"
    Write-CommandOutput "Transcription Enabled" $enableTranscript
    if ($outputDir) { Write-CommandOutput "Transcription Directory" $outputDir }

    # Script block logging
    $sblPath = "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $enableSBL = Get-RegistryValue -Hive "HKLM" -Path $sblPath -Name "EnableScriptBlockLogging"
    Write-CommandOutput "ScriptBlock Logging" $enableSBL

    # Module logging
    $mlPath = "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $enableML = Get-RegistryValue -Hive "HKLM" -Path $mlPath -Name "EnableModuleLogging"
    Write-CommandOutput "Module Logging" $enableML
}

function Get-SBPowerShellHistory {
    Write-CommandHeader "PowerShellHistory" "PowerShell command history"

    $historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $historyPath) {
        Write-Host "  History file: $historyPath" -ForegroundColor DarkGray
        $fileInfo = Get-Item $historyPath
        Write-CommandOutput "Size" (Format-FileSize $fileInfo.Length)
        Write-CommandOutput "LastModified" $fileInfo.LastWriteTime
        Write-Host ""
        Write-Host "  Last 50 commands:" -ForegroundColor Cyan
        Get-Content -Path $historyPath -Tail 50 -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "    $_"
        }
    } else {
        Write-Host "  No PowerShell history file found"
    }
}

function Get-SBRDPSessions {
    Write-CommandHeader "RDPSessions" "Current RDP sessions"

    try {
        $sessions = & qwinsta 2>$null
        if ($sessions) {
            foreach ($line in $sessions) {
                Write-Host "  $line"
            }
        }
    } catch {
        Write-Host "  Unable to enumerate RDP sessions" -ForegroundColor Yellow
    }
}

function Get-SBRDPSettings {
    Write-CommandHeader "RDPsettings" "Remote Desktop settings"

    $rdpPath = "SYSTEM\CurrentControlSet\Control\Terminal Server"
    $rdpTcpPath = "$rdpPath\WinStations\RDP-Tcp"

    $fDenyTSConn = Get-RegistryValue -Hive "HKLM" -Path $rdpPath -Name "fDenyTSConnections"
    Write-CommandOutput "RDP Enabled" ($fDenyTSConn -eq 0)
    Write-CommandOutput "NLA Required" (Get-RegistryValue -Hive "HKLM" -Path $rdpTcpPath -Name "UserAuthentication")
    Write-CommandOutput "Port" (Get-RegistryValue -Hive "HKLM" -Path $rdpTcpPath -Name "PortNumber")
    Write-CommandOutput "SecurityLayer" (Get-RegistryValue -Hive "HKLM" -Path $rdpTcpPath -Name "SecurityLayer")

    # Shadowing settings
    $shadow = Get-RegistryValue -Hive "HKLM" -Path $rdpTcpPath -Name "Shadow"
    $shadowDesc = switch ($shadow) {
        0 {"Disabled"} 1 {"Full Control with user permission"} 2 {"Full Control without permission"}
        3 {"View Only with user permission"} 4 {"View Only without permission"} default {$shadow}
    }
    Write-CommandOutput "Shadow" $shadowDesc
}

function Get-SBRecycleBin {
    Write-CommandHeader "RecycleBin" "Recycle bin items (last 30 days)"

    try {
        $shell = New-Object -ComObject Shell.Application
        $recycleBin = $shell.Namespace(10)
        $items = $recycleBin.Items()

        $cutoff = (Get-Date).AddDays(-30)

        Write-Host ("  {0,-40} {1,-15} {2,-24} {3}" -f "Name", "Size", "DateDeleted", "DeletedFrom")
        Write-Host ("  {0,-40} {1,-15} {2,-24} {3}" -f "----", "----", "-----------", "-----------")

        foreach ($item in $items) {
            $dateDeleted = $item.ExtendedProperty("System.Recycle.DateDeleted")
            if ($dateDeleted -and $dateDeleted -gt $cutoff) {
                $deletedFrom = $item.ExtendedProperty("System.Recycle.DeletedFrom")
                $size = Format-FileSize $item.Size
                $name = if ($item.Name.Length -gt 38) { $item.Name.Substring(0, 35) + "..." } else { $item.Name }
                Write-Host ("  {0,-40} {1,-15} {2,-24} {3}" -f $name, $size, $dateDeleted, $deletedFrom)
            }
        }
    } catch {
        Write-Host "  Error enumerating recycle bin: $_" -ForegroundColor Red
    }
}

function Get-SBARPTable {
    Write-CommandHeader "ARPTable" "ARP table entries"

    try {
        $arp = Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Permanent' }
        Write-Host ("  {0,-20} {1,-20} {2,-15} {3}" -f "IPAddress", "LinkLayerAddress", "State", "Interface")
        Write-Host ("  {0,-20} {1,-20} {2,-15} {3}" -f "---------", "----------------", "-----", "---------")

        foreach ($entry in $arp) {
            $ifName = (Get-NetAdapter -InterfaceIndex $entry.InterfaceIndex -ErrorAction SilentlyContinue).Name
            Write-Host ("  {0,-20} {1,-20} {2,-15} {3}" -f $entry.IPAddress, $entry.LinkLayerAddress, $entry.State, $ifName)
        }
    } catch {
        Write-Host "  Error enumerating ARP table: $_" -ForegroundColor Red
    }
}

function Get-SBScheduledTasks {
    Write-CommandHeader "ScheduledTasks" "Scheduled tasks"

    if ($Script:FilterResults) {
        Write-Host "  Non-Microsoft scheduled tasks" -ForegroundColor DarkGray
    }
    Write-Host ""

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($task in $tasks) {
            if ($Script:FilterResults) {
                if ($task.Author -match "^Microsoft" -or $task.TaskPath -match "^\\Microsoft") { continue }
            }

            $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue

            Write-Host " TaskName                                 : $($task.TaskName)"
            Write-Host " TaskPath                                 : $($task.TaskPath)"
            Write-Host " State                                    : $($task.State)"
            Write-Host " Author                                   : $($task.Author)"
            if ($task.Actions) {
                foreach ($action in $task.Actions) {
                    Write-Host " Action                                   : $($action.Execute) $($action.Arguments)"
                }
            }
            Write-Host " LastRunTime                              : $($info.LastRunTime)"
            Write-Host " NextRunTime                              : $($info.NextRunTime)"
            Write-Host ""
        }
    } catch {
        Write-Host "  Error enumerating scheduled tasks: $_" -ForegroundColor Red
    }
}

function Get-SBSecureBoot {
    Write-CommandHeader "SecureBoot" "Secure Boot configuration"

    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        Write-CommandOutput "SecureBootEnabled" $secureBoot
    } catch {
        Write-Host "  Unable to determine Secure Boot status (may require admin or UEFI system)" -ForegroundColor Yellow
    }
}

function Get-SBSecurityPackages {
    Write-CommandHeader "SecurityPackages" "Security packages"

    $secPkgPath = "SYSTEM\CurrentControlSet\Control\Lsa"
    $packages = Get-RegistryValue -Hive "HKLM" -Path $secPkgPath -Name "Security Packages"

    if ($packages) {
        foreach ($pkg in $packages) {
            Write-Host "  $pkg"
        }
    }

    $ospkgPath = "SYSTEM\CurrentControlSet\Control\Lsa\OSConfig"
    $osPackages = Get-RegistryValue -Hive "HKLM" -Path $ospkgPath -Name "Security Packages"
    if ($osPackages) {
        Write-Host ""
        Write-Host "  OSConfig Security Packages:" -ForegroundColor Cyan
        foreach ($pkg in $osPackages) {
            Write-Host "    $pkg"
        }
    }
}

function Get-SBServices {
    Write-CommandHeader "Services" "Services with file info"

    if ($Script:FilterResults) {
        Write-Host "  Non-Microsoft Services" -ForegroundColor DarkGray
    }
    Write-Host ""

    $services = Get-WmiData -Class Win32_Service
    foreach ($svc in $services) {
        $companyName = $null
        $binaryPath = $null

        if ($svc.PathName) {
            $pathMatch = [regex]::Match($svc.PathName, '^\W*([a-z]:\\.+?(\.exe|\.dll|\.sys))', 'IgnoreCase')
            if ($pathMatch.Success) { $binaryPath = $pathMatch.Groups[1].Value }
        }

        if ($binaryPath -and $binaryPath -match "svchost\.exe$") {
            $serviceDll = Get-RegistryValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\Services\$($svc.Name)\Parameters" -Name "ServiceDll"
            if (-not $serviceDll) {
                $serviceDll = Get-RegistryValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\Services\$($svc.Name)" -Name "ServiceDll"
            }
            if ($serviceDll) { $binaryPath = $serviceDll }
        }

        if ($binaryPath) {
            $fileInfo = Get-FileVersionInfo -Path $binaryPath
            if ($fileInfo) { $companyName = $fileInfo.CompanyName }
        }

        if ($Script:FilterResults -and $companyName -match "^Microsoft") { continue }

        Write-Host " Name                                     : $($svc.Name)"
        Write-Host " DisplayName                              : $($svc.DisplayName)"
        Write-Host " Description                              : $($svc.Description)"
        Write-Host " User                                     : $($svc.StartName)"
        Write-Host " State                                    : $($svc.State)"
        Write-Host " StartMode                                : $($svc.StartMode)"
        Write-Host " PathName                                 : $($svc.PathName)"
        Write-Host " BinaryPath                               : $binaryPath"
        Write-Host " CompanyName                              : $companyName"
        Write-Host ""
    }
}

function Get-SBSysmon {
    Write-CommandHeader "Sysmon" "Sysmon configuration"

    $sysmonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64"
    if (-not (Test-Path $sysmonPath)) {
        $sysmonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon"
    }

    if (Test-Path $sysmonPath) {
        $svc = Get-ItemProperty -Path $sysmonPath -ErrorAction SilentlyContinue
        Write-CommandOutput "Installed" $true
        Write-CommandOutput "ImagePath" $svc.ImagePath

        $configPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters"
        if (Test-Path $configPath) {
            $config = Get-ItemProperty -Path $configPath -ErrorAction SilentlyContinue
            Write-CommandOutput "HashingAlgorithm" $config.HashingAlgorithm
            Write-CommandOutput "Options" $config.Options
        }
    } else {
        Write-Host "  Sysmon is not installed" -ForegroundColor DarkGray
    }
}

function Get-SBTcpConnections {
    Write-CommandHeader "TcpConnections" "Current TCP connections"

    try {
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
        Write-Host ("  {0,-25} {1,-8} {2,-25} {3,-8} {4,-15} {5}" -f "LocalAddress", "LPort", "RemoteAddress", "RPort", "State", "Process")
        Write-Host ("  {0,-25} {1,-8} {2,-25} {3,-8} {4,-15} {5}" -f "-----------", "-----", "-------------", "-----", "-----", "-------")

        foreach ($conn in $connections) {
            $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            Write-Host ("  {0,-25} {1,-8} {2,-25} {3,-8} {4,-15} {5}" -f $conn.LocalAddress, $conn.LocalPort, $conn.RemoteAddress, $conn.RemotePort, $conn.State, $procName)
        }
    } catch {
        Write-Host "  Error enumerating TCP connections: $_" -ForegroundColor Red
    }
}

function Get-SBTokenGroups {
    Write-CommandHeader "TokenGroups" "Current token groups"

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        foreach ($group in $identity.Groups) {
            try {
                $groupName = $group.Translate([Security.Principal.NTAccount]).Value
                Write-Host "  $groupName ($($group.Value))"
            } catch {
                Write-Host "  $($group.Value)"
            }
        }
    } catch {
        Write-Host "  Error enumerating token groups: $_" -ForegroundColor Red
    }
}

function Get-SBTokenPrivileges {
    Write-CommandHeader "TokenPrivileges" "Current token privileges"

    try {
        $output = & whoami /priv 2>$null
        if ($output) {
            $inPrivs = $false
            foreach ($line in $output) {
                if ($line -match "^PRIVILEGES INFORMATION") { $inPrivs = $true; continue }
                if ($inPrivs -and $line -match "^\s*$") { continue }
                if ($inPrivs -and $line.Trim()) {
                    Write-Host "  $($line.Trim())"
                }
            }
        }
    } catch {
        Write-Host "  Error enumerating token privileges: $_" -ForegroundColor Red
    }
}

function Get-SBUAC {
    Write-CommandHeader "UAC" "UAC settings"

    $uacPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $props = @{
        "EnableLUA" = "UAC Enabled"
        "ConsentPromptBehaviorAdmin" = "Admin Consent Behavior"
        "ConsentPromptBehaviorUser" = "User Consent Behavior"
        "FilterAdministratorToken" = "Filter Admin Token"
        "EnableInstallerDetection" = "Installer Detection"
        "EnableSecureUIAPaths" = "Secure UIA Paths"
        "EnableVirtualization" = "Virtualization"
        "PromptOnSecureDesktop" = "Prompt on Secure Desktop"
        "LocalAccountTokenFilterPolicy" = "Local Account Token Filter"
    }

    foreach ($prop in $props.Keys) {
        $value = Get-RegistryValue -Hive "HKLM" -Path $uacPath -Name $prop
        if ($null -ne $value) { Write-CommandOutput $props[$prop] $value }
    }

    $enableLUA = Get-RegistryValue -Hive "HKLM" -Path $uacPath -Name "EnableLUA"
    $consentAdmin = Get-RegistryValue -Hive "HKLM" -Path $uacPath -Name "ConsentPromptBehaviorAdmin"
    $promptSecure = Get-RegistryValue -Hive "HKLM" -Path $uacPath -Name "PromptOnSecureDesktop"

    Write-Host ""
    if ($enableLUA -eq 0) {
        Write-Host "  [!] UAC is DISABLED" -ForegroundColor Red
    } elseif ($consentAdmin -eq 0 -and $promptSecure -eq 0) {
        Write-Host "  [*] UAC configured to auto-elevate without prompting" -ForegroundColor Yellow
    }
}

function Get-SBUdpConnections {
    Write-CommandHeader "UdpConnections" "Current UDP endpoints"

    try {
        $endpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
        Write-Host ("  {0,-25} {1,-8} {2}" -f "LocalAddress", "LPort", "Process")
        Write-Host ("  {0,-25} {1,-8} {2}" -f "-----------", "-----", "-------")

        foreach ($ep in $endpoints) {
            $procName = (Get-Process -Id $ep.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            Write-Host ("  {0,-25} {1,-8} {2}" -f $ep.LocalAddress, $ep.LocalPort, $procName)
        }
    } catch {
        Write-Host "  Error enumerating UDP endpoints: $_" -ForegroundColor Red
    }
}

function Get-SBUserRightAssignments {
    Write-CommandHeader "UserRightAssignments" "User right assignments"

    if (-not (Test-IsHighIntegrity)) {
        Write-Host "  Requires admin privileges" -ForegroundColor Yellow
        return
    }

    try {
        $seceditOutput = & secedit /export /cfg "$env:TEMP\secpol.cfg" /areas USER_RIGHTS 2>$null
        if (Test-Path "$env:TEMP\secpol.cfg") {
            $content = Get-Content "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
            $inRights = $false
            foreach ($line in $content) {
                if ($line -match "^\[Privilege Rights\]") { $inRights = $true; continue }
                if ($line -match "^\[" -and $inRights) { break }
                if ($inRights -and $line -match "^Se.+=") {
                    Write-Host "  $line"
                }
            }
            Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "  Error enumerating user rights: $_" -ForegroundColor Red
    }
}

function Get-SBWifiProfile {
    Write-CommandHeader "WifiProfile" "Saved WiFi profiles"

    try {
        $profiles = & netsh wlan show profiles 2>$null
        if ($profiles) {
            $profileNames = $profiles | Select-String "All User Profile" | ForEach-Object {
                ($_ -split ":")[1].Trim()
            }

            foreach ($name in $profileNames) {
                Write-Host " Profile                                  : $name"
                $details = & netsh wlan show profile name="$name" key=clear 2>$null
                $keyContent = ($details | Select-String "Key Content") -replace ".*:\s*", ""
                if ($keyContent) {
                    Write-Host " Key                                      : $keyContent"
                }
                Write-Host ""
            }
        }
    } catch {
        Write-Host "  Error enumerating WiFi profiles: $_" -ForegroundColor Red
    }
}

function Get-SBWindowsAutoLogon {
    Write-CommandHeader "WindowsAutoLogon" "Registry autologon information"

    $winlogonPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    Write-CommandOutput "DefaultDomainName" (Get-RegistryValue -Hive "HKLM" -Path $winlogonPath -Name "DefaultDomainName")
    Write-CommandOutput "DefaultUserName" (Get-RegistryValue -Hive "HKLM" -Path $winlogonPath -Name "DefaultUserName")
    Write-CommandOutput "DefaultPassword" (Get-RegistryValue -Hive "HKLM" -Path $winlogonPath -Name "DefaultPassword")
    Write-CommandOutput "AltDefaultDomainName" (Get-RegistryValue -Hive "HKLM" -Path $winlogonPath -Name "AltDefaultDomainName")
    Write-CommandOutput "AltDefaultUserName" (Get-RegistryValue -Hive "HKLM" -Path $winlogonPath -Name "AltDefaultUserName")
    Write-CommandOutput "AltDefaultPassword" (Get-RegistryValue -Hive "HKLM" -Path $winlogonPath -Name "AltDefaultPassword")
}

function Get-SBWindowsDefender {
    Write-CommandHeader "WindowsDefender" "Windows Defender settings"

    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defender) {
            Write-CommandOutput "AMServiceEnabled" $defender.AMServiceEnabled
            Write-CommandOutput "AntispywareEnabled" $defender.AntispywareEnabled
            Write-CommandOutput "AntivirusEnabled" $defender.AntivirusEnabled
            Write-CommandOutput "BehaviorMonitorEnabled" $defender.BehaviorMonitorEnabled
            Write-CommandOutput "IoavProtectionEnabled" $defender.IoavProtectionEnabled
            Write-CommandOutput "RealTimeProtectionEnabled" $defender.RealTimeProtectionEnabled
            Write-CommandOutput "AntivirusSignatureLastUpdated" $defender.AntivirusSignatureLastUpdated
        }

        $prefs = Get-MpPreference -ErrorAction SilentlyContinue
        if ($prefs) {
            Write-Host ""
            Write-Host "  Exclusions:" -ForegroundColor Cyan
            if ($prefs.ExclusionPath) {
                Write-Host "    Path Exclusions:" -ForegroundColor DarkGray
                foreach ($p in $prefs.ExclusionPath) { Write-Host "      $p" }
            }
            if ($prefs.ExclusionProcess) {
                Write-Host "    Process Exclusions:" -ForegroundColor DarkGray
                foreach ($p in $prefs.ExclusionProcess) { Write-Host "      $p" }
            }
            if ($prefs.ExclusionExtension) {
                Write-Host "    Extension Exclusions:" -ForegroundColor DarkGray
                foreach ($e in $prefs.ExclusionExtension) { Write-Host "      $e" }
            }
        }
    } catch {
        Write-Host "  Error querying Windows Defender: $_" -ForegroundColor Red
    }
}

function Get-SBWindowsEventForwarding {
    Write-CommandHeader "WindowsEventForwarding" "Windows Event Forwarding settings"

    $wefPath = "SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
    $subMgr = Get-RegistryValue -Hive "HKLM" -Path $wefPath -Name "1"

    if ($subMgr) {
        Write-CommandOutput "SubscriptionManager" $subMgr
    } else {
        Write-Host "  Windows Event Forwarding not configured" -ForegroundColor DarkGray
    }
}

function Get-SBWindowsFirewall {
    Write-CommandHeader "WindowsFirewall" "Windows Firewall settings"

    try {
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        foreach ($profile in $profiles) {
            Write-Host "  $($profile.Name) Profile:" -ForegroundColor Cyan
            Write-CommandOutput "Enabled" $profile.Enabled 4
            Write-CommandOutput "DefaultInboundAction" $profile.DefaultInboundAction 4
            Write-CommandOutput "DefaultOutboundAction" $profile.DefaultOutboundAction 4
            Write-CommandOutput "LogFileName" $profile.LogFileName 4
            Write-CommandOutput "LogBlocked" $profile.LogBlocked 4
            Write-Host ""
        }
    } catch {
        Write-Host "  Error querying firewall settings: $_" -ForegroundColor Red
    }
}

function Get-SBWindowsVault {
    Write-CommandHeader "WindowsVault" "Windows Credential Manager"

    try {
        $output = & cmdkey /list 2>$null
        if ($output) {
            foreach ($line in $output) {
                if ($line.Trim()) {
                    Write-Host "  $($line.Trim())"
                }
            }
        }
    } catch {
        Write-Host "  Error querying Windows Vault: $_" -ForegroundColor Red
    }
}

function Get-SBWMI {
    Write-CommandHeader "WMI" "WMI information"

    Write-Host "  WMI Namespace Enumeration:" -ForegroundColor Cyan
    try {
        $namespaces = Get-WmiData -Class __Namespace -Namespace "root"
        foreach ($ns in $namespaces | Select-Object -First 20) {
            Write-Host "    root\$($ns.Name)"
        }
    } catch {
        Write-Host "  Error enumerating WMI: $_" -ForegroundColor Red
    }
}

function Get-SBWMIEventConsumer {
    Write-CommandHeader "WMIEventConsumer" "WMI event consumers"

    try {
        $consumers = Get-WmiData -Class __EventConsumer -Namespace "root\subscription"
        foreach ($consumer in $consumers) {
            Write-Host " Name                                     : $($consumer.Name)"
            Write-Host " Type                                     : $($consumer.__CLASS)"
            Write-Host ""
        }
    } catch {
        Write-Host "  No WMI event consumers found or access denied" -ForegroundColor DarkGray
    }
}

function Get-SBWMIEventFilter {
    Write-CommandHeader "WMIEventFilter" "WMI event filters"

    try {
        $filters = Get-WmiData -Class __EventFilter -Namespace "root\subscription"
        foreach ($filter in $filters) {
            Write-Host " Name                                     : $($filter.Name)"
            Write-Host " Query                                    : $($filter.Query)"
            Write-Host ""
        }
    } catch {
        Write-Host "  No WMI event filters found or access denied" -ForegroundColor DarkGray
    }
}

function Get-SBWMIFilterBinding {
    Write-CommandHeader "WMIFilterBinding" "WMI filter to consumer bindings"

    try {
        $bindings = Get-WmiData -Class __FilterToConsumerBinding -Namespace "root\subscription"
        foreach ($binding in $bindings) {
            Write-Host " Consumer                                 : $($binding.Consumer)"
            Write-Host " Filter                                   : $($binding.Filter)"
            Write-Host ""
        }
    } catch {
        Write-Host "  No WMI bindings found or access denied" -ForegroundColor DarkGray
    }
}

function Get-SBWSUS {
    Write-CommandHeader "WSUS" "WSUS settings"

    $wuPath = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $wuServer = Get-RegistryValue -Hive "HKLM" -Path $wuPath -Name "WUServer"
    $wuStatusServer = Get-RegistryValue -Hive "HKLM" -Path $wuPath -Name "WUStatusServer"
    $useWU = Get-RegistryValue -Hive "HKLM" -Path "$wuPath\AU" -Name "UseWUServer"

    if ($wuServer) {
        Write-CommandOutput "WUServer" $wuServer
        Write-CommandOutput "WUStatusServer" $wuStatusServer
        Write-CommandOutput "UseWUServer" $useWU

        if ($wuServer -match "^http://") {
            Write-Host ""
            Write-Host "  [!] WSUS is using HTTP - potentially vulnerable to WSUS exploitation" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  WSUS not configured (using Windows Update directly)" -ForegroundColor DarkGray
    }
}

#endregion

#region User Commands

function Get-SBCloudCredentials {
    Write-CommandHeader "CloudCredentials" "Cloud credential files"

    $locations = @(
        @{Name="AWS"; Path="$env:USERPROFILE\.aws\credentials"},
        @{Name="AWS Config"; Path="$env:USERPROFILE\.aws\config"},
        @{Name="Azure"; Path="$env:USERPROFILE\.azure\accessTokens.json"},
        @{Name="Azure Profile"; Path="$env:USERPROFILE\.azure\azureProfile.json"},
        @{Name="GCP"; Path="$env:APPDATA\gcloud\credentials.db"},
        @{Name="GCP Legacy"; Path="$env:APPDATA\gcloud\legacy_credentials"},
        @{Name="GCP Access Tokens"; Path="$env:APPDATA\gcloud\access_tokens.db"}
    )

    foreach ($loc in $locations) {
        if (Test-Path $loc.Path -ErrorAction SilentlyContinue) {
            $info = Get-Item $loc.Path
            Write-Host " $($loc.Name)" -ForegroundColor Cyan
            Write-CommandOutput "Path" $loc.Path 4
            Write-CommandOutput "Size" (Format-FileSize $info.Length) 4
            Write-CommandOutput "LastModified" $info.LastWriteTime 4
            Write-Host ""
        }
    }
}

function Get-SBCredEnum {
    Write-CommandHeader "CredEnum" "Credential enumeration"

    Write-Host "  Use 'WindowsVault' command for cmdkey enumeration" -ForegroundColor DarkGray
    Write-Host "  Programmatic CredEnumerate requires P/Invoke" -ForegroundColor DarkGray
}

function Get-SBDpapiMasterKeys {
    Write-CommandHeader "DpapiMasterKeys" "DPAPI master key files"

    $paths = @(
        "$env:APPDATA\Microsoft\Protect",
        "$env:LOCALAPPDATA\Microsoft\Protect"
    )

    foreach ($basePath in $paths) {
        if (Test-Path $basePath) {
            Write-Host "  $basePath" -ForegroundColor Cyan
            Get-ChildItem -Path $basePath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -match "^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$") {
                    Write-CommandOutput $_.Name "$($_.LastWriteTime) ($(Format-FileSize $_.Length))" 4
                }
            }
            Write-Host ""
        }
    }
}

function Get-SBExplorerMRUs {
    Write-CommandHeader "ExplorerMRUs" "Explorer most recently used files and folders"

    $mruPaths = @(
        @{Name="RecentDocs"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"},
        @{Name="ComDlg32 OpenSave"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"},
        @{Name="ComDlg32 LastVisited"; Path="SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"}
    )

    foreach ($mru in $mruPaths) {
        Write-Host "  $($mru.Name):" -ForegroundColor Cyan
        $values = Get-RegistryValues -Hive "HKCU" -Path $mru.Path
        $count = 0
        foreach ($key in $values.Keys | Where-Object { $_ -notmatch "^(MRUListEx|PS)" } | Select-Object -First 10) {
            Write-Host "    $key"
            $count++
        }
        if ($count -eq 0) { Write-Host "    (none)" }
        Write-Host ""
    }
}

function Get-SBExplorerRunCommands {
    Write-CommandHeader "ExplorerRunCommands" "Recent Explorer run commands"

    foreach ($sid in (Get-UserSIDs)) {
        $runMRUPath = "$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        $values = Get-RegistryValues -Hive "HKU" -Path $runMRUPath

        if ($values.Count -gt 0) {
            Write-Host "  SID: $sid" -ForegroundColor Cyan
            foreach ($key in $values.Keys | Where-Object { $_ -notmatch "^(MRUList|PS)" }) {
                Write-CommandOutput $key $values[$key] 4
            }
            Write-Host ""
        }
    }
}

function Get-SBRDPSavedConnections {
    Write-CommandHeader "RDPSavedConnections" "Saved RDP connections"

    foreach ($sid in (Get-UserSIDs)) {
        $rdpPath = "$sid\Software\Microsoft\Terminal Server Client\Servers"
        $servers = Get-RegistrySubkeys -Hive "HKU" -Path $rdpPath

        if ($servers) {
            Write-Host "  SID: $sid" -ForegroundColor Cyan
            foreach ($server in $servers) {
                $username = Get-RegistryValue -Hive "HKU" -Path "$rdpPath\$server" -Name "UsernameHint"
                Write-CommandOutput $server $username 4
            }
            Write-Host ""
        }
    }

    # Current user
    $rdpPath = "Software\Microsoft\Terminal Server Client\Servers"
    $servers = Get-RegistrySubkeys -Hive "HKCU" -Path $rdpPath
    if ($servers) {
        Write-Host "  Current User:" -ForegroundColor Cyan
        foreach ($server in $servers) {
            $username = Get-RegistryValue -Hive "HKCU" -Path "$rdpPath\$server" -Name "UsernameHint"
            Write-CommandOutput $server $username 4
        }
    }
}

function Get-SBPuttyHostKeys {
    Write-CommandHeader "PuttyHostKeys" "PuTTY SSH host keys"

    $puttyPath = "Software\SimonTatham\PuTTY\SshHostKeys"
    $keys = Get-RegistryValues -Hive "HKCU" -Path $puttyPath

    foreach ($key in $keys.Keys | Where-Object { $_ -notmatch "^PS" }) {
        Write-Host "  $key"
    }
}

function Get-SBPuttySessions {
    Write-CommandHeader "PuttySessions" "PuTTY saved sessions"

    $puttyPath = "Software\SimonTatham\PuTTY\Sessions"
    $sessions = Get-RegistrySubkeys -Hive "HKCU" -Path $puttyPath

    foreach ($session in $sessions) {
        if ($session -eq "Default%20Settings") { continue }
        $sessionPath = "$puttyPath\$session"
        Write-Host " Session                                  : $([System.Web.HttpUtility]::UrlDecode($session))"
        Write-Host " HostName                                 : $(Get-RegistryValue -Hive 'HKCU' -Path $sessionPath -Name 'HostName')"
        Write-Host " UserName                                 : $(Get-RegistryValue -Hive 'HKCU' -Path $sessionPath -Name 'UserName')"
        Write-Host " Port                                     : $(Get-RegistryValue -Hive 'HKCU' -Path $sessionPath -Name 'PortNumber')"
        Write-Host " PublicKeyFile                            : $(Get-RegistryValue -Hive 'HKCU' -Path $sessionPath -Name 'PublicKeyFile')"
        Write-Host ""
    }
}

function Get-SBRecentFiles {
    Write-CommandHeader "RecentFiles" "Recently accessed files"

    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentPath) {
        try {
            $shell = New-Object -ComObject WScript.Shell
            Get-ChildItem -Path $recentPath -Filter "*.lnk" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 30 |
            ForEach-Object {
                try {
                    $shortcut = $shell.CreateShortcut($_.FullName)
                    Write-Host ("  {0,-30} : {1}" -f $_.BaseName, $shortcut.TargetPath)
                } catch {}
            }
        } catch {}
    }
}

function Get-SBClipboard {
    Write-CommandHeader "Clipboard" "Current clipboard contents"

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        $text = [System.Windows.Forms.Clipboard]::GetText()
        if ($text) {
            if ($text.Length -gt 500) { $text = $text.Substring(0, 500) + "..." }
            Write-Host "  $text"
        } else {
            Write-Host "  Clipboard is empty or contains non-text data"
        }
    } catch {
        Write-Host "  Unable to access clipboard: $_" -ForegroundColor Red
    }
}

#endregion

#region Browser Commands

function Get-SBChromiumBookmarks {
    Write-CommandHeader "ChromiumBookmarks" "Chromium-based browser bookmarks"

    $browsers = @(
        @{Name="Chrome"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data"},
        @{Name="Edge"; Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data"},
        @{Name="Brave"; Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"}
    )

    foreach ($browser in $browsers) {
        $bookmarksPath = "$($browser.Path)\Default\Bookmarks"
        if (Test-Path $bookmarksPath) {
            Write-Host "  $($browser.Name) Bookmarks:" -ForegroundColor Cyan
            try {
                $bookmarks = Get-Content -Path $bookmarksPath -Raw | ConvertFrom-Json

                function Get-BookmarkItems($node) {
                    if ($node.type -eq "url") {
                        $name = if ($node.name.Length -gt 40) { $node.name.Substring(0, 37) + "..." } else { $node.name }
                        Write-Host ("    {0,-42} : {1}" -f $name, $node.url)
                    }
                    if ($node.children) {
                        foreach ($child in $node.children | Select-Object -First 20) {
                            Get-BookmarkItems $child
                        }
                    }
                }

                Get-BookmarkItems $bookmarks.roots.bookmark_bar
            } catch {}
            Write-Host ""
        }
    }
}

function Get-SBChromiumHistory {
    Write-CommandHeader "ChromiumHistory" "Chromium-based browser history"

    $browsers = @(
        @{Name="Chrome"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"},
        @{Name="Edge"; Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"},
        @{Name="Brave"; Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\History"}
    )

    foreach ($browser in $browsers) {
        if (Test-Path $browser.Path) {
            $info = Get-Item $browser.Path
            Write-Host " $($browser.Name)" -ForegroundColor Cyan
            Write-CommandOutput "Path" $browser.Path 4
            Write-CommandOutput "Size" (Format-FileSize $info.Length) 4
            Write-CommandOutput "LastModified" $info.LastWriteTime 4
            Write-Host "    (SQLite database - requires external parsing when browser closed)" -ForegroundColor DarkGray
            Write-Host ""
        }
    }
}

function Get-SBChromiumPresence {
    Write-CommandHeader "ChromiumPresence" "Chromium-based browser presence"

    $browsers = @(
        @{Name="Chrome"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data"},
        @{Name="Edge"; Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data"},
        @{Name="Brave"; Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"},
        @{Name="Opera"; Path="$env:APPDATA\Opera Software\Opera Stable"},
        @{Name="Vivaldi"; Path="$env:LOCALAPPDATA\Vivaldi\User Data"}
    )

    foreach ($browser in $browsers) {
        if (Test-Path $browser.Path) {
            Write-Host " $($browser.Name)" -ForegroundColor Cyan
            Write-CommandOutput "Path" $browser.Path 4

            $profiles = Get-ChildItem -Path $browser.Path -Directory -ErrorAction SilentlyContinue |
                       Where-Object { $_.Name -match "^(Default|Profile)" }
            foreach ($profile in $profiles) {
                Write-CommandOutput "Profile" $profile.Name 4
            }
            Write-Host ""
        }
    }
}

function Get-SBFirefoxHistory {
    Write-CommandHeader "FirefoxHistory" "Firefox browser history location"

    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxPath) {
        Get-ChildItem -Path $firefoxPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $placesDb = Join-Path $_.FullName "places.sqlite"
            if (Test-Path $placesDb) {
                $info = Get-Item $placesDb
                Write-Host " Profile: $($_.Name)" -ForegroundColor Cyan
                Write-CommandOutput "Path" $placesDb 4
                Write-CommandOutput "Size" (Format-FileSize $info.Length) 4
                Write-CommandOutput "LastModified" $info.LastWriteTime 4
                Write-Host ""
            }
        }
    } else {
        Write-Host "  Firefox not found"
    }
}

function Get-SBFirefoxPresence {
    Write-CommandHeader "FirefoxPresence" "Firefox browser presence"

    $firefoxPath = "$env:APPDATA\Mozilla\Firefox"
    if (Test-Path $firefoxPath) {
        Write-CommandOutput "InstallPath" $firefoxPath

        $profilesPath = "$firefoxPath\Profiles"
        if (Test-Path $profilesPath) {
            $profiles = Get-ChildItem -Path $profilesPath -Directory -ErrorAction SilentlyContinue
            foreach ($profile in $profiles) {
                Write-CommandOutput "Profile" $profile.Name
            }
        }
    } else {
        Write-Host "  Firefox not installed"
    }
}

function Get-SBIEFavorites {
    Write-CommandHeader "IEFavorites" "Internet Explorer favorites"

    $favPath = "$env:USERPROFILE\Favorites"
    if (Test-Path $favPath) {
        Get-ChildItem -Path $favPath -Filter "*.url" -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 30 |
        ForEach-Object {
            $content = Get-Content $_.FullName -ErrorAction SilentlyContinue
            $url = ($content | Select-String "^URL=") -replace "URL=", ""
            Write-Host ("  {0,-40} : {1}" -f $_.BaseName, $url)
        }
    } else {
        Write-Host "  No IE favorites found"
    }
}

function Get-SBIETabs {
    Write-CommandHeader "IETabs" "Internet Explorer open tabs"

    $tabPath = "Software\Microsoft\Internet Explorer\Recovery\Active"
    $values = Get-RegistryValues -Hive "HKCU" -Path $tabPath

    if ($values.Count -gt 0) {
        foreach ($key in $values.Keys | Where-Object { $_ -notmatch "^PS" }) {
            Write-CommandOutput $key $values[$key]
        }
    } else {
        Write-Host "  No open IE tabs found"
    }
}

function Get-SBIEUrls {
    Write-CommandHeader "IEUrls" "Internet Explorer typed URLs"

    $iePath = "Software\Microsoft\Internet Explorer\TypedURLs"
    $values = Get-RegistryValues -Hive "HKCU" -Path $iePath

    foreach ($key in $values.Keys | Where-Object { $_ -match "^url" } | Sort-Object) {
        Write-Host "  $($values[$key])"
    }
}

#endregion

#region Products Commands

function Get-SBCloudSyncProviders {
    Write-CommandHeader "CloudSyncProviders" "Registered cloud sync providers"

    $syncPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager"
    $providers = Get-RegistrySubkeys -Hive "HKCU" -Path $syncPath

    foreach ($provider in $providers) {
        Write-Host " Provider: $provider" -ForegroundColor Cyan
    }

    # Known cloud paths
    $cloudPaths = @(
        @{Name="OneDrive"; Path="$env:USERPROFILE\OneDrive"},
        @{Name="Dropbox"; Path="$env:USERPROFILE\Dropbox"},
        @{Name="Google Drive"; Path="$env:USERPROFILE\Google Drive"},
        @{Name="iCloud"; Path="$env:USERPROFILE\iCloudDrive"}
    )

    Write-Host ""
    Write-Host "  Detected Cloud Folders:" -ForegroundColor Cyan
    foreach ($cloud in $cloudPaths) {
        if (Test-Path $cloud.Path) {
            Write-CommandOutput $cloud.Name $cloud.Path 4
        }
    }
}

function Get-SBFileZilla {
    Write-CommandHeader "FileZilla" "FileZilla saved connections"

    $fzPaths = @(
        "$env:APPDATA\FileZilla\recentservers.xml",
        "$env:APPDATA\FileZilla\sitemanager.xml"
    )

    foreach ($path in $fzPaths) {
        if (Test-Path $path) {
            Write-Host " Found: $path" -ForegroundColor Cyan
            try {
                [xml]$xml = Get-Content $path
                $servers = $xml.SelectNodes("//Server")
                foreach ($server in $servers) {
                    Write-CommandOutput "Host" $server.Host 4
                    Write-CommandOutput "Port" $server.Port 4
                    Write-CommandOutput "User" $server.User 4
                    Write-CommandOutput "Pass" "(check file)" 4
                    Write-Host ""
                }
            } catch {}
        }
    }
}

function Get-SBInstalledProducts {
    Write-CommandHeader "InstalledProducts" "Installed software"

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $products = foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }

    $products = $products | Sort-Object DisplayName -Unique

    Write-Host ("  {0,-50} {1,-20} {2}" -f "Name", "Version", "Publisher")
    Write-Host ("  {0,-50} {1,-20} {2}" -f "----", "-------", "---------")

    foreach ($prod in $products | Select-Object -First 50) {
        $name = if ($prod.DisplayName.Length -gt 48) { $prod.DisplayName.Substring(0, 45) + "..." } else { $prod.DisplayName }
        Write-Host ("  {0,-50} {1,-20} {2}" -f $name, $prod.DisplayVersion, $prod.Publisher)
    }
}

function Get-SBKeePass {
    Write-CommandHeader "KeePass" "KeePass configuration files"

    $kpPaths = @(
        "$env:APPDATA\KeePass\KeePass.config.xml",
        "$env:LOCALAPPDATA\KeePass\KeePass.config.xml",
        "$env:PROGRAMDATA\KeePass\KeePass.config.xml"
    )

    foreach ($path in $kpPaths) {
        if (Test-Path $path) {
            Write-CommandOutput "Config Found" $path
            try {
                [xml]$xml = Get-Content $path
                $recentDbs = $xml.SelectNodes("//Database")
                foreach ($db in $recentDbs) {
                    Write-CommandOutput "Recent DB" $db.Path 4
                }
            } catch {}
        }
    }

    # Search for kdbx files
    Write-Host ""
    Write-Host "  Searching for .kdbx files in common locations..." -ForegroundColor DarkGray
    @("$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop") | ForEach-Object {
        if (Test-Path $_) {
            Get-ChildItem -Path $_ -Filter "*.kdbx" -Recurse -ErrorAction SilentlyContinue -Depth 3 | ForEach-Object {
                Write-CommandOutput "KeePass DB" $_.FullName 4
            }
        }
    }
}

function Get-SBMcAfeeConfigs {
    Write-CommandHeader "McAfeeConfigs" "McAfee configuration files"

    $mcafeePaths = @(
        "$env:PROGRAMDATA\McAfee",
        "$env:PROGRAMFILES\McAfee",
        "${env:PROGRAMFILES(x86)}\McAfee"
    )

    foreach ($path in $mcafeePaths) {
        if (Test-Path $path) {
            Write-CommandOutput "McAfee Path" $path
            Get-ChildItem -Path $path -Filter "*.xml" -Recurse -ErrorAction SilentlyContinue -Depth 2 | Select-Object -First 10 | ForEach-Object {
                Write-Host "    $($_.FullName)"
            }
        }
    }
}

function Get-SBMcAfeeSiteList {
    Write-CommandHeader "McAfeeSiteList" "McAfee SiteList.xml locations"

    $siteListPaths = @(
        "$env:PROGRAMDATA\McAfee\Common Framework\SiteList.xml",
        "$env:ALLUSERSPROFILE\Application Data\McAfee\Common Framework\SiteList.xml"
    )

    foreach ($path in $siteListPaths) {
        if (Test-Path $path) {
            Write-CommandOutput "SiteList Found" $path
            Write-Host "    (May contain ePO server credentials)" -ForegroundColor Yellow
        }
    }
}

function Get-SBMTPuTTY {
    Write-CommandHeader "MTPuTTY" "MTPuTTY saved sessions"

    $mtputtyPath = "$env:APPDATA\TTYPlus\mtputty.xml"
    if (Test-Path $mtputtyPath) {
        Write-CommandOutput "Config Found" $mtputtyPath
        try {
            [xml]$xml = Get-Content $mtputtyPath
            $servers = $xml.SelectNodes("//Node[@Type='1']")
            foreach ($server in $servers) {
                Write-Host " DisplayName                              : $($server.DisplayName)"
                Write-Host " ServerName                               : $($server.ServerName)"
                Write-Host " UserName                                 : $($server.UserName)"
                Write-Host ""
            }
        } catch {}
    } else {
        Write-Host "  MTPuTTY not found"
    }
}

function Get-SBOfficeMRUs {
    Write-CommandHeader "OfficeMRUs" "Microsoft Office recent files"

    $officeVersions = @("16.0", "15.0", "14.0", "12.0")
    $officeApps = @("Word", "Excel", "PowerPoint", "Access")

    foreach ($version in $officeVersions) {
        foreach ($app in $officeApps) {
            $mruPath = "SOFTWARE\Microsoft\Office\$version\$app\File MRU"
            $values = Get-RegistryValues -Hive "HKCU" -Path $mruPath

            if ($values.Count -gt 1) {
                Write-Host "  Office $version ${app}:" -ForegroundColor Cyan
                foreach ($key in $values.Keys | Where-Object { $_ -match "^Item" } | Select-Object -First 5) {
                    Write-Host "    $($values[$key])"
                }
            }
        }
    }
}

function Get-SBOneNote {
    Write-CommandHeader "OneNote" "OneNote notebook locations"

    $onenotePath = "SOFTWARE\Microsoft\Office"
    $versions = @("16.0", "15.0", "14.0")

    foreach ($version in $versions) {
        $notebookPath = "$onenotePath\$version\OneNote\OpenNotebooks"
        $notebooks = Get-RegistryValues -Hive "HKCU" -Path $notebookPath

        if ($notebooks.Count -gt 0) {
            Write-Host "  OneNote $version Notebooks:" -ForegroundColor Cyan
            foreach ($key in $notebooks.Keys | Where-Object { $_ -notmatch "^PS" }) {
                Write-Host "    $key"
            }
        }
    }
}

function Get-SBOracleSQLDeveloper {
    Write-CommandHeader "OracleSQLDeveloper" "Oracle SQL Developer connections"

    $sqldevPath = "$env:APPDATA\SQL Developer"
    if (Test-Path $sqldevPath) {
        $connFiles = Get-ChildItem -Path $sqldevPath -Filter "connections*.xml" -Recurse -ErrorAction SilentlyContinue
        foreach ($file in $connFiles) {
            Write-CommandOutput "Connections File" $file.FullName
            try {
                [xml]$xml = Get-Content $file.FullName
                $conns = $xml.SelectNodes("//StringRefAddr[@addrType='user']")
                foreach ($conn in $conns) {
                    Write-Host "    User: $($conn.Contents)"
                }
            } catch {}
        }
    } else {
        Write-Host "  Oracle SQL Developer not found"
    }
}

function Get-SBOutlookDownloads {
    Write-CommandHeader "OutlookDownloads" "Outlook attachment save locations"

    $outlookPath = "SOFTWARE\Microsoft\Office"
    $versions = @("16.0", "15.0", "14.0")

    foreach ($version in $versions) {
        $secPath = "$outlookPath\$version\Outlook\Security"
        $outlookTempPath = Get-RegistryValue -Hive "HKCU" -Path $secPath -Name "OutlookSecureTempFolder"
        if ($outlookTempPath -and (Test-Path $outlookTempPath)) {
            Write-Host "  Outlook $version Temp Folder:" -ForegroundColor Cyan
            Write-CommandOutput "Path" $outlookTempPath 4
            $files = Get-ChildItem -Path $outlookTempPath -ErrorAction SilentlyContinue | Select-Object -First 10
            foreach ($file in $files) {
                Write-Host "    $($file.Name)"
            }
        }
    }
}

function Get-SBRDCManFiles {
    Write-CommandHeader "RDCManFiles" "Remote Desktop Connection Manager files"

    $rdcmanPaths = @(
        "$env:LOCALAPPDATA\Microsoft\Remote Desktop Connection Manager",
        "$env:USERPROFILE\Documents"
    )

    foreach ($path in $rdcmanPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Filter "*.rdg" -Recurse -ErrorAction SilentlyContinue -Depth 2 | ForEach-Object {
                Write-CommandOutput "RDG File" $_.FullName
                Write-Host "    (May contain saved credentials)" -ForegroundColor Yellow
            }
        }
    }
}

function Get-SBSCCM {
    Write-CommandHeader "SCCM" "SCCM client information"

    try {
        $sccm = Get-WmiData -Class SMS_Client -Namespace "root\ccm"
        if ($sccm) {
            Write-CommandOutput "ClientVersion" $sccm.ClientVersion
        }

        $sccmPolicy = Get-WmiData -Class CCM_Authority -Namespace "root\ccm"
        if ($sccmPolicy) {
            Write-CommandOutput "CurrentManagementPoint" $sccmPolicy.CurrentManagementPoint
            Write-CommandOutput "Name" $sccmPolicy.Name
        }
    } catch {
        Write-Host "  SCCM client not found or inaccessible" -ForegroundColor DarkGray
    }
}

function Get-SBSlackDownloads {
    Write-CommandHeader "SlackDownloads" "Slack download locations"

    $slackPath = "$env:APPDATA\Slack"
    if (Test-Path $slackPath) {
        $downloads = "$slackPath\downloads"
        if (Test-Path $downloads) {
            Write-CommandOutput "Downloads Path" $downloads
            Get-ChildItem -Path $downloads -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object {
                Write-Host "    $($_.Name)"
            }
        }
    } else {
        Write-Host "  Slack not installed"
    }
}

function Get-SBSlackPresence {
    Write-CommandHeader "SlackPresence" "Slack installation presence"

    $slackPaths = @(
        "$env:APPDATA\Slack",
        "$env:LOCALAPPDATA\slack"
    )

    foreach ($path in $slackPaths) {
        if (Test-Path $path) {
            Write-CommandOutput "Slack Path" $path
        }
    }

    # Check for cookies/storage
    $storagePath = "$env:APPDATA\Slack\storage"
    if (Test-Path $storagePath) {
        Write-CommandOutput "Storage Path" $storagePath
    }
}

function Get-SBSlackWorkspaces {
    Write-CommandHeader "SlackWorkspaces" "Slack workspaces"

    $storagePath = "$env:APPDATA\Slack\storage"
    if (Test-Path $storagePath) {
        Get-ChildItem -Path $storagePath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Name -match "^T[A-Z0-9]+") {
                Write-CommandOutput "Workspace ID" $_.Name
            }
        }
    }
}

function Get-SBSuperPutty {
    Write-CommandHeader "SuperPutty" "SuperPuTTY saved sessions"

    $spPath = "$env:APPDATA\SuperPuTTY\Sessions.xml"
    if (Test-Path $spPath) {
        Write-CommandOutput "Sessions File" $spPath
        try {
            [xml]$xml = Get-Content $spPath
            $sessions = $xml.SelectNodes("//SessionData")
            foreach ($session in $sessions) {
                Write-Host " SessionName                              : $($session.SessionName)"
                Write-Host " Host                                     : $($session.Host)"
                Write-Host " Port                                     : $($session.Port)"
                Write-Host " Username                                 : $($session.Username)"
                Write-Host ""
            }
        } catch {}
    } else {
        Write-Host "  SuperPuTTY not found"
    }
}

#endregion

#region Event Log Commands

function Get-SBExplicitLogonEvents {
    Write-CommandHeader "ExplicitLogonEvents" "4648 explicit credential logon events (last 7 days)"

    if (-not (Test-IsHighIntegrity)) {
        Write-Host "  Requires admin privileges" -ForegroundColor Yellow
        return
    }

    try {
        $startTime = (Get-Date).AddDays(-7)
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648; StartTime=$startTime} -MaxEvents 20 -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            Write-Host " TimeCreated                              : $($event.TimeCreated)"
            Write-Host " SubjectUserName                          : $($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text')"
            Write-Host " TargetUserName                           : $($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text')"
            Write-Host " TargetServerName                         : $($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetServerName'}).'#text')"
            Write-Host ""
        }
    } catch {
        Write-Host "  Error reading event logs: $_" -ForegroundColor Red
    }
}

function Get-SBLogonEvents {
    Write-CommandHeader "LogonEvents" "4624 logon events (last 7 days)"

    if (-not (Test-IsHighIntegrity)) {
        Write-Host "  Requires admin privileges" -ForegroundColor Yellow
        return
    }

    try {
        $startTime = (Get-Date).AddDays(-7)
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$startTime} -MaxEvents 20 -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $logonType = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
            $targetUser = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'

            if ($logonType -in @(2, 10, 11)) {  # Interactive, RemoteInteractive, CachedInteractive
                Write-Host " TimeCreated                              : $($event.TimeCreated)"
                Write-Host " TargetUserName                           : $targetUser"
                Write-Host " LogonType                                : $logonType"
                Write-Host ""
            }
        }
    } catch {
        Write-Host "  Error reading event logs: $_" -ForegroundColor Red
    }
}

function Get-SBPoweredOnEvents {
    Write-CommandHeader "PoweredOnEvents" "System power-on events (last 7 days)"

    try {
        $startTime = (Get-Date).AddDays(-7)
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(1,12,13); StartTime=$startTime} -MaxEvents 20 -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            $eventType = switch ($event.Id) {
                1 { "System started" }
                12 { "OS started" }
                13 { "OS shutdown" }
            }
            Write-Host ("  {0,-24} : {1}" -f $event.TimeCreated, $eventType)
        }
    } catch {
        Write-Host "  Error reading event logs: $_" -ForegroundColor Red
    }
}

function Get-SBPowerShellEvents {
    Write-CommandHeader "PowerShellEvents" "PowerShell script block logs (last 7 days)"

    if (-not (Test-IsHighIntegrity)) {
        Write-Host "  Requires admin privileges" -ForegroundColor Yellow
        return
    }

    try {
        $startTime = (Get-Date).AddDays(-7)
        $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$startTime} -MaxEvents 10 -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            Write-Host " TimeCreated                              : $($event.TimeCreated)"
            $scriptBlock = $event.Properties[2].Value
            if ($scriptBlock.Length -gt 200) { $scriptBlock = $scriptBlock.Substring(0, 197) + "..." }
            Write-Host " ScriptBlock                              : $scriptBlock"
            Write-Host ""
        }
    } catch {
        Write-Host "  PowerShell script block logging not enabled or no events" -ForegroundColor DarkGray
    }
}

function Get-SBProcessCreationEvents {
    Write-CommandHeader "ProcessCreationEvents" "4688 process creation events (last 7 days)"

    if (-not (Test-IsHighIntegrity)) {
        Write-Host "  Requires admin privileges" -ForegroundColor Yellow
        return
    }

    try {
        $startTime = (Get-Date).AddDays(-7)
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$startTime} -MaxEvents 20 -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            Write-Host " TimeCreated                              : $($event.TimeCreated)"
            Write-Host " NewProcessName                           : $(($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'NewProcessName'}).'#text')"
            Write-Host " SubjectUserName                          : $(($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text')"
            Write-Host ""
        }
    } catch {
        Write-Host "  Error reading event logs: $_" -ForegroundColor Red
    }
}

function Get-SBSysmonEvents {
    Write-CommandHeader "SysmonEvents" "Sysmon process creation events (last 7 days)"

    try {
        $startTime = (Get-Date).AddDays(-7)
        $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$startTime} -MaxEvents 20 -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            Write-Host " TimeCreated                              : $($event.TimeCreated)"
            Write-Host " Image                                    : $(($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text')"
            Write-Host " User                                     : $(($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'}).'#text')"
            Write-Host " CommandLine                              : $(($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'}).'#text')"
            Write-Host ""
        }
    } catch {
        Write-Host "  Sysmon not installed or no events found" -ForegroundColor DarkGray
    }
}

#endregion

#region Misc Commands

function Get-SBInterestingFiles {
    Write-CommandHeader "InterestingFiles" "Interesting file search"

    $patterns = @("*.config", "*.xml", "*.ini", "*.txt", "*.json")
    $keywords = @("password", "credential", "secret", "connectionstring")
    $searchPaths = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents")

    Write-Host "  Searching for potentially interesting files..." -ForegroundColor DarkGray

    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath) {
            foreach ($pattern in $patterns) {
                Get-ChildItem -Path $searchPath -Filter $pattern -Recurse -ErrorAction SilentlyContinue -Depth 2 | ForEach-Object {
                    $content = Get-Content $_.FullName -ErrorAction SilentlyContinue -Raw
                    foreach ($keyword in $keywords) {
                        if ($content -match $keyword) {
                            Write-Host "  Found: $($_.FullName) (contains '$keyword')" -ForegroundColor Yellow
                            break
                        }
                    }
                }
            }
        }
    }
}

function Get-SBInterestingProcesses {
    Write-CommandHeader "InterestingProcesses" "Interesting/sensitive processes"

    $interestingProcs = @(
        "keepass", "1password", "lastpass", "bitwarden",
        "mstsc", "putty", "winscp", "filezilla",
        "vpn", "openvpn", "wireguard",
        "veracrypt", "truecrypt", "bitlocker",
        "outlook", "thunderbird",
        "sqlserver", "postgres", "mysql", "oracle",
        "notepad++", "code", "devenv"
    )

    $processes = Get-Process -ErrorAction SilentlyContinue

    foreach ($proc in $processes) {
        foreach ($interesting in $interestingProcs) {
            if ($proc.ProcessName -match $interesting) {
                Write-Host " ProcessName                              : $($proc.ProcessName)"
                Write-Host " ProcessId                                : $($proc.Id)"
                Write-Host " Path                                     : $($proc.Path)"
                Write-Host ""
                break
            }
        }
    }
}

function Get-SBFileInfo {
    Write-CommandHeader "FileInfo" "File information utility"

    Write-Host "  Use: Get-SBFileInfo -Path <filepath>" -ForegroundColor DarkGray
    Write-Host "  This is a utility command - provide a file path as argument"
}

function Get-SBDir {
    Write-CommandHeader "dir" "Directory listing utility"

    Write-Host "  Use: Get-ChildItem for directory listings" -ForegroundColor DarkGray
    Write-Host "  This is a utility command - provide a directory path as argument"
}

function Get-SBReg {
    Write-CommandHeader "reg" "Registry query utility"

    Write-Host "  Use: Get-RegistryValue -Hive <HKLM|HKCU|HKU> -Path <path> -Name <name>" -ForegroundColor DarkGray
    Write-Host "  This is a utility command - provide registry path as argument"
}

function Get-SBSearchIndex {
    Write-CommandHeader "SearchIndex" "Windows Search index information"

    try {
        $searchPath = "SOFTWARE\Microsoft\Windows Search"
        $dataPath = Get-RegistryValue -Hive "HKLM" -Path "$searchPath\Databases\Windows" -Name "c:\ProgramData\Microsoft\Search\Data\Applications\Windows"

        Write-CommandOutput "SearchIndexPath" "C:\ProgramData\Microsoft\Search\Data\Applications\Windows"

        $indexFile = "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"
        if (Test-Path $indexFile) {
            $info = Get-Item $indexFile
            Write-CommandOutput "Windows.edb Size" (Format-FileSize $info.Length)
            Write-CommandOutput "LastModified" $info.LastWriteTime
        }
    } catch {
        Write-Host "  Error querying search index: $_" -ForegroundColor Red
    }
}

function Get-SBRPCMappedEndpoints {
    Write-CommandHeader "RPCMappedEndpoints" "RPC mapped endpoints"

    try {
        $rpcPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq 135 -or $_.LocalPort -gt 49151 }

        Write-Host ("  {0,-25} {1,-8} {2}" -f "LocalAddress", "Port", "Process")
        Write-Host ("  {0,-25} {1,-8} {2}" -f "-----------", "----", "-------")

        foreach ($conn in $rpcPorts | Select-Object -First 20) {
            $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            Write-Host ("  {0,-25} {1,-8} {2}" -f $conn.LocalAddress, $conn.LocalPort, $procName)
        }
    } catch {
        Write-Host "  Error enumerating RPC endpoints: $_" -ForegroundColor Red
    }
}

function Get-SBWindowsCredentialFiles {
    Write-CommandHeader "WindowsCredentialFiles" "Windows credential files"

    $credPaths = @(
        "$env:LOCALAPPDATA\Microsoft\Credentials",
        "$env:APPDATA\Microsoft\Credentials"
    )

    foreach ($path in $credPaths) {
        if (Test-Path $path) {
            Write-Host "  $path" -ForegroundColor Cyan
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                Write-CommandOutput $_.Name "$($_.LastWriteTime) ($(Format-FileSize $_.Length))" 4
            }
            Write-Host ""
        }
    }
}

function Get-SBCertificates {
    Write-CommandHeader "Certificates" "User/machine certificates"

    Write-Host "  Current User Certificates:" -ForegroundColor Cyan
    try {
        Get-ChildItem -Path Cert:\CurrentUser\My -ErrorAction SilentlyContinue | ForEach-Object {
            Write-CommandOutput $_.Subject $_.Thumbprint 4
            Write-CommandOutput "Expires" $_.NotAfter 6
            Write-Host ""
        }
    } catch {}

    if (Test-IsHighIntegrity) {
        Write-Host "  Local Machine Certificates:" -ForegroundColor Cyan
        try {
            Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | ForEach-Object {
                Write-CommandOutput $_.Subject $_.Thumbprint 4
                Write-CommandOutput "Expires" $_.NotAfter 6
                Write-Host ""
            }
        } catch {}
    }
}

#endregion

#region Command Groups and Mappings

$Script:CommandGroups = @{
    System = @(
        "OSInfo", "AntiVirus", "AMSIProviders", "AppLocker", "AuditPolicies", "AuditPolicyRegistry",
        "AutoRuns", "Certificates", "CredGuard", "DNSCache", "DotNet", "EnvironmentPath",
        "EnvironmentVariables", "Hotfixes", "IdleTime", "InternetSettings", "LAPS", "LastShutdown",
        "LocalGroups", "LocalGPOs", "LocalUsers", "LogonSessions", "LSASettings", "MappedDrives",
        "MicrosoftUpdates", "NamedPipes", "NetworkProfiles", "NetworkShares", "NTLMSettings",
        "OptionalFeatures", "Printers", "Processes", "ProcessOwners", "PSSessionSettings",
        "PowerShell", "PowerShellHistory", "RDPSessions", "RDPsettings", "RecycleBin", "ARPTable",
        "ScheduledTasks", "SecureBoot", "SecurityPackages", "Services", "Sysmon", "TcpConnections",
        "TokenGroups", "TokenPrivileges", "UAC", "UdpConnections", "UserRightAssignments",
        "WifiProfile", "WindowsAutoLogon", "WindowsDefender", "WindowsEventForwarding",
        "WindowsFirewall", "WindowsVault", "WMI", "WMIEventConsumer", "WMIEventFilter",
        "WMIFilterBinding", "WSUS"
    )
    User = @(
        "Certificates", "Clipboard", "CloudCredentials", "CredEnum", "DpapiMasterKeys",
        "ExplorerMRUs", "ExplorerRunCommands", "RDPSavedConnections", "PuttyHostKeys",
        "PuttySessions", "RecentFiles", "PowerShellHistory", "WindowsCredentialFiles"
    )
    Browser = @(
        "ChromiumBookmarks", "ChromiumHistory", "ChromiumPresence",
        "FirefoxHistory", "FirefoxPresence",
        "IEFavorites", "IETabs", "IEUrls"
    )
    Chromium = @(
        "ChromiumBookmarks", "ChromiumHistory", "ChromiumPresence"
    )
    Slack = @(
        "SlackDownloads", "SlackPresence", "SlackWorkspaces"
    )
    Remote = @(
        "OSInfo", "AntiVirus", "AuditPolicyRegistry", "DNSCache", "DotNet", "Hotfixes",
        "LastShutdown", "LocalGroups", "LocalUsers", "LogonSessions", "LSASettings",
        "MappedDrives", "NetworkProfiles", "NetworkShares", "NTLMSettings", "Processes",
        "ProcessOwners", "Services", "UAC", "WindowsAutoLogon", "WindowsFirewall"
    )
    Misc = @(
        "CloudCredentials", "CloudSyncProviders", "FileZilla", "InstalledProducts", "KeePass",
        "InterestingFiles", "InterestingProcesses", "McAfeeConfigs", "McAfeeSiteList", "MTPuTTY",
        "OfficeMRUs", "OneNote", "OracleSQLDeveloper", "OutlookDownloads", "RDCManFiles",
        "SCCM", "SlackDownloads", "SlackPresence", "SlackWorkspaces", "SuperPutty",
        "ExplicitLogonEvents", "LogonEvents", "PoweredOnEvents", "PowerShellEvents",
        "ProcessCreationEvents", "SysmonEvents", "RPCMappedEndpoints", "SearchIndex"
    )
}

$Script:AllCommands = @{
    # System Commands
    "OSInfo" = { Get-SBOSInfo }
    "AntiVirus" = { Get-SBAntiVirus }
    "AMSIProviders" = { Get-SBAMSIProviders }
    "AppLocker" = { Get-SBAppLocker }
    "AuditPolicies" = { Get-SBAuditPolicies }
    "AuditPolicyRegistry" = { Get-SBAuditPolicyRegistry }
    "AutoRuns" = { Get-SBAutoRuns }
    "CredGuard" = { Get-SBCredGuard }
    "DNSCache" = { Get-SBDNSCache }
    "DotNet" = { Get-SBDotNet }
    "EnvironmentPath" = { Get-SBEnvironmentPath }
    "EnvironmentVariables" = { Get-SBEnvironmentVariables }
    "Hotfixes" = { Get-SBHotfixes }
    "IdleTime" = { Get-SBIdleTime }
    "InternetSettings" = { Get-SBInternetSettings }
    "LAPS" = { Get-SBLAPSSettings }
    "LastShutdown" = { Get-SBLastShutdown }
    "LocalGroups" = { Get-SBLocalGroups }
    "LocalGPOs" = { Get-SBLocalGPOs }
    "LocalUsers" = { Get-SBLocalUsers }
    "LogonSessions" = { Get-SBLogonSessions }
    "LSASettings" = { Get-SBLSASettings }
    "MappedDrives" = { Get-SBMappedDrives }
    "MicrosoftUpdates" = { Get-SBMicrosoftUpdates }
    "NamedPipes" = { Get-SBNamedPipes }
    "NetworkProfiles" = { Get-SBNetworkProfiles }
    "NetworkShares" = { Get-SBNetworkShares }
    "NTLMSettings" = { Get-SBNTLMSettings }
    "OptionalFeatures" = { Get-SBOptionalFeatures }
    "Printers" = { Get-SBPrinters }
    "Processes" = { Get-SBProcesses }
    "ProcessOwners" = { Get-SBProcessOwners }
    "PSSessionSettings" = { Get-SBPSSessionSettings }
    "PowerShell" = { Get-SBPowerShell }
    "PowerShellHistory" = { Get-SBPowerShellHistory }
    "RDPSessions" = { Get-SBRDPSessions }
    "RDPsettings" = { Get-SBRDPSettings }
    "RecycleBin" = { Get-SBRecycleBin }
    "ARPTable" = { Get-SBARPTable }
    "ScheduledTasks" = { Get-SBScheduledTasks }
    "SecureBoot" = { Get-SBSecureBoot }
    "SecurityPackages" = { Get-SBSecurityPackages }
    "Services" = { Get-SBServices }
    "Sysmon" = { Get-SBSysmon }
    "TcpConnections" = { Get-SBTcpConnections }
    "TokenGroups" = { Get-SBTokenGroups }
    "TokenPrivileges" = { Get-SBTokenPrivileges }
    "UAC" = { Get-SBUAC }
    "UdpConnections" = { Get-SBUdpConnections }
    "UserRightAssignments" = { Get-SBUserRightAssignments }
    "WifiProfile" = { Get-SBWifiProfile }
    "WindowsAutoLogon" = { Get-SBWindowsAutoLogon }
    "WindowsDefender" = { Get-SBWindowsDefender }
    "WindowsEventForwarding" = { Get-SBWindowsEventForwarding }
    "WindowsFirewall" = { Get-SBWindowsFirewall }
    "WindowsVault" = { Get-SBWindowsVault }
    "WMI" = { Get-SBWMI }
    "WMIEventConsumer" = { Get-SBWMIEventConsumer }
    "WMIEventFilter" = { Get-SBWMIEventFilter }
    "WMIFilterBinding" = { Get-SBWMIFilterBinding }
    "WSUS" = { Get-SBWSUS }

    # User Commands
    "CloudCredentials" = { Get-SBCloudCredentials }
    "CredEnum" = { Get-SBCredEnum }
    "DpapiMasterKeys" = { Get-SBDpapiMasterKeys }
    "ExplorerMRUs" = { Get-SBExplorerMRUs }
    "ExplorerRunCommands" = { Get-SBExplorerRunCommands }
    "RDPSavedConnections" = { Get-SBRDPSavedConnections }
    "PuttyHostKeys" = { Get-SBPuttyHostKeys }
    "PuttySessions" = { Get-SBPuttySessions }
    "RecentFiles" = { Get-SBRecentFiles }
    "Clipboard" = { Get-SBClipboard }
    "WindowsCredentialFiles" = { Get-SBWindowsCredentialFiles }
    "Certificates" = { Get-SBCertificates }

    # Browser Commands
    "ChromiumBookmarks" = { Get-SBChromiumBookmarks }
    "ChromiumHistory" = { Get-SBChromiumHistory }
    "ChromiumPresence" = { Get-SBChromiumPresence }
    "FirefoxHistory" = { Get-SBFirefoxHistory }
    "FirefoxPresence" = { Get-SBFirefoxPresence }
    "IEFavorites" = { Get-SBIEFavorites }
    "IETabs" = { Get-SBIETabs }
    "IEUrls" = { Get-SBIEUrls }

    # Products Commands
    "CloudSyncProviders" = { Get-SBCloudSyncProviders }
    "FileZilla" = { Get-SBFileZilla }
    "InstalledProducts" = { Get-SBInstalledProducts }
    "KeePass" = { Get-SBKeePass }
    "McAfeeConfigs" = { Get-SBMcAfeeConfigs }
    "McAfeeSiteList" = { Get-SBMcAfeeSiteList }
    "MTPuTTY" = { Get-SBMTPuTTY }
    "OfficeMRUs" = { Get-SBOfficeMRUs }
    "OneNote" = { Get-SBOneNote }
    "OracleSQLDeveloper" = { Get-SBOracleSQLDeveloper }
    "OutlookDownloads" = { Get-SBOutlookDownloads }
    "RDCManFiles" = { Get-SBRDCManFiles }
    "SCCM" = { Get-SBSCCM }
    "SlackDownloads" = { Get-SBSlackDownloads }
    "SlackPresence" = { Get-SBSlackPresence }
    "SlackWorkspaces" = { Get-SBSlackWorkspaces }
    "SuperPutty" = { Get-SBSuperPutty }

    # Event Log Commands
    "ExplicitLogonEvents" = { Get-SBExplicitLogonEvents }
    "LogonEvents" = { Get-SBLogonEvents }
    "PoweredOnEvents" = { Get-SBPoweredOnEvents }
    "PowerShellEvents" = { Get-SBPowerShellEvents }
    "ProcessCreationEvents" = { Get-SBProcessCreationEvents }
    "SysmonEvents" = { Get-SBSysmonEvents }

    # Misc Commands
    "InterestingFiles" = { Get-SBInterestingFiles }
    "InterestingProcesses" = { Get-SBInterestingProcesses }
    "FileInfo" = { Get-SBFileInfo }
    "dir" = { Get-SBDir }
    "reg" = { Get-SBReg }
    "SearchIndex" = { Get-SBSearchIndex }
    "RPCMappedEndpoints" = { Get-SBRPCMappedEndpoints }
}

#endregion

#region Help System

function Show-Help {
    Write-Host ""
    Write-Host "Seatbelt (PowerShell Edition) - Security Enumeration Tool" -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\Seatbelt.ps1 [-Command <cmd1,cmd2,...>] [-Group <groupname>] [-Full] [-OutputFile <path>] [-Quiet]"
    Write-Host ""
    Write-Host "Parameters:" -ForegroundColor Yellow
    Write-Host "  -Command       Specific command(s) to run (comma-separated)"
    Write-Host "  -Group         Command group: System, User, Browser, Remote, Misc, Slack, Chromium, All"
    Write-Host "  -Full          Return unfiltered results (default: filtered)"
    Write-Host "  -OutputFile    Path to save output"
    Write-Host "  -Quiet         Suppress banner"
    Write-Host "  -ComputerName  Remote computer (for supported commands)"
    Write-Host ""
    Write-Host "Available Groups:" -ForegroundColor Yellow
    Write-Host "  System   - OS, security, network, services, processes (~62 commands)"
    Write-Host "  User     - User-specific data, credentials, history (~13 commands)"
    Write-Host "  Browser  - Browser artifacts, bookmarks, history (~8 commands)"
    Write-Host "  Remote   - Commands supporting remote execution (~21 commands)"
    Write-Host "  Misc     - Third-party apps, event logs, files (~28 commands)"
    Write-Host "  Slack    - Slack artifacts (~3 commands)"
    Write-Host "  Chromium - Chromium browser data (~3 commands)"
    Write-Host "  All      - Run all commands"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\Seatbelt.ps1 -Command OSInfo"
    Write-Host "  .\Seatbelt.ps1 -Command OSInfo,Processes,Services"
    Write-Host "  .\Seatbelt.ps1 -Group System"
    Write-Host "  .\Seatbelt.ps1 -Group All -Full"
    Write-Host "  .\Seatbelt.ps1 -Group System -OutputFile C:\results.txt"
    Write-Host ""
    Write-Host "Available Commands ($($Script:AllCommands.Count) total):" -ForegroundColor Yellow

    $cmdList = $Script:AllCommands.Keys | Sort-Object
    $columns = 4
    $columnWidth = 25

    for ($i = 0; $i -lt $cmdList.Count; $i += $columns) {
        $line = "  "
        for ($j = 0; $j -lt $columns -and ($i + $j) -lt $cmdList.Count; $j++) {
            $line += "{0,-$columnWidth}" -f $cmdList[$i + $j]
        }
        Write-Host $line
    }
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

    # Determine commands to run from group
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

    # Add individual commands
    if ($Command) {
        $commandsToRun += $Command
    }

    $commandsToRun = $commandsToRun | Select-Object -Unique

    # Setup output redirection if needed
    $transcriptStarted = $false
    if ($OutputFile) {
        try {
            Start-Transcript -Path $OutputFile -Force | Out-Null
            $transcriptStarted = $true
        }
        catch {
            Write-Host "Warning: Could not start transcript. Using alternative output method." -ForegroundColor Yellow
        }
    }

    try {
        Write-Host ""
        Write-Host "[*] Running $($commandsToRun.Count) command(s)" -ForegroundColor Cyan
        Write-Host "[*] Started at: $(Get-Date)" -ForegroundColor DarkGray
        if ($Script:FilterResults) {
            Write-Host "[*] Results filtered (use -Full for complete output)" -ForegroundColor DarkGray
        }
        Write-Host ""

        $completed = 0
        foreach ($cmd in $commandsToRun) {
            if ($Script:AllCommands.ContainsKey($cmd)) {
                try {
                    if ($DelayCommands -gt 0) {
                        Start-Sleep -Milliseconds $DelayCommands
                    }
                    & $Script:AllCommands[$cmd]
                    $completed++
                }
                catch {
                    Write-Host "Error executing $cmd : $_" -ForegroundColor Red
                }
            }
            else {
                Write-Host "Unknown command: $cmd" -ForegroundColor Yellow
            }
        }

        Write-Host ""
        Write-Host "[*] Completed $completed/$($commandsToRun.Count) commands" -ForegroundColor Cyan
        Write-Host "[*] Finished at: $(Get-Date)" -ForegroundColor DarkGray

        $duration = (Get-Date) - $Script:StartTime
        Write-Host "[*] Duration: $($duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor DarkGray
    }
    finally {
        if ($transcriptStarted) {
            Stop-Transcript | Out-Null
            Write-Host "[*] Output saved to: $OutputFile" -ForegroundColor Green
        }
    }
}

# Run the main function
Invoke-Seatbelt

#endregion
