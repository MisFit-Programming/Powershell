<#
.SYNOPSIS
    Compact, color-coded Windows Server health and terminal-session monitor.

.DESCRIPTION
    Displays a single-screen dashboard that refreshes in place and highlights
    performance or service issues in color. Designed for Windows Server and
    Remote Desktop / terminal-server acceptance monitoring.

    The script does not remediate or restart services. It can write alert
    history to a local log file unless -NoLog is specified.

.PARAMETER RefreshSeconds
    Dashboard refresh interval in seconds. Default: 10.

.PARAMETER EventCheckSeconds
    Interval used to check the System and Application event logs. Default: 60.

.PARAMETER AdditionalServices
    Optional service names to monitor in addition to TermService and Spooler.

.PARAMETER MaxUsers
    Maximum terminal sessions shown on the dashboard. Default: 8.

.PARAMETER MaxProcesses
    Maximum CPU-consuming processes shown. Default: 5.

.PARAMETER MaxIssues
    Maximum active issues shown. Default: 5.

.PARAMETER IgnoreLegacyAspNetFilterErrors
    Suppresses IIS-W3SVC-WP events 2268 and 2274. Useful when a known legacy
    ASP.NET ISAPI architecture mismatch exists and is not part of the active
    application path.

.PARAMETER NoLog
    Prevents the script from writing alert history to disk.

.EXAMPLE
    .\WindowsServerHealthMonitor.ps1

.EXAMPLE
    .\WindowsServerHealthMonitor.ps1 -AdditionalServices APSC,SVCM,SVCW,QuickBooksDB31

.EXAMPLE
    .\WindowsServerHealthMonitor.ps1 -RefreshSeconds 5 -MaxUsers 12 -IgnoreLegacyAspNetFilterErrors

.NOTES
    PowerShell 5.1 compatible.
    Run in an elevated PowerShell session for the most complete visibility.
    Press Ctrl+C to stop.
#>

[CmdletBinding()]
param(
    [ValidateRange(2,3600)]
    [int]$RefreshSeconds = 10,

    [ValidateRange(10,3600)]
    [int]$EventCheckSeconds = 60,

    [string[]]$AdditionalServices = @(),

    [ValidateRange(1,50)]
    [int]$MaxUsers = 8,

    [ValidateRange(1,20)]
    [int]$MaxProcesses = 5,

    [ValidateRange(1,20)]
    [int]$MaxIssues = 5,

    [ValidateRange(1,100)]
    [int]$CpuWarn = 70,

    [ValidateRange(1,100)]
    [int]$CpuCrit = 90,

    [ValidateRange(1,100)]
    [int]$MemWarn = 80,

    [ValidateRange(1,100)]
    [int]$MemCrit = 90,

    [ValidateRange(1,1000)]
    [int]$DiskLatencyWarnMs = 20,

    [ValidateRange(1,5000)]
    [int]$DiskLatencyCritMs = 50,

    [ValidateRange(1,100)]
    [int]$DiskQueueWarn = 5,

    [ValidateRange(1,500)]
    [int]$DiskQueueCrit = 10,

    [ValidateRange(1,100)]
    [int]$DiskFreeWarnPercent = 20,

    [ValidateRange(1,100)]
    [int]$DiskFreeCritPercent = 10,

    [switch]$IgnoreLegacyAspNetFilterErrors,
    [switch]$NoLog
)

if ($CpuCrit -lt $CpuWarn) { throw 'CpuCrit must be greater than or equal to CpuWarn.' }
if ($MemCrit -lt $MemWarn) { throw 'MemCrit must be greater than or equal to MemWarn.' }
if ($DiskLatencyCritMs -lt $DiskLatencyWarnMs) { throw 'DiskLatencyCritMs must be greater than or equal to DiskLatencyWarnMs.' }
if ($DiskQueueCrit -lt $DiskQueueWarn) { throw 'DiskQueueCrit must be greater than or equal to DiskQueueWarn.' }
if ($DiskFreeCritPercent -gt $DiskFreeWarnPercent) { throw 'DiskFreeCritPercent must be less than or equal to DiskFreeWarnPercent.' }

$CriticalServices = @('TermService','Spooler') + $AdditionalServices
$CriticalServices = @($CriticalServices | Where-Object { $_ } | Select-Object -Unique)

$LogFolder = Join-Path $env:ProgramData 'WindowsServerHealthMonitor'
$AlertLog = Join-Path $LogFolder 'Alerts.log'

if (-not $NoLog) {
    New-Item -ItemType Directory -Path $LogFolder -Force -ErrorAction SilentlyContinue | Out-Null
}

$AlertCooldownSeconds = 300
$LastAlert = @{}
$LastEventCheck = Get-Date
$RecentImportantEvents = @()
$PreviousNetworkBytes = $null
$PreviousNetworkTime = Get-Date

function Add-Issue {
    param(
        [ValidateSet('WARNING','CRITICAL')]
        [string]$Severity,
        [string]$Message
    )

    $script:Issues += [pscustomobject]@{
        Severity = $Severity
        Message  = $Message
    }

    if ($NoLog) { return }

    $Key = "$Severity|$Message"
    $Now = Get-Date

    if (-not $LastAlert.ContainsKey($Key) -or (($Now - $LastAlert[$Key]).TotalSeconds -ge $AlertCooldownSeconds)) {
        "$($Now.ToString('yyyy-MM-dd HH:mm:ss')) [$Severity] $Message" |
            Out-File -FilePath $AlertLog -Append -Encoding utf8
        $LastAlert[$Key] = $Now
    }
}

function Get-Color {
    param(
        [double]$Value,
        [double]$Warning,
        [double]$Critical,
        [switch]$LowerIsBad
    )

    if ($LowerIsBad) {
        if ($Value -le $Critical) { return 'Red' }
        if ($Value -le $Warning)  { return 'Yellow' }
        return 'Green'
    }

    if ($Value -ge $Critical) { return 'Red' }
    if ($Value -ge $Warning)  { return 'Yellow' }
    return 'Green'
}

function Get-UserSessions {
    $Rows = @()
    $Raw = quser 2>$null

    if (-not $Raw) { return @() }

    foreach ($Line in ($Raw | Select-Object -Skip 1)) {
        if ([string]::IsNullOrWhiteSpace($Line)) { continue }

        $Clean = $Line.TrimStart('>')
        $Parts = $Clean -split '\s{2,}'
        if ($Parts.Count -lt 4) { continue }

        $User = $Parts[0].Trim()
        $SessionName = ''
        $Id = ''
        $State = ''
        $Idle = ''
        $Logon = ''

        if ($Parts.Count -ge 6) {
            $SessionName = $Parts[1].Trim()
            $Id = $Parts[2].Trim()
            $State = $Parts[3].Trim()
            $Idle = $Parts[4].Trim()
            $Logon = ($Parts[5..($Parts.Count - 1)] -join ' ').Trim()
        }
        elseif ($Parts.Count -eq 5) {
            $Id = $Parts[1].Trim()
            $State = $Parts[2].Trim()
            $Idle = $Parts[3].Trim()
            $Logon = $Parts[4].Trim()
        }

        $Rows += [pscustomobject]@{
            User    = $User
            Session = $SessionName
            Id      = $Id
            State   = $State
            Idle    = $Idle
            Logon   = $Logon
        }
    }

    return $Rows
}

function Get-PendingRebootState {
    $Cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $Wu = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $RenameData = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    $HasRename = [bool]$RenameData
    $BenignRenameOnly = $false

    if ($HasRename) {
        $NonBenign = @(
            $RenameData | Where-Object {
                $_ -and
                $_ -notmatch '\\Microsoft OneDrive\\' -and
                $_ -notmatch '\\spool\\V4Dirs\\'
            }
        )
        $BenignRenameOnly = ($NonBenign.Count -eq 0)
    }

    [pscustomobject]@{
        CBS              = $Cbs
        WindowsUpdate    = $Wu
        PendingRename    = $HasRename
        BenignRenameOnly = $BenignRenameOnly
    }
}

while ($true) {
    $Issues = @()
    $Now = Get-Date

    $OS = Get-CimInstance Win32_OperatingSystem
    $CPU = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average,1)
    $TotalMemoryGB = [math]::Round($OS.TotalVisibleMemorySize / 1MB,1)
    $FreeMemoryGB = [math]::Round($OS.FreePhysicalMemory / 1MB,1)
    $MemoryUsed = [math]::Round((($OS.TotalVisibleMemorySize - $OS.FreePhysicalMemory) / $OS.TotalVisibleMemorySize) * 100,1)

    if ($CPU -ge $CpuCrit) { Add-Issue CRITICAL "CPU utilization $CPU%" }
    elseif ($CPU -ge $CpuWarn) { Add-Issue WARNING "CPU utilization $CPU%" }

    if ($MemoryUsed -ge $MemCrit) { Add-Issue CRITICAL "Memory utilization $MemoryUsed%" }
    elseif ($MemoryUsed -ge $MemWarn) { Add-Issue WARNING "Memory utilization $MemoryUsed%" }

    $Uptime = $Now - $OS.LastBootUpTime
    $UptimeText = '{0}d {1}h {2}m' -f $Uptime.Days,$Uptime.Hours,$Uptime.Minutes

    $Sessions = @(Get-UserSessions)
    $ActiveSessions = @($Sessions | Where-Object State -match '^Active$')
    $DisconnectedSessions = @($Sessions | Where-Object State -match '^Disc')

    $Volumes = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and $_.Size -gt 0 })
    $VolumeRows = @()

    foreach ($Volume in $Volumes) {
        $FreeGB = [math]::Round($Volume.SizeRemaining / 1GB,1)
        $FreePercent = [math]::Round(($Volume.SizeRemaining / $Volume.Size) * 100,1)

        if ($FreePercent -le $DiskFreeCritPercent) { Add-Issue CRITICAL "$($Volume.DriveLetter): drive has $FreePercent% free" }
        elseif ($FreePercent -le $DiskFreeWarnPercent) { Add-Issue WARNING "$($Volume.DriveLetter): drive has $FreePercent% free" }

        $VolumeRows += [pscustomobject]@{
            Drive = "$($Volume.DriveLetter):"
            FreeGB = $FreeGB
            FreePercent = $FreePercent
        }
    }

    $DiskPerf = @(Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -ErrorAction SilentlyContinue | Where-Object Name -ne '_Total')
    $WorstLatency = 0.0
    $WorstQueue = 0.0

    foreach ($Disk in $DiskPerf) {
        $ReadMs = [double]$Disk.AvgDisksecPerRead * 1000
        $WriteMs = [double]$Disk.AvgDisksecPerWrite * 1000
        $Latency = [math]::Max($ReadMs,$WriteMs)
        $Queue = [double]$Disk.CurrentDiskQueueLength
        if ($Latency -gt $WorstLatency) { $WorstLatency = $Latency }
        if ($Queue -gt $WorstQueue) { $WorstQueue = $Queue }
    }

    $WorstLatency = [math]::Round($WorstLatency,1)
    $WorstQueue = [math]::Round($WorstQueue,1)

    if ($WorstLatency -ge $DiskLatencyCritMs) { Add-Issue CRITICAL "Disk latency $WorstLatency ms" }
    elseif ($WorstLatency -ge $DiskLatencyWarnMs) { Add-Issue WARNING "Disk latency $WorstLatency ms" }

    if ($WorstQueue -ge $DiskQueueCrit) { Add-Issue CRITICAL "Disk queue $WorstQueue" }
    elseif ($WorstQueue -ge $DiskQueueWarn) { Add-Issue WARNING "Disk queue $WorstQueue" }

    $NetStats = @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue)
    $CurrentNetworkBytes = (($NetStats | Measure-Object ReceivedBytes -Sum).Sum + ($NetStats | Measure-Object SentBytes -Sum).Sum)
    $ElapsedNetworkSeconds = ($Now - $PreviousNetworkTime).TotalSeconds
    $NetworkMbps = 0.0

    if ($null -ne $PreviousNetworkBytes -and $ElapsedNetworkSeconds -gt 0 -and $CurrentNetworkBytes -ge $PreviousNetworkBytes) {
        $NetworkMbps = [math]::Round((($CurrentNetworkBytes - $PreviousNetworkBytes) * 8 / $ElapsedNetworkSeconds) / 1MB,2)
    }

    $PreviousNetworkBytes = $CurrentNetworkBytes
    $PreviousNetworkTime = $Now

    $ServiceStatus = @()
    foreach ($ServiceName in $CriticalServices) {
        $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $Service) {
            Add-Issue WARNING "Service $ServiceName not found"
            $ServiceStatus += [pscustomobject]@{ Name = $ServiceName; Status = 'Missing' }
            continue
        }

        if ($Service.Status -ne 'Running') { Add-Issue CRITICAL "$ServiceName is $($Service.Status)" }
        $ServiceStatus += [pscustomobject]@{ Name = $ServiceName; Status = [string]$Service.Status }
    }

    $RdpListener = Get-NetTCPConnection -State Listen -LocalPort 3389 -ErrorAction SilentlyContinue | Select-Object -First 1
    $Port80 = Get-NetTCPConnection -State Listen -LocalPort 80 -ErrorAction SilentlyContinue | Select-Object -First 1
    $Port443 = Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $RdpListener) { Add-Issue CRITICAL 'RDP port 3389 is not listening' }

    $Pending = Get-PendingRebootState
    if ($Pending.CBS) { Add-Issue WARNING 'Component Based Servicing requires a reboot' }
    if ($Pending.WindowsUpdate) { Add-Issue WARNING 'Windows Update requires a reboot' }
    if ($Pending.PendingRename -and -not $Pending.BenignRenameOnly) { Add-Issue WARNING 'Pending file operations require review' }

    if (($Now - $LastEventCheck).TotalSeconds -ge $EventCheckSeconds) {
        $Events = @()
        foreach ($LogName in 'System','Application') {
            $Events += Get-WinEvent -FilterHashtable @{
                LogName   = $LogName
                Level     = 1,2
                StartTime = $LastEventCheck
            } -ErrorAction SilentlyContinue
        }

        $LastEventCheck = $Now

        $ImportantEvents = @(
            $Events | Where-Object {
                if ($IgnoreLegacyAspNetFilterErrors -and $_.ProviderName -eq 'Microsoft-Windows-IIS-W3SVC-WP' -and $_.Id -in 2268,2274) {
                    return $false
                }
                return $true
            }
        )

        $RecentImportantEvents = @($ImportantEvents | Sort-Object TimeCreated -Descending | Select-Object -First 3)

        foreach ($Event in $ImportantEvents) {
            $SevereProvider = $Event.ProviderName -match 'Disk|Ntfs|stor|volmgr|WHEA|VSS|TerminalServices'
            if ($Event.LevelDisplayName -eq 'Critical' -or $SevereProvider) {
                Add-Issue CRITICAL "Event $($Event.Id) from $($Event.ProviderName)"
            }
            else {
                Add-Issue WARNING "Event $($Event.Id) from $($Event.ProviderName)"
            }
        }
    }

    $LogicalCpuCount = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    $TopCPU = @(
        Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin '_Total','Idle' -and $_.IDProcess -ne 0 } |
            ForEach-Object {
                [pscustomobject]@{
                    Process = $_.Name
                    PID     = $_.IDProcess
                    CPU     = [math]::Round(([double]$_.PercentProcessorTime / $LogicalCpuCount),1)
                    RAMMB   = [math]::Round($_.WorkingSetPrivate / 1MB,0)
                }
            } |
            Sort-Object CPU -Descending |
            Select-Object -First $MaxProcesses
    )

    Clear-Host

    $CriticalCount = @($Issues | Where-Object Severity -eq 'CRITICAL').Count
    $WarningCount = @($Issues | Where-Object Severity -eq 'WARNING').Count

    Write-Host ('=' * 78) -ForegroundColor DarkGray
    Write-Host " $env:COMPUTERNAME   WINDOWS SERVER HEALTH MONITOR" -ForegroundColor Cyan
    Write-Host (" {0}   Uptime: {1}   Refresh: {2}s" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$UptimeText,$RefreshSeconds) -ForegroundColor DarkGray
    Write-Host ('=' * 78) -ForegroundColor DarkGray

    if ($CriticalCount -gt 0) {
        Write-Host " STATUS: CRITICAL   Critical: $CriticalCount   Warnings: $WarningCount " -ForegroundColor White -BackgroundColor Red
    }
    elseif ($WarningCount -gt 0) {
        Write-Host " STATUS: WARNING    Critical: 0   Warnings: $WarningCount " -ForegroundColor Black -BackgroundColor Yellow
    }
    else {
        Write-Host ' STATUS: HEALTHY    Critical: 0   Warnings: 0 ' -ForegroundColor Black -BackgroundColor Green
    }

    Write-Host ''
    Write-Host 'PERFORMANCE' -ForegroundColor Cyan
    Write-Host ' CPU ' -NoNewline
    Write-Host "$CPU%" -NoNewline -ForegroundColor (Get-Color $CPU $CpuWarn $CpuCrit)
    Write-Host '   RAM ' -NoNewline
    Write-Host "$MemoryUsed%" -NoNewline -ForegroundColor (Get-Color $MemoryUsed $MemWarn $MemCrit)
    Write-Host " ($FreeMemoryGB/$TotalMemoryGB GB free/total)" -NoNewline
    Write-Host '   Disk ' -NoNewline
    Write-Host "$WorstLatency ms" -NoNewline -ForegroundColor (Get-Color $WorstLatency $DiskLatencyWarnMs $DiskLatencyCritMs)
    Write-Host '   Queue ' -NoNewline
    Write-Host "$WorstQueue" -NoNewline -ForegroundColor (Get-Color $WorstQueue $DiskQueueWarn $DiskQueueCrit)
    Write-Host "   Net $NetworkMbps Mbps"

    Write-Host ''
    Write-Host 'STORAGE' -ForegroundColor Cyan
    foreach ($Volume in $VolumeRows) {
        $Color = Get-Color $Volume.FreePercent $DiskFreeWarnPercent $DiskFreeCritPercent -LowerIsBad
        Write-Host (" {0,-3} {1,8} GB free ({2,5}%)" -f $Volume.Drive,$Volume.FreeGB,$Volume.FreePercent) -ForegroundColor $Color
    }

    Write-Host ''
    Write-Host ("USERS   Total: {0}   Active: {1}   Disconnected: {2}" -f $Sessions.Count,$ActiveSessions.Count,$DisconnectedSessions.Count) -ForegroundColor Cyan
    Write-Host ("{0,-18} {1,-7} {2,-9} {3,-9} {4}" -f 'User','ID','State','Idle','Logon') -ForegroundColor DarkGray

    foreach ($Session in ($Sessions | Select-Object -First $MaxUsers)) {
        $SessionColor = if ($Session.State -match '^Active$') { 'Green' } elseif ($Session.State -match '^Disc') { 'Yellow' } else { 'White' }
        Write-Host ("{0,-18} {1,-7} {2,-9} {3,-9} {4}" -f $Session.User,$Session.Id,$Session.State,$Session.Idle,$Session.Logon) -ForegroundColor $SessionColor
    }

    if ($Sessions.Count -gt $MaxUsers) {
        Write-Host (" + {0} additional session(s)" -f ($Sessions.Count - $MaxUsers)) -ForegroundColor DarkGray
    }

    Write-Host ''
    Write-Host 'SERVICES / CONNECTIVITY' -ForegroundColor Cyan
    $ServicesHealthy = @($ServiceStatus | Where-Object Status -ne 'Running').Count -eq 0
    Write-Host ' Services: ' -NoNewline
    if ($ServicesHealthy) { Write-Host 'OK' -NoNewline -ForegroundColor Green } else { Write-Host 'ISSUE' -NoNewline -ForegroundColor Red }
    Write-Host '   RDP: ' -NoNewline
    if ($RdpListener) { Write-Host 'LISTENING' -NoNewline -ForegroundColor Green } else { Write-Host 'DOWN' -NoNewline -ForegroundColor Red }
    Write-Host '   HTTP: ' -NoNewline
    if ($Port80) { Write-Host '80 ' -NoNewline -ForegroundColor Green } else { Write-Host '80 ' -NoNewline -ForegroundColor DarkGray }
    if ($Port443) { Write-Host '443' -ForegroundColor Green } else { Write-Host '443' -ForegroundColor DarkGray }

    if ($Pending.PendingRename -and $Pending.BenignRenameOnly) {
        Write-Host ' INFO: Only OneDrive / V4 printer cleanup is pending the next reboot.' -ForegroundColor Cyan
    }

    Write-Host ''
    Write-Host 'TOP CPU PROCESSES' -ForegroundColor Cyan
    Write-Host ("{0,-24} {1,7} {2,8} {3,10}" -f 'Process','PID','CPU%','RAM MB') -ForegroundColor DarkGray
    foreach ($Process in $TopCPU) {
        $ProcessColor = if ($Process.CPU -ge 50) { 'Red' } elseif ($Process.CPU -ge 25) { 'Yellow' } else { 'White' }
        Write-Host ("{0,-24} {1,7} {2,8} {3,10}" -f $Process.Process,$Process.PID,$Process.CPU,$Process.RAMMB) -ForegroundColor $ProcessColor
    }

    Write-Host ''
    Write-Host 'ACTIVE ISSUES' -ForegroundColor Cyan
    if ($Issues.Count -eq 0) {
        Write-Host ' None' -ForegroundColor Green
    }
    else {
        foreach ($Issue in ($Issues | Select-Object -First $MaxIssues)) {
            if ($Issue.Severity -eq 'CRITICAL') {
                Write-Host (" CRITICAL  {0}" -f $Issue.Message) -ForegroundColor White -BackgroundColor Red
            }
            else {
                Write-Host (" WARNING   {0}" -f $Issue.Message) -ForegroundColor Yellow
            }
        }

        if ($Issues.Count -gt $MaxIssues) {
            Write-Host (" + {0} more issue(s)" -f ($Issues.Count - $MaxIssues)) -ForegroundColor DarkGray
        }
    }

    if ($RecentImportantEvents.Count -gt 0) {
        Write-Host ''
        Write-Host 'RECENT EVENTS' -ForegroundColor Cyan
        foreach ($Event in $RecentImportantEvents) {
            $Message = (($Event.Message -replace '[\r\n]+',' ') -replace '\s+',' ').Trim()
            if ($Message.Length -gt 70) { $Message = $Message.Substring(0,67) + '...' }
            $EventColor = if ($Event.LevelDisplayName -eq 'Critical') { 'Red' } else { 'Yellow' }
            Write-Host (" {0} | {1} | {2}" -f $Event.Id,$Event.ProviderName,$Message) -ForegroundColor $EventColor
        }
    }

    Write-Host ''
    if ($NoLog) {
        Write-Host ' Logging disabled. Ctrl+C to stop.' -ForegroundColor DarkGray
    }
    else {
        Write-Host (" Alert Log: {0}   Ctrl+C to stop" -f $AlertLog) -ForegroundColor DarkGray
    }

    Start-Sleep -Seconds $RefreshSeconds
}
