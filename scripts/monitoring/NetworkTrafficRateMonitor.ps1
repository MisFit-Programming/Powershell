<#
.SYNOPSIS
    Monitors live Windows network adapter packet rates and can flag broadcast or multicast storms.

.DESCRIPTION
    Samples Get-NetAdapterStatistics at a configurable interval and calculates
    receive rates for broadcast, multicast, unicast, discarded packets, and
    receive throughput.

    By default, all active network adapters are monitored. Use -Name to target
    one or more adapters, including wildcard names, or -PhysicalOnly to exclude
    virtual adapters.

    Storm detection is optional. Set -StormThreshold to a packets-per-second
    value to flag an adapter when either broadcast or multicast traffic reaches
    or exceeds that rate.

.PARAMETER Name
    One or more adapter names or wildcard patterns. If omitted, all active
    adapters are monitored.

.PARAMETER IntervalSeconds
    Number of seconds between samples. Default: 5.

.PARAMETER Samples
    Number of samples to collect. Default: 0, which runs continuously until
    Ctrl+C is pressed.

.PARAMETER PhysicalOnly
    Monitor only active physical hardware interfaces.

.PARAMETER CsvPath
    Optional path to append sample results as CSV.

.PARAMETER StormThreshold
    Optional packets-per-second threshold for broadcast or multicast traffic.
    A value of 0 disables storm detection. Default: 0.

.PARAMETER ConsecutiveStormSamples
    Number of consecutive threshold violations required before the state changes
    from ELEVATED to STORM. Default: 2.

.EXAMPLE
    .\NetworkTrafficRateMonitor.ps1

    Monitor all active adapters every five seconds.

.EXAMPLE
    .\NetworkTrafficRateMonitor.ps1 -Name "Ethernet" -IntervalSeconds 2

    Monitor a specific adapter every two seconds.

.EXAMPLE
    .\NetworkTrafficRateMonitor.ps1 -Name "Embedded NIC*","vEthernet*" -Samples 12

    Monitor matching physical and virtual adapters for 12 samples.

.EXAMPLE
    .\NetworkTrafficRateMonitor.ps1 -PhysicalOnly -CsvPath C:\Temp\network-rates.csv

    Monitor active physical adapters and append results to a CSV file.

.EXAMPLE
    .\NetworkTrafficRateMonitor.ps1 -StormThreshold 1000

    Flag an adapter when broadcast or multicast receive traffic reaches
    1,000 packets per second. Two consecutive threshold violations are required
    before the adapter is marked STORM.

.EXAMPLE
    .\NetworkTrafficRateMonitor.ps1 -Name "Ethernet" -StormThreshold 500 -ConsecutiveStormSamples 1

    Flag the specified adapter immediately when broadcast or multicast traffic
    reaches 500 packets per second.

.NOTES
    Author: Philip Stacy
    Requires Windows PowerShell / PowerShell on Windows with the NetAdapter module.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]]$Name,

    [ValidateRange(1, 3600)]
    [int]$IntervalSeconds = 5,

    [ValidateRange(0, 2147483647)]
    [int]$Samples = 0,

    [switch]$PhysicalOnly,

    [string]$CsvPath,

    [ValidateRange(0, 1000000000)]
    [double]$StormThreshold = 0,

    [ValidateRange(1, 100)]
    [int]$ConsecutiveStormSamples = 2
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if (-not (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) -or
    -not (Get-Command Get-NetAdapterStatistics -ErrorAction SilentlyContinue)) {
    throw 'The NetAdapter PowerShell module is required. Run this script on Windows with the NetAdapter module available.'
}

function Resolve-MonitoredAdapters {
    [CmdletBinding()]
    param()

    if ($Name) {
        $resolved = foreach ($pattern in $Name) {
            Get-NetAdapter -Name $pattern -ErrorAction SilentlyContinue
        }

        $resolved = @($resolved | Sort-Object -Property Name -Unique)

        if (-not $resolved) {
            throw "No network adapters matched: $($Name -join ', ')"
        }
    }
    else {
        $resolved = @(Get-NetAdapter | Where-Object Status -eq 'Up')
    }

    if ($PhysicalOnly) {
        $resolved = @($resolved | Where-Object HardwareInterface -eq $true)
    }

    $resolved = @($resolved | Where-Object Status -eq 'Up' | Sort-Object Name)

    if (-not $resolved) {
        throw 'No active network adapters matched the requested criteria.'
    }

    return $resolved
}

function Get-StatisticsSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Adapters
    )

    $snapshot = @{}

    foreach ($adapter in $Adapters) {
        try {
            $snapshot[$adapter.Name] = Get-NetAdapterStatistics -Name $adapter.Name
        }
        catch {
            Write-Warning "Unable to read statistics for '$($adapter.Name)': $($_.Exception.Message)"
        }
    }

    return $snapshot
}

function Get-Rate {
    param(
        [AllowNull()]
        $Before,
        [AllowNull()]
        $After,
        [int]$Seconds
    )

    if ($null -eq $Before -or $null -eq $After) {
        return $null
    }

    $delta = [double]$After - [double]$Before

    # Counters can reset if an adapter is disabled/re-enabled during monitoring.
    if ($delta -lt 0) {
        return $null
    }

    return $delta / $Seconds
}

$adapters = @(Resolve-MonitoredAdapters)
$stormCounts = @{}

foreach ($adapter in $adapters) {
    $stormCounts[$adapter.Name] = 0
}

Write-Host "Monitoring $($adapters.Count) active adapter(s) every $IntervalSeconds second(s). Press Ctrl+C to stop."
Write-Host "Adapters: $($adapters.Name -join ', ')"

if ($StormThreshold -gt 0) {
    Write-Host "Storm detection: enabled at $StormThreshold packets/sec for broadcast OR multicast traffic."
    Write-Host "Storm confirmation: $ConsecutiveStormSamples consecutive sample(s)."
}
else {
    Write-Host 'Storm detection: disabled. Use -StormThreshold <pps> to enable.'
}

Write-Host ''

$sampleNumber = 0

while ($Samples -eq 0 -or $sampleNumber -lt $Samples) {
    $before = Get-StatisticsSnapshot -Adapters $adapters
    Start-Sleep -Seconds $IntervalSeconds
    $after = Get-StatisticsSnapshot -Adapters $adapters

    $timestamp = Get-Date
    $results = foreach ($adapter in $adapters) {
        if (-not $before.ContainsKey($adapter.Name) -or -not $after.ContainsKey($adapter.Name)) {
            continue
        }

        $a = $before[$adapter.Name]
        $b = $after[$adapter.Name]

        $broadcastPps = Get-Rate -Before $a.ReceivedBroadcastPackets -After $b.ReceivedBroadcastPackets -Seconds $IntervalSeconds
        $multicastPps = Get-Rate -Before $a.ReceivedMulticastPackets -After $b.ReceivedMulticastPackets -Seconds $IntervalSeconds
        $unicastPps   = Get-Rate -Before $a.ReceivedUnicastPackets -After $b.ReceivedUnicastPackets -Seconds $IntervalSeconds
        $discardPps   = Get-Rate -Before $a.ReceivedDiscardedPackets -After $b.ReceivedDiscardedPackets -Seconds $IntervalSeconds
        $rxBytesPs    = Get-Rate -Before $a.ReceivedBytes -After $b.ReceivedBytes -Seconds $IntervalSeconds

        $state = 'NORMAL'
        $thresholdExceeded = $false

        if ($StormThreshold -gt 0) {
            if (($null -ne $broadcastPps -and $broadcastPps -ge $StormThreshold) -or
                ($null -ne $multicastPps -and $multicastPps -ge $StormThreshold)) {
                $thresholdExceeded = $true
                $stormCounts[$adapter.Name] = [int]$stormCounts[$adapter.Name] + 1

                if ($stormCounts[$adapter.Name] -ge $ConsecutiveStormSamples) {
                    $state = 'STORM'
                }
                else {
                    $state = 'ELEVATED'
                }
            }
            else {
                $stormCounts[$adapter.Name] = 0
            }
        }

        $result = [PSCustomObject]@{
            Timestamp      = $timestamp.ToString('yyyy-MM-dd HH:mm:ss')
            Adapter        = $adapter.Name
            State          = $state
            BroadcastPps   = if ($null -eq $broadcastPps) { $null } else { [math]::Round($broadcastPps, 1) }
            MulticastPps   = if ($null -eq $multicastPps) { $null } else { [math]::Round($multicastPps, 1) }
            UnicastPps     = if ($null -eq $unicastPps)   { $null } else { [math]::Round($unicastPps, 1) }
            RxMbps         = if ($null -eq $rxBytesPs)    { $null } else { [math]::Round(($rxBytesPs * 8) / 1MB, 2) }
            DiscardedPps   = if ($null -eq $discardPps)   { $null } else { [math]::Round($discardPps, 1) }
        }

        if ($state -eq 'STORM') {
            Write-Warning ("NETWORK STORM DETECTED on '{0}' | Broadcast: {1:N1} pps | Multicast: {2:N1} pps | Threshold: {3:N1} pps" -f `
                $adapter.Name, $broadcastPps, $multicastPps, $StormThreshold)
        }
        elseif ($thresholdExceeded) {
            Write-Warning ("Elevated Layer-2 traffic on '{0}' | Broadcast: {1:N1} pps | Multicast: {2:N1} pps | Confirmation sample {3}/{4}" -f `
                $adapter.Name, $broadcastPps, $multicastPps, $stormCounts[$adapter.Name], $ConsecutiveStormSamples)
        }

        $result
    }

    if ($results) {
        $results |
            Format-Table -Property Timestamp, Adapter, State, BroadcastPps, MulticastPps, UnicastPps, RxMbps, DiscardedPps -AutoSize |
            Out-String -Width 260 |
            Write-Host

        if ($CsvPath) {
            $parent = Split-Path -Parent $CsvPath
            if ($parent -and -not (Test-Path $parent)) {
                New-Item -ItemType Directory -Path $parent -Force | Out-Null
            }

            $results | Export-Csv -Path $CsvPath -NoTypeInformation -Append
        }
    }

    $sampleNumber++

    # Refresh adapter status between samples so a disconnected adapter does not
    # cause the monitor to fail indefinitely.
    $adapters = @($adapters | Where-Object {
        (Get-NetAdapter -Name $_.Name -ErrorAction SilentlyContinue).Status -eq 'Up'
    })

    if (-not $adapters) {
        Write-Warning 'All monitored adapters are down or unavailable. Stopping.'
        break
    }

    foreach ($adapter in $adapters) {
        if (-not $stormCounts.ContainsKey($adapter.Name)) {
            $stormCounts[$adapter.Name] = 0
        }
    }
}
