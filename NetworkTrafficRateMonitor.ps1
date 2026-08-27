<#
.SYNOPSIS
    Monitors live Windows network adapter packet rates.

.DESCRIPTION
    Samples Get-NetAdapterStatistics at a configurable interval and calculates
    receive rates for broadcast, multicast, unicast, discarded packets, and
    receive throughput.

    By default, all active network adapters are monitored. Use -Name to target
    one or more adapters, including wildcard names, or -PhysicalOnly to exclude
    virtual adapters.

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

    [string]$CsvPath
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

Write-Host "Monitoring $($adapters.Count) active adapter(s) every $IntervalSeconds second(s). Press Ctrl+C to stop."
Write-Host "Adapters: $($adapters.Name -join ', ')"
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

        [PSCustomObject]@{
            Timestamp      = $timestamp.ToString('yyyy-MM-dd HH:mm:ss')
            Adapter        = $adapter.Name
            BroadcastPps   = if ($null -eq $broadcastPps) { $null } else { [math]::Round($broadcastPps, 1) }
            MulticastPps   = if ($null -eq $multicastPps) { $null } else { [math]::Round($multicastPps, 1) }
            UnicastPps     = if ($null -eq $unicastPps)   { $null } else { [math]::Round($unicastPps, 1) }
            RxMbps         = if ($null -eq $rxBytesPs)    { $null } else { [math]::Round(($rxBytesPs * 8) / 1MB, 2) }
            DiscardedPps   = if ($null -eq $discardPps)   { $null } else { [math]::Round($discardPps, 1) }
        }
    }

    if ($results) {
        $results |
            Format-Table -Property Timestamp, Adapter, BroadcastPps, MulticastPps, UnicastPps, RxMbps, DiscardedPps -AutoSize |
            Out-String -Width 240 |
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
}
