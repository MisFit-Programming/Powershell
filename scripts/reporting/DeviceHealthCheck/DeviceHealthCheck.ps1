<#
.SYNOPSIS
Read-only Windows assessment for Datto RMM; native IT Glue Documents publisher.
.DESCRIPTION
Single-file component. Parser floor: Windows PowerShell 2.0; full engine: 5.1.
No dependencies are installed. Only explicit -ReportPath writes a local file.
Dot-sourcing loads functions only, for offline tests. See README.md before rollout.
#>
[CmdletBinding()]
param([switch]$SkipUpload, [string]$ReportPath, [string]$APIEndpoint)

function Initialize-HealthEngine {
    $script:EngineVersion = '1.0.2'
    $script:SupportMatrixLastUpdated = '2026-10-06'
    $script:Results = New-Object System.Collections.ArrayList
    $script:Roles = @()
    $script:TimedOutProbes = 0
    $script:AbandonedPipelines = New-Object System.Collections.ArrayList
    $script:Weights = @{Identity=2; Hardware=3; Storage=5; Windows=4; Patch=4; Security=4; Network=3; Events=3; Roles=5; Runtime=5}
    $script:Credit = @{PASS=1.0; INFO=1.0; WARNING=0.5; CRITICAL=0.0; UNKNOWN=0.0; UNSUPPORTED=0.0; 'NOT APPLICABLE'=0.0}
    $script:Severity = @{PASS=0; INFO=0; WARNING=2; CRITICAL=3; UNKNOWN=1; UNSUPPORTED=1; 'NOT APPLICABLE'=0}
    $script:Secret = [string]$env:strITGLUE
}

function Protect-Text {
    param($Value, [int]$Limit=4000)
    $s = [string]$Value
    if ($script:Secret) {
        foreach ($form in @($script:Secret,[uri]::EscapeDataString($script:Secret),$script:Secret.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;'))) { $s=$s.Replace($form,'[REDACTED]') }
    }
    $s = $s -replace '(?i)ITG\.[A-Za-z0-9._-]+','[REDACTED]'
    $s = $s -replace '(?i)(password|secret|token|authorization|x-api-key)\s*[:=]\s*\S+','$1=[REDACTED]'
    $s = $s -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]',' '
    if ($s.Length -gt $Limit) { $s = $s.Substring(0,$Limit) + ' [truncated]' }
    return $s
}
function ConvertTo-HtmlText {
    param($Value)
    $s = Protect-Text $Value 16000
    return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}
function Write-Phase { param([string]$Message) Write-Host ('[DHC] ' + (Protect-Text $Message)) }
function Get-HealthConfiguration {
    # name => default, minimum, maximum; all overrides must be invariant integers.
    $spec = @{
        EventDays=@(7,1,90); MaxEventGroups=@(25,1,100); DiskWarningPercent=@(15,1,99); DiskCriticalPercent=@(10,1,99)
        DiskWarningGB=@(20,1,1000); DiskCriticalGB=@(10,1,1000); DiskEmergencyGB=@(2,1,100)
        UptimeWarningDays=@(45,1,3650); UptimeCriticalDays=@(90,1,3650)
        PatchWarningDays=@(45,1,3650); PatchCriticalDays=@(90,1,3650)
        TimeWarningSeconds=@(120,1,86400); TimeCriticalSeconds=@(300,1,86400)
        MinimumCoverage=@(80,1,100); ProbeTimeoutSeconds=@(25,5,120); MaxEventsPerLog=@(2000,100,10000)
    }
    $cfg = @{}
    foreach ($name in $spec.Keys) {
        $raw = [Environment]::GetEnvironmentVariable('DHC_' + $name)
        $v = [int]$spec[$name][0]
        if ($raw) {
            $parsed = 0
            if ($raw -notmatch '^\d+$' -or -not [int]::TryParse($raw,[ref]$parsed) -or $parsed -lt $spec[$name][1] -or $parsed -gt $spec[$name][2]) {
                throw ('Invalid DHC_' + $name + '; expected integer ' + $spec[$name][1] + '..' + $spec[$name][2] + '.')
            }
            $v = $parsed
        }
        $cfg[$name] = $v
    }
    if ($cfg.DiskCriticalPercent -ge $cfg.DiskWarningPercent -or $cfg.DiskCriticalGB -ge $cfg.DiskWarningGB -or $cfg.DiskEmergencyGB -gt $cfg.DiskCriticalGB) { throw 'Disk thresholds are inconsistent.' }
    foreach ($pair in @(@('UptimeWarningDays','UptimeCriticalDays'),@('PatchWarningDays','PatchCriticalDays'),@('TimeWarningSeconds','TimeCriticalSeconds'))) {
        if ($cfg[$pair[0]] -ge $cfg[$pair[1]]) { throw ('Threshold order invalid: ' + $pair[0]) }
    }
    return $cfg
}
function Get-RuntimeDecision {
    param([version]$Version,[int]$PointerSize,[string]$Wow64)
    if ($Version -lt (New-Object Version(5,1))) { return 'Legacy' }
    if ($PointerSize -eq 4 -and $Wow64) { return 'Degraded32Bit' }
    return 'Full'
}
function New-Observation {
    param([string]$Name,[string]$Status,[string]$Summary,$Evidence='', [string]$Recommendation='')
    @{Name=$Name; Status=$Status; Summary=$Summary; Evidence=$Evidence; Recommendation=$Recommendation}
}
function Add-HealthCheckResult {
    param([string]$Category,[string]$Subcategory,[string]$CheckName,[string]$Status,[string]$Summary,$Evidence='', [string]$Recommendation='', [string]$Source='', [bool]$Required=$false,[double]$Weight=1)
    if (-not $script:Credit.ContainsKey($Status)) { throw 'Invalid health result state.' }
    $success = @('PASS','INFO','WARNING','CRITICAL','NOT APPLICABLE') -contains $Status
    [void]$script:Results.Add((New-Object PSObject -Property @{
        Category=$Category; Subcategory=$Subcategory; CheckName=(Protect-Text $CheckName); Status=$Status
        Severity=$script:Severity[$Status]; Weight=$Weight; Required=$Required; Applicable=($Status -ne 'NOT APPLICABLE')
        Summary=(Protect-Text $Summary); Evidence=(Protect-Text $Evidence 12000); Recommendation=(Protect-Text $Recommendation)
        Source=$Source; CollectionTime=[DateTime]::UtcNow.ToString('o'); CollectionSucceeded=$success; EventGroups=@(); EventGroupCount=0
    }))
}
function Get-DiskStatus {
    param([double]$Size,[double]$Free,$Config)
    if ($Size -le 0 -or $Free -lt 0 -or $Free -gt $Size) { return 'UNKNOWN' }
    $pct=100*$Free/$Size; $gb=$Free/1GB
    # Never demand more emergency free space than the critical percentage of a small volume.
    # Applies to all volumes, without guessing that an unlettered volume is EFI/recovery.
    $emergencyGB=[math]::Min($Config.DiskEmergencyGB,($Size/1GB)*$Config.DiskCriticalPercent/100)
    if ($gb -lt $emergencyGB -or ($pct -lt $Config.DiskCriticalPercent -and $gb -lt $Config.DiskCriticalGB)) { return 'CRITICAL' }
    if ($pct -lt $Config.DiskWarningPercent -and $gb -lt $Config.DiskWarningGB) { return 'WARNING' }
    return 'PASS'
}
function Get-AgeStatus {
    param([double]$Age,[double]$Warning,[double]$Critical)
    if ($Age -lt 0) { return 'UNKNOWN' }
    if ($Age -ge $Critical) { return 'CRITICAL' }; if ($Age -ge $Warning) { return 'WARNING' }; return 'PASS'
}
function Get-CpuSampleObservation {
    $samples=@(); $provider='Win32_PerfFormattedData_PerfOS_Processor'
    try {
        for ($i=0;$i -lt 3;$i++) {
            $p=@(Get-ReadOnlyWmi Win32_PerfFormattedData_PerfOS_Processor "Name='_Total'")
            if ($p.Count -ne 1 -or $null -eq $p[0].PercentProcessorTime -or $p[0].PercentProcessorTime -lt 0 -or $p[0].PercentProcessorTime -gt 100) { throw 'Invalid CPU sample.' }
            $samples += [double]$p[0].PercentProcessorTime
            if ($i -lt 2) { Start-Sleep -Seconds 1 }
        }
    } catch {
        $samples=@(); $provider='Win32_Processor.LoadPercentage (fallback; logical-processor weighted)'
        for ($i=0;$i -lt 3;$i++) {
            $p=@(Get-ReadOnlyWmi Win32_Processor '' 'root\cimv2' 'LoadPercentage,NumberOfLogicalProcessors')
            if (-not $p.Count) { throw 'No fallback CPU data.' }
            $weighted=0.0; $count=0.0
            foreach ($cpu in $p) {
                if ($null -eq $cpu.LoadPercentage -or $cpu.LoadPercentage -lt 0 -or $cpu.LoadPercentage -gt 100 -or $cpu.NumberOfLogicalProcessors -le 0) { throw 'Invalid fallback CPU sample.' }
                $weighted += [double]$cpu.LoadPercentage*[double]$cpu.NumberOfLogicalProcessors
                $count += [double]$cpu.NumberOfLogicalProcessors
            }
            $samples += $weighted/$count
            if ($i -lt 2) { Start-Sleep -Seconds 1 }
        }
    }
    $avg=($samples | Measure-Object -Average).Average; $state='PASS'
    if (($samples | Measure-Object -Minimum).Minimum -ge 90) { $state='WARNING' }
    New-Observation 'Short CPU sample' $state ('Three-sample average: '+[math]::Round($avg,1)+'%') ('Provider='+$provider+'; One-second interval samples: '+($samples -join ', ')) 'Confirm sustained load with monitoring before capacity or process changes.'
}
function Get-ReadOnlyWmi {
    param([string]$Class,[string]$Filter='', [string]$Namespace='root\cimv2', [string]$Properties='*')
    # Local WMI only. Never Win32_Product; never InvokeMethod. Enumeration timeout is finite.
    if ($Class -notmatch '^[A-Za-z0-9_]+$' -or $Class -eq 'Win32_Product') { throw 'Disallowed WMI class.' }
    $scope = New-Object System.Management.ManagementScope(('\\.\' + $Namespace))
    $scope.Options.Timeout = [TimeSpan]::FromSeconds(10)
    $query = 'SELECT ' + $Properties + ' FROM ' + $Class
    if ($Filter) { $query += ' WHERE ' + $Filter }
    $opts = New-Object System.Management.EnumerationOptions
    $opts.Timeout=[TimeSpan]::FromSeconds(10); $opts.ReturnImmediately=$true; $opts.Rewindable=$false
    $searcher = New-Object System.Management.ManagementObjectSearcher($scope,(New-Object System.Management.ObjectQuery($query)),$opts)
    try {
        $items=$searcher.Get()
        try {
            $count=0
            foreach ($item in $items) {
                $count++; if ($count -gt 2000) { throw 'WMI row safety limit reached.' }
                $row=@{}; foreach ($p in $item.Properties) { $row[$p.Name]=$p.Value }
                New-Object PSObject -Property $row
                $item.Dispose()
            }
        } finally { if ($items) { $items.Dispose() } }
    } finally { $searcher.Dispose() }
}
function Get-ReadRegistry {
    param([string]$Path,[string]$Name)
    # Explicitly open read-only in current registry view; 32-bit execution is blocked below.
    $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path,$false)
    if (-not $key) { return $null }
    try { return $key.GetValue($Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } finally { $key.Close() }
}
function Test-ReadRegistryKey {
    param([string]$Path)
    $k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path,$false)
    if (-not $k) { return $false }; $k.Close(); return $true
}
function Get-EvidenceText {
    param($Rows,[string[]]$Properties,[int]$Limit=80)
    $all=@($Rows); $lines=@()
    foreach ($row in @($all | Select-Object -First $Limit)) {
        $parts=@(); foreach ($p in $Properties) { $parts += ($p + '=' + (@($row.$p) -join ', ')) }; $lines += ($parts -join '; ')
    }
    if ($all.Count -gt $Limit) { $lines += ('Additional rows omitted: ' + ($all.Count-$Limit)) }
    return ($lines -join "`n")
}
function Require-Command {
    param([string]$Name,[string]$Module='')
    if ($Module) {
        if (-not (Get-Module -ListAvailable -Name $Module -ErrorAction Stop)) { throw ('UNSUPPORTED: installed module unavailable: ' + $Module) }
        Import-Module $Module -ErrorAction Stop -WarningAction SilentlyContinue
    }
    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) { throw ('UNSUPPORTED: command unavailable: ' + $Name) }
}
function Invoke-ReadOnlyNative {
    param([string]$Name,[string]$Arguments)
    # A closed allowlist: no caller-controlled diagnostic switches or arbitrary executables.
    $allowed=@{'w32tm.exe'=@('/query /status /verbose','/query /source')}
    if (-not $allowed.ContainsKey($Name) -or $allowed[$Name] -notcontains $Arguments) { throw 'Native command is not read-only allowlisted.' }
    $path=Join-Path ([Environment]::GetFolderPath('System')) $Name
    if (-not [IO.File]::Exists($path)) { throw 'UNSUPPORTED: native reader unavailable.' }
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$path; $start.Arguments=$Arguments; $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
    $process=New-Object Diagnostics.Process; $process.StartInfo=$start
    try {
        [void]$process.Start()
        # Async reads avoid pipe-buffer deadlock. Full engine uses .NET 4.5+ only.
        $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10000)) { $process.Kill(); throw 'Native read-only query timed out.' }
        if ($process.ExitCode -ne 0) { throw 'Native read-only query failed.' }
        $text=$stdout.Result
        if ($text.Length -gt 16000) { throw 'Native output exceeded size bound.' }
        return $text
    } finally { $process.Dispose() }
}
function Get-ProbePrelude {
    $text=''
    foreach ($name in @('New-Observation','Get-DiskStatus','Get-AgeStatus','Get-CpuSampleObservation','Get-ReadOnlyWmi','Get-ReadRegistry','Test-ReadRegistryKey','Get-EvidenceText','Require-Command','Invoke-ReadOnlyNative','Read-CuratedEvents')) {
        $text += "function $name {`n" + (Get-Item ('function:' + $name)).Definition + "`n}`n"
    }
    return $text
}
function Invoke-HealthProbe {
    param([string]$Category,[string]$Name,[scriptblock]$Body,[bool]$Required=$false,$Context=@{},[int]$Timeout=0)
    if (-not $Timeout) { $Timeout=$script:Config.ProbeTimeoutSeconds }
    $rows=@(); $ps=$null; $abandoned=$false
    try {
        if ($script:TimedOutProbes -ge 3) { throw 'Collection safety circuit open after three timeouts.' }
        $ps=[Management.Automation.PowerShell]::Create()
        $code='param($cfg,$ctx) $ErrorActionPreference="Stop";' + (Get-ProbePrelude) + "`ntry {`n" + $Body.ToString() + @'

} catch {
    $state='UNKNOWN'
    if ($_.Exception.Message -match 'UNSUPPORTED:') { $state='UNSUPPORTED' }
    $reason='Provider/query unavailable'
    if ($_.Exception -is [UnauthorizedAccessException]) { $reason='Access denied' }
    if ($_.Exception -is [Management.ManagementException]) {
        if (@('InvalidClass','InvalidNamespace','NotSupported') -contains [string]$_.Exception.ErrorCode) { $state='UNSUPPORTED'; $reason='WMI capability unavailable' }
        if ([string]$_.Exception.ErrorCode -eq 'AccessDenied') { $reason='Access denied' }
    }
    New-Observation 'Collection incomplete' $state $reason ('Failure type: '+$_.Exception.GetType().Name) 'Check privileges, installed capabilities and provider availability; rerun the assessment.'
}
'@
        [void]$ps.AddScript($code).AddArgument($script:Config).AddArgument($Context)
        $async=$ps.BeginInvoke()
        if (-not $async.AsyncWaitHandle.WaitOne($Timeout*1000)) {
            $script:TimedOutProbes++; $abandoned=$true
            [void]$ps.BeginStop($null,$null); [void]$script:AbandonedPipelines.Add($ps)
            throw 'Probe exceeded its deadline; results discarded.'
        }
        $rows=@($ps.EndInvoke($async))
        # HadErrors also remembers caught provider errors after a successful fallback.
        # The wrapper uses ErrorAction=Stop and emits a failure observation for every
        # unhandled collection error; validate those observations, not that sticky flag.
        if (-not $rows.Count) { throw 'Probe returned no observations.' }
        foreach ($r in $rows) { if (-not $r.Name -or -not $script:Credit.ContainsKey([string]$r.Status)) { throw 'Invalid probe output.' } }
    } catch {
        $state='UNKNOWN'; if ($_.Exception.Message -match 'UNSUPPORTED:') { $state='UNSUPPORTED' }
        # Completed observations remain useful; never discard an earlier critical finding merely
        # because a later query in the same domain failed. Timed-out pipeline output is discarded.
        $valid=@($rows | Where-Object {$_.Name -and $script:Credit.ContainsKey([string]$_.Status)})
        $rows=$valid + @(New-Observation $Name $state 'Collection unavailable; this is not a healthy result.' ('Failure type: ' + $_.Exception.GetType().Name) 'Check permissions, installed capabilities and provider availability; rerun the assessment.')
    } finally { if ($ps -and -not $abandoned) { $ps.Dispose() } }
    # A probe has a fixed weight; devices with more disks/services do not dilute other domains.
    $weight=[double]$script:Weights[$Category]/[math]::Max(1,$rows.Count)
    foreach ($r in $rows) {
        Add-HealthCheckResult $Category $Name $r.Name $r.Status $r.Summary $r.Evidence $r.Recommendation $Name $Required $weight
        if ($r.EventGroups) { $script:Results[$script:Results.Count-1].EventGroups=@($r.EventGroups) }
        if ($r.EventGroupCount) { $script:Results[$script:Results.Count-1].EventGroupCount=[int]$r.EventGroupCount }
    }
}
function Get-AssessmentScore {
    param($Results,[int]$MinimumCoverage=80)
    $total=0.0; $covered=0.0; $earned=0.0; $missing=@(); $critical=0; $warnings=0; $unknown=0
    foreach ($r in $Results) {
        if (-not $r.Applicable) { continue }
        $total += $r.Weight
        if ($r.CollectionSucceeded) { $covered += $r.Weight }
        elseif ($r.Required) { $missing += $r.Subcategory }
        $earned += $r.Weight * $script:Credit[$r.Status]
        if ($r.Status -eq 'CRITICAL') { $critical++ }; if ($r.Status -eq 'WARNING') { $warnings++ }
        if (@('UNKNOWN','UNSUPPORTED') -contains $r.Status) { $unknown++ }
    }
    $coverage=0.0; $score=0
    if ($total -gt 0) { $coverage=100*$covered/$total; $score=[math]::Floor(100*$earned/$total) }
    $incomplete=($total -eq 0 -or $coverage -lt $MinimumCoverage -or $missing.Count -gt 0)
    $status='Healthy'
    if ($score -lt 90) { $status='Attention Required' }; if ($score -lt 75) { $status='At Risk' }; if ($score -lt 50 -or $critical -gt 0) { $status='Critical' }
    $official=[string]$score; if ($incomplete) { $status='Unable to Assess'; $official='Withheld' }
    return @{Status=$status; Score=$official; Coverage=[math]::Round($coverage,1); Incomplete=$incomplete; Missing=@($missing | Select-Object -Unique); Critical=$critical; Warnings=$warnings; Unknown=$unknown}
}

function Read-CuratedEvents {
    param([string]$Log,[string]$Provider='')
    $filter=@{LogName=$Log; StartTime=[DateTime]::Now.AddDays(-$cfg.EventDays); Level=@(1,2,3)}
    if ($Provider) { $filter.ProviderName=$Provider }
    try { $events=@(Get-WinEvent -FilterHashtable $filter -MaxEvents ($cfg.MaxEventsPerLog+1) -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events=@() } else { throw } }
    $capped=$events.Count -gt $cfg.MaxEventsPerLog
    $events=@($events | Select-Object -First $cfg.MaxEventsPerLog)
    # DCOM 10016 is expected permission noise on supported Windows; no permission remediation.
    $events=@($events | Where-Object { -not ($_.ProviderName -eq 'Microsoft-Windows-DistributedCOM' -and $_.Id -eq 10016) })
    $groups=@($events | Group-Object LogName,ProviderName,Id,Level | Sort-Object @{Expression={($_.Group | Measure-Object Level -Minimum).Minimum}},@{Expression={($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated};Descending=$true},@{Expression={$_.Count};Descending=$true})
    $details=@(); $worst='PASS'; $groupRows=@()
    foreach ($g in $groups) {
        $first=$g.Group | Sort-Object TimeCreated | Select-Object -First 1
        $last=$g.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
        # No raw event payload/message: these can contain usernames, document names or secrets.
        $summary='Windows logged a warning/error; inspect the referenced event locally for context.'
        if ($last.ProviderName -match 'disk|storport|stornvme|Ntfs') { $summary='Storage provider reported an error or warning. Investigate device, controller and filesystem evidence.' }
        if ($last.Id -eq 41 -and $last.ProviderName -eq 'Microsoft-Windows-Kernel-Power') { $summary='Unexpected restart recorded; this does not establish its cause.' }
        $groupRows += @{Log=$Log;Provider=$last.ProviderName;EventID=$last.Id;Level=$last.Level;Count=$g.Count;First=$first.TimeCreated.ToString('o');Last=$last.TimeCreated.ToString('o');Summary=$summary;Action='Inspect the referenced local events and correlate with monitoring; no root cause is inferred.'}
        if ($worst -eq 'PASS') { $worst='WARNING' }
        if ($last.Level -eq 1 -or ($last.ProviderName -match '^(disk|Ntfs|storport|stornvme)$' -and $g.Count -ge 3)) { $worst='CRITICAL' }
    }
    if ($capped) { $details += 'Event query reached its cap. Counts and first/last times cover only the sampled recent events.' }
    $observation=New-Observation $Log $worst ('Curated warning/error groups: ' + $groups.Count) ($details -join "`n") 'Review grouped events in context; an event ID alone does not establish root cause.'
    $observation.EventGroups=@($groupRows | Select-Object -First $cfg.MaxEventGroups); $observation.EventGroupCount=$groups.Count
    $observation
    if ($capped) { New-Observation ($Log+' coverage') 'UNKNOWN' 'Event volume exceeded the collection cap.' '' 'Review this log directly or shorten the lookback.' }
}
function Get-LifecycleObservation {
    param($OS,$Edition,[datetime]$Now=[DateTime]::UtcNow)
    # Deliberately narrow: known standard server releases and legacy clients only.
    # ESU entitlement is never inferred; unknown editions/channels remain UNKNOWN.
    $end=$null; $label='Unknown release or servicing channel'
    $build=[string]$OS.BuildNumber; $server=([int]$OS.ProductType -gt 1)
    if ($server -and [string]$Edition -match '^(ServerStandard|ServerDatacenter|ServerStandardCore|ServerDatacenterCore)$') {
        $matrix=@{'7601'='2020-01-14';'9200'='2023-10-10';'9600'='2023-10-10';'14393'='2027-01-12';'17763'='2029-01-09';'20348'='2031-10-14';'26100'='2034-11-14'}
        if ($matrix.ContainsKey($build)) { $end=[datetime]::ParseExact($matrix[$build],'yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture); $label='Standard server extended support' }
    } elseif (-not $server -and [string]$Edition -match '^(Professional|Enterprise|Ultimate|HomePremium|HomeBasic|Core)$') {
        $matrix=@{'7601'='2020-01-14';'9200'='2016-01-12';'9600'='2023-01-10'}
        if ($matrix.ContainsKey($build)) { $end=[datetime]::ParseExact($matrix[$build],'yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture); $label='Legacy client extended support' }
    }
    if (-not $end) { return (New-Observation 'OS lifecycle' 'UNKNOWN' $label ('Build='+$build+'; Edition='+$Edition) 'Verify Microsoft lifecycle for this exact edition and servicing channel.') }
    $state='INFO'; if ($Now.Date -gt $end.Date) { $state='WARNING' }
    New-Observation 'OS lifecycle' $state ($label+' ends '+$end.ToString('yyyy-MM-dd')) 'ESU entitlement and servicing compliance are not determined by this matrix.' 'Verify support entitlement and plan lifecycle changes through the normal change process.'
}
function Get-BaselineHealth {
    Write-Phase 'Collecting baseline health'
    Invoke-HealthProbe Identity 'System identity' {
        $os=@(Get-ReadOnlyWmi Win32_OperatingSystem)[0]; $cs=@(Get-ReadOnlyWmi Win32_ComputerSystem)[0]; $bios=@(Get-ReadOnlyWmi Win32_BIOS)[0]
        if (-not $os.Caption -or -not $cs.Name) { throw 'Missing identity.' }
        $vm='Physical or undetermined'; if (($cs.Manufacturer+' '+$cs.Model) -match 'Virtual|VMware|KVM|Xen|HVM|Bochs|QEMU') { $vm='Virtual machine indicator detected' }
        New-Observation 'System overview' 'INFO' ($os.Caption+'; '+$vm) ((Get-EvidenceText @($cs) @('Name','Domain','PartOfDomain','DomainRole','Manufacturer','Model','TotalPhysicalMemory'))+"`n"+(Get-EvidenceText @($os) @('Caption','Version','BuildNumber','OSArchitecture','InstallDate','LastBootUpTime','ProductType'))+"`n"+(Get-EvidenceText @($bios) @('SerialNumber','SMBIOSBIOSVersion','ReleaseDate')))
    } $true
    Invoke-HealthProbe Hardware 'CPU and memory' {
        $cpu=@(Get-ReadOnlyWmi Win32_Processor); $os=@(Get-ReadOnlyWmi Win32_OperatingSystem)[0]
        if (-not $cpu.Count -or $os.TotalVisibleMemorySize -le 0 -or $null -eq $os.FreePhysicalMemory) { throw 'Missing hardware data.' }
        $memory=100*(1-[double]$os.FreePhysicalMemory/[double]$os.TotalVisibleMemorySize)
        $state='PASS'; if ($memory -ge 90) { $state='WARNING' }
        New-Observation 'Memory pressure' $state ('Physical memory used: '+[math]::Round($memory,1)+'%') (Get-EvidenceText @($os) @('TotalVisibleMemorySize','FreePhysicalMemory','TotalVirtualMemorySize','FreeVirtualMemory')) 'If sustained, review memory consumers and paging; this is a short observation.'
        New-Observation 'Processor inventory' 'INFO' 'Processor models and topology.' (Get-EvidenceText $cpu @('Name','NumberOfCores','NumberOfLogicalProcessors'))
        Get-CpuSampleObservation
    } $true
    Invoke-HealthProbe Hardware 'Page file' {
        $p=@(Get-ReadOnlyWmi Win32_PageFileUsage)
        New-Observation 'Page file indicators' 'INFO' ('Page files reported: '+$p.Count) (Get-EvidenceText $p @('Name','AllocatedBaseSize','CurrentUsage','PeakUsage'))
    }
    Invoke-HealthProbe Storage 'Volume capacity' {
        $os=@(Get-ReadOnlyWmi Win32_OperatingSystem)[0]; $vol=@(Get-ReadOnlyWmi Win32_Volume 'DriveType=3')
        if (-not $vol.Count) { throw 'No fixed volumes returned.' }
        foreach ($v in $vol) {
            $state='UNKNOWN'; $pct='Unknown'
            if ($null -ne $v.FreeSpace -and $v.Capacity -gt 0) { $state=Get-DiskStatus $v.Capacity $v.FreeSpace $cfg; $pct=[math]::Round(100*$v.FreeSpace/$v.Capacity,1) }
            New-Observation ([string]$v.Name) $state ('Free: '+[math]::Round($v.FreeSpace/1GB,2)+' GB / '+$pct+'%') ('SizeGB='+[math]::Round($v.Capacity/1GB,2)+'; UsedGB='+[math]::Round(($v.Capacity-$v.FreeSpace)/1GB,2)+'; FileSystem='+$v.FileSystem+'; SystemVolume='+($v.DriveLetter -eq $os.SystemDrive)) 'Review growth and capacity for constrained volumes.'
        }
    } $true
    Invoke-HealthProbe Storage 'Physical disks' {
        $d=@(Get-ReadOnlyWmi Win32_DiskDrive)
        if (-not $d.Count) { throw 'No physical disk evidence.' }
        New-Observation 'Disk models' 'INFO' 'Windows disk inventory; Status alone is not SMART assurance.' (Get-EvidenceText $d @('Model','InterfaceType','Size','Status'))
    }
    Invoke-HealthProbe Storage 'Modern storage health' {
        Require-Command Get-PhysicalDisk Storage
        $disks=@(Get-PhysicalDisk -ErrorAction Stop)
        if (-not $disks.Count) { throw 'No modern storage health data.' }
        foreach ($d in $disks) {
            $state='UNKNOWN'
            if ([string]$d.HealthStatus -eq 'Healthy') { $state='PASS' }
            elseif ([string]$d.HealthStatus -eq 'Warning') { $state='WARNING' }
            elseif ([string]$d.HealthStatus -eq 'Unhealthy') { $state='CRITICAL' }
            New-Observation ([string]$d.FriendlyName) $state 'Windows storage provider health; hardware controller coverage may differ.' (Get-EvidenceText @($d) @('FriendlyName','MediaType','HealthStatus','OperationalStatus','Size')) 'Investigate abnormal storage status and correlate with controller monitoring.'
        }
    }
    Invoke-HealthProbe Storage 'SMART predictive failure' {
        $d=@(Get-ReadOnlyWmi MSStorageDriver_FailurePredictStatus '' 'root\wmi')
        if (-not $d.Count) { throw 'UNSUPPORTED: no predictive failure provider.' }
        foreach ($v in $d) {
            if ($null -eq $v.PredictFailure) { throw 'Missing prediction.' }
            $state='PASS'; if ($v.PredictFailure) { $state='CRITICAL' }
            New-Observation ([string]$v.InstanceName) $state ('PredictFailure='+$v.PredictFailure) ('Reason='+$v.Reason) 'Investigate predicted storage failure immediately; validate backup coverage.'
        }
    }
    Invoke-HealthProbe Windows 'Uptime' {
        $os=@(Get-ReadOnlyWmi Win32_OperatingSystem)[0]
        $boot=[Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
        $days=([DateTime]::Now-$boot).TotalDays
        New-Observation 'Uptime' (Get-AgeStatus $days $cfg.UptimeWarningDays $cfg.UptimeCriticalDays) ([math]::Round($days,1).ToString()+' days') ('Boot='+$boot.ToString('o')) 'Review reboot requirements and maintenance scheduling; no reboot was attempted.'
    }
    Invoke-HealthProbe Windows 'Critical services' {
        foreach ($name in @('RpcSs','DcomLaunch','EventLog','Winmgmt','BFE','MpsSvc')) {
            $s=@(Get-ReadOnlyWmi Win32_Service ("Name='"+$name+"'"))
            if ($s.Count -ne 1) { New-Observation $name 'UNKNOWN' 'Expected service metadata unavailable.'; continue }
            $state='PASS'; if ($s[0].State -ne 'Running') { $state='CRITICAL' }
            New-Observation $name $state ('State='+$s[0].State+'; StartMode='+$s[0].StartMode) '' 'Investigate why the critical service is stopped before making changes.'
        }
    } $true
    Invoke-HealthProbe Patch 'Pending reboot' {
        $reasons=@()
        foreach ($p in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) { if (Test-ReadRegistryKey $p) { $reasons += $p } }
        if (Get-ReadRegistry 'SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations') { $reasons += 'Pending file rename operations (paths intentionally omitted)' }
        $a=Get-ReadRegistry 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' 'ComputerName'
        $b=Get-ReadRegistry 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' 'ComputerName'
        if ($a -and $b -and $a -ne $b) { $reasons += 'Pending computer rename' }
        $state='PASS'; if ($reasons.Count) { $state='WARNING' }
        New-Observation 'Reboot indicators' $state ('Indicators found: '+$reasons.Count) ($reasons -join '; ') 'Correlate with the patch tool and schedule maintenance if a restart is required.'
    } $true
    Invoke-HealthProbe Patch 'Installed update evidence' {
        $q=@(Get-ReadOnlyWmi Win32_QuickFixEngineering)
        $dated=@()
        foreach ($u in $q) {
            $date=[datetime]::MinValue
            if ($u.InstalledOn -and [datetime]::TryParse([string]$u.InstalledOn,[ref]$date) -and $date -le [datetime]::Now -and $date.Year -gt 2000) { $dated += New-Object PSObject -Property @{ID=$u.HotFixID; Date=$date; Description=$u.Description} }
        }
        if (-not $dated.Count) { throw 'No reliable installed update dates.' }
        $last=$dated | Sort-Object Date -Descending | Select-Object -First 1
        $age=([datetime]::Now-$last.Date).TotalDays
        New-Observation 'Latest installed CBS/QFE update evidence' (Get-AgeStatus $age $cfg.PatchWarningDays $cfg.PatchCriticalDays) ('Latest evidence '+$last.ID+'; '+[math]::Floor($age)+' days old') (Get-EvidenceText @($dated | Sort-Object Date -Descending | Select-Object -First 5) @('ID','Date','Description')) 'Verify quality/security update compliance in the patch-management system. QFE evidence is incomplete and does not prove all applicable patches are installed.'
    } $true
    Invoke-HealthProbe Patch 'Patch management configuration' {
        $s=@(Get-ReadOnlyWmi Win32_Service "Name='wuauserv'")
        $wsus=Get-ReadRegistry 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUServer'
        New-Observation 'Windows Update configuration' 'INFO' 'Observed configuration only; no update scan initiated.' ((Get-EvidenceText $s @('Name','State','StartMode'))+'; WSUS='+$wsus+'; UseWUServer='+(Get-ReadRegistry 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'UseWUServer')+'; NoAutoUpdate='+(Get-ReadRegistry 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate')+'; DattoAgentService='+(@(Get-ReadOnlyWmi Win32_Service "Name='CagService'").Count -gt 0))
    }
    Get-SecurityHealth
    Get-NetworkHealth
    foreach ($log in @('System','Application')) { Invoke-HealthProbe Events $log { Read-CuratedEvents $ctx.Log } $true @{Log=$log} }
}

function Get-SecurityHealth {
    Invoke-HealthProbe Security 'Endpoint protection' {
        $os=@(Get-ReadOnlyWmi Win32_OperatingSystem)[0]
        $evidence=@(); $state='UNKNOWN'
        if ([int]$os.ProductType -eq 1) {
            $av=@(Get-ReadOnlyWmi AntiVirusProduct '' 'root\SecurityCenter2' 'displayName,productState,timestamp')
            $evidence += Get-EvidenceText $av @('displayName','productState','timestamp')
            if ($av.Count) { $state='INFO' }
        }
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            $d=Get-MpComputerStatus -ErrorAction Stop
            $evidence += Get-EvidenceText @($d) @('AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled','AntivirusSignatureLastUpdated','AMRunningMode')
            if ($d.AMRunningMode -eq 'Normal' -and $d.AntivirusEnabled -and $d.RealTimeProtectionEnabled) { $state='PASS' }
            elseif ($d.AMRunningMode -eq 'Normal') { $state='WARNING' }
        }
        New-Observation 'Protection registration and Defender' $state 'Registration is not proof of third-party agent health; server SecurityCenter2 is not assumed.' ($evidence -join "`n") 'Verify third-party EDR health in its management console when Defender is passive or unavailable.'
    } $true
    Invoke-HealthProbe Security 'Firewall profiles' {
        # HNetCfg.FwPolicy2 property reads only. No setters or rule changes.
        $fw=New-Object -ComObject HNetCfg.FwPolicy2
        try {
            foreach ($p in @(@('Domain',1),@('Private',2),@('Public',4))) {
                $enabled=$fw.FirewallEnabled($p[1]); $active=([int]$fw.CurrentProfileTypes -band $p[1]) -ne 0
                $state='PASS'; if (-not $enabled) { $state='WARNING' }
                New-Observation ($p[0]+' firewall') $state ('Enabled='+$enabled+'; Active='+$active) '' 'Validate intended firewall enforcement, including any third-party control.'
            }
        } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($fw) }
    } $true
    Invoke-HealthProbe Security 'Encryption' {
        # Project only nonsecret provider properties. Get-BitLockerVolume can return key protectors.
        $v=@(Get-ReadOnlyWmi Win32_EncryptableVolume '' 'root\cimv2\Security\MicrosoftVolumeEncryption' 'DeviceID,DriveLetter,ProtectionStatus')
        if (-not $v.Count) { throw 'No encryption evidence.' }
        foreach ($d in $v) {
            $state='UNKNOWN'; if ($d.ProtectionStatus -eq 1) { $state='INFO' }; if ($d.ProtectionStatus -eq 0) { $state='WARNING' }
            $name=[string]$d.DriveLetter; if (-not $name) { $name=[string]$d.DeviceID }
            New-Observation $name $state 'BitLocker protection: 0=Off, 1=On, 2=Unknown. No key protectors or recovery secrets queried.' (Get-EvidenceText @($d) @('DeviceID','DriveLetter','ProtectionStatus')) 'Confirm encryption requirements. Algorithm, conversion progress and key recovery are not assessed.'
        }
    }
    Invoke-HealthProbe Security 'TPM' {
        # Do not obtain Get-Tpm's OwnerAuth property or call TPM provisioning methods.
        $t=@(Get-ReadOnlyWmi Win32_Tpm '' 'root\cimv2\Security\MicrosoftTpm' 'IsActivated_InitialValue,IsEnabled_InitialValue,IsOwned_InitialValue,SpecVersion,ManufacturerId')
        if (-not $t.Count) { New-Observation 'TPM presence' 'INFO' 'TPM provider returned no device.'; return }
        $state='INFO'; if (-not $t[0].IsEnabled_InitialValue -or -not $t[0].IsActivated_InitialValue) { $state='WARNING' }
        New-Observation 'TPM state' $state 'TPM initial provider state; ownership authorization is not queried.' (Get-EvidenceText $t @('IsActivated_InitialValue','IsEnabled_InitialValue','IsOwned_InitialValue','SpecVersion','ManufacturerId'))
    }
    Invoke-HealthProbe Security 'Secure Boot' {
        Require-Command Confirm-SecureBootUEFI SecureBoot
        try { $enabled=Confirm-SecureBootUEFI -ErrorAction Stop }
        catch { if ($_.Exception.Message -match 'not supported') { throw 'UNSUPPORTED: firmware does not expose Secure Boot.' }; throw }
        $state='PASS'; if (-not $enabled) { $state='WARNING' }
        New-Observation 'Secure Boot' $state ('Enabled='+$enabled) '' 'Validate firmware security requirements before planning changes.'
    }
    Invoke-HealthProbe Security 'SMB and remote access' {
        $smb=Get-ReadRegistry 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
        if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) { $smb=[int](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol }
        $state='UNKNOWN'; if ($null -ne $smb) { $state='PASS'; if ([int]$smb -ne 0) { $state='WARNING' } }
        New-Observation 'SMBv1 server protocol' $state ('Explicit SMB1 setting='+$smb) 'An absent legacy registry value is not proof SMBv1 is disabled.' 'Verify legacy protocol requirements and remove dependencies through change control.'
        $rdp=Get-ReadRegistry 'SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        $nla=Get-ReadRegistry 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
        $state='INFO'; if ($null -eq $rdp) { $state='UNKNOWN' }; if ($rdp -eq 0 -and $nla -ne 1) { $state='WARNING' }
        New-Observation 'Remote Desktop and NLA' $state ('DenyRDP='+$rdp+'; NLA='+$nla) '' 'If RDP is enabled, validate NLA and network access controls.'
    }
    Invoke-HealthProbe Security 'Local administrators' {
        $g=@(Get-ReadOnlyWmi Win32_Group "LocalAccount=True AND SID='S-1-5-32-544'")
        if ($g.Count -ne 1) { throw 'Local Administrators group unavailable.' }
        $group=[ADSI]('WinNT://'+$env:COMPUTERNAME+'/'+$g[0].Name+',group')
        $members=@($group.psbase.Invoke('Members'))
        $names=@(); foreach ($m in $members) { $names += $m.GetType().InvokeMember('AdsPath','GetProperty',$null,$m,$null) }
        New-Observation 'Local Administrators membership' 'INFO' ('Direct members: '+$names.Count+'; nested groups not expanded.') ($names -join "`n") 'Review membership against approved privileged access; presence alone is not a finding.'
    }
}

function Get-NetworkHealth {
    Invoke-HealthProbe Network 'Adapter configuration' {
        $a=@(Get-ReadOnlyWmi Win32_NetworkAdapterConfiguration 'IPEnabled=True')
        if (-not $a.Count) { throw 'No enabled IP configuration.' }
        $links=@(Get-ReadOnlyWmi Win32_NetworkAdapter 'NetEnabled=True')
        New-Observation 'Network interfaces' 'INFO' 'Enabled IP adapters, including virtual interfaces.' ((Get-EvidenceText $a @('Description','IPAddress','IPSubnet','DefaultIPGateway','DNSServerSearchOrder','DHCPEnabled'))+"`n"+(Get-EvidenceText $links @('Name','Speed','NetConnectionStatus','PhysicalAdapter')))
    } $true
    Invoke-HealthProbe Network 'Gateway reachability' {
        $a=@(Get-ReadOnlyWmi Win32_NetworkAdapterConfiguration 'IPEnabled=True')
        $gateways=@($a | ForEach-Object {$_.DefaultIPGateway} | Where-Object {$_} | Select-Object -Unique)
        if (-not $gateways.Count) { New-Observation 'Default gateway' 'NOT APPLICABLE' 'No default gateway configured.'; return }
        foreach ($g in $gateways) {
            $ping=New-Object Net.NetworkInformation.Ping
            try { $reply=$ping.Send([string]$g,1000); New-Observation ('Gateway '+$g) 'INFO' ('ICMP='+$reply.Status) 'No ICMP reply does not prove network failure.' } finally { $ping.Dispose() }
        }
    }
    Invoke-HealthProbe Network 'Domain DNS' {
        $cs=@(Get-ReadOnlyWmi Win32_ComputerSystem)[0]
        if (-not $cs.PartOfDomain) { New-Observation 'Domain DNS' 'NOT APPLICABLE' 'Workgroup device.'; return }
        $a=[Net.Dns]::GetHostAddresses([string]$cs.Domain)
        if (-not $a.Count) { throw 'Domain has no DNS addresses.' }
        New-Observation 'Domain DNS resolution' 'PASS' ('Domain='+$cs.Domain) (($a | ForEach-Object {$_.IPAddressToString}) -join ', ')
    }
    Invoke-HealthProbe Network 'Secure channel' {
        $cs=@(Get-ReadOnlyWmi Win32_ComputerSystem)[0]
        if (-not $cs.PartOfDomain) { New-Observation 'Secure channel' 'NOT APPLICABLE' 'Workgroup device.'; return }
        if ([int]$cs.DomainRole -ge 4) { New-Observation 'Secure channel' 'NOT APPLICABLE' 'Domain controller; replication is assessed in AD DS.'; return }
        Require-Command Test-ComputerSecureChannel
        $ok=Test-ComputerSecureChannel -ErrorAction Stop
        $state='PASS'; if (-not $ok) { $state='CRITICAL' }
        New-Observation 'Domain member secure channel' $state ('Trusted='+$ok) 'Read-only test; Repair is never supplied.' 'Investigate domain connectivity and trust evidence before making changes.'
    }
    Invoke-HealthProbe Network 'Windows Time configuration' {
        $svc=@(Get-ReadOnlyWmi Win32_Service "Name='W32Time'")
        $source=Get-ReadRegistry 'SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'NtpServer'
        $type=Get-ReadRegistry 'SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'Type'
        $state='INFO'; if ($svc.Count -ne 1) { $state='UNKNOWN' }
        New-Observation 'Time service and configured source' $state ('Type='+$type+'; ConfiguredPeer='+$source) (Get-EvidenceText $svc @('State','StartMode')) 'Configured peers are not proof of synchronization. Correlate measured drift and Time-Service events.'
    }
    Invoke-HealthProbe Network 'Measured time drift' {
        # Read-only NTP client request to a numeric configured peer; no w32tm /resync.
        $raw=[string](Get-ReadRegistry 'SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'NtpServer')
        $peer=($raw -split '\s+')[0] -replace ',.*$',''
        $mode=Get-ReadRegistry 'SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'Type'
        if ($mode -eq 'NT5DS') { $peer=[string]$env:LOGONSERVER -replace '^\\\\','' }
        if (-not $peer -or $peer -match '[^a-zA-Z0-9.:-]') { throw 'No safely identifiable current time peer.' }
        $udp=New-Object Net.Sockets.UdpClient
        try {
            $udp.Client.ReceiveTimeout=3000; $udp.Connect($peer,123)
            $packet=New-Object byte[] 48; $packet[0]=0x23
            $epoch=New-Object DateTime(1900,1,1,0,0,0,[DateTimeKind]::Utc)
            $t1=[DateTime]::UtcNow; $sec=($t1-$epoch).TotalSeconds
            $whole=[uint32][math]::Floor($sec); $fraction=[uint32](($sec-[math]::Floor($sec))*4294967296.0)
            for ($i=0;$i -lt 4;$i++) { $packet[40+$i]=[byte](($whole -shr (24-8*$i)) -band 255); $packet[44+$i]=[byte](($fraction -shr (24-8*$i)) -band 255) }
            [void]$udp.Send($packet,48); $remote=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0); $reply=$udp.Receive([ref]$remote); $t4=[DateTime]::UtcNow
            if ($reply.Length -lt 48 -or ($reply[0] -band 7) -ne 4 -or ($reply[0] -shr 6) -eq 3 -or $reply[1] -lt 1 -or $reply[1] -gt 15) { throw 'Unsynchronized or invalid NTP response.' }
            for ($i=0;$i -lt 8;$i++) { if ($reply[24+$i] -ne $packet[40+$i]) { throw 'NTP origin mismatch.' } }
            $times=@()
            foreach ($offset in @(32,40)) { $s=0.0; $f=0.0; for ($i=0;$i -lt 4;$i++) { $s=$s*256+$reply[$offset+$i]; $f=$f*256+$reply[$offset+4+$i] }; $times += $epoch.AddSeconds($s+$f/4294967296.0) }
            $drift=(($times[0]-$t1).TotalSeconds+($times[1]-$t4).TotalSeconds)/2
            if (($t4-$t1).TotalSeconds -gt 2) { throw 'NTP round trip too long for usable measurement.' }
            New-Observation 'NTP drift sample' (Get-AgeStatus ([math]::Abs($drift)) $cfg.TimeWarningSeconds $cfg.TimeCriticalSeconds) ('Offset='+[math]::Round($drift,3)+' seconds; Peer='+$peer) ('Stratum='+$reply[1]+'; RTT='+[math]::Round(($t4-$t1).TotalMilliseconds)+' ms; single unauthenticated sample, not proof of Windows Time synchronization') 'Validate time hierarchy and repeated offsets before changing time configuration.'
        } finally { $udp.Close() }
    }
    Invoke-HealthProbe Network 'Windows Time synchronization status' {
        $status=Invoke-ReadOnlyNative 'w32tm.exe' '/query /status /verbose'
        $source=Invoke-ReadOnlyNative 'w32tm.exe' '/query /source'
        $state='INFO'
        if ($status -match '(?im)^Leap Indicator:\s*3' -or $status -match '(?im)^Last Sync Error:\s*[1-9]') { $state='WARNING' }
        New-Observation 'Windows Time reported synchronization' $state ('Reported source='+$source.Trim()) $status 'Review last successful synchronization and leap state. Localized output is shown as evidence without guessing its meaning.'
    }
}

function Get-RoleCatalog {
    @(
        @{Name='Active Directory Domain Services'; Services=@('NTDS'); Feature='AD-Domain-Services'; Log='Directory Service'; Pack='AD'}
        @{Name='DNS Server'; Services=@('DNS'); Feature='DNS'; Log='DNS Server'; Pack='DNS'}
        @{Name='DHCP Server'; Services=@('DHCPServer'); Feature='DHCP'; Log='Microsoft-Windows-Dhcp-Server/Admin'; Pack='DHCP'}
        @{Name='File Services / SMB'; Services=@('LanmanServer'); Feature='FS-FileServer'; Log='Microsoft-Windows-SMBServer/Operational'; Pack='File'}
        @{Name='Print Server'; Services=@('Spooler'); Feature='Print-Server'; Log='Microsoft-Windows-PrintService/Admin'; Pack='Print'}
        @{Name='Hyper-V'; Services=@('vmms'); Feature='Hyper-V'; Log='Microsoft-Windows-Hyper-V-VMMS-Admin'; Pack='HyperV'}
        @{Name='IIS'; Services=@('W3SVC','WAS'); Feature='Web-Server'; Log='System'; Pack='IIS'}
        @{Name='Remote Desktop Services'; Services=@('TermService'); Feature='RDS-RD-Server'; Log='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Pack='RDS'}
        @{Name='Windows Server Backup'; Services=@('wbengine'); Feature='Windows-Server-Backup'; Log='Microsoft-Windows-Backup'; Pack='Backup'}
        @{Name='Failover Clustering'; Services=@('ClusSvc'); Feature='Failover-Clustering'; Log='Microsoft-Windows-FailoverClustering/Operational'; Pack='Cluster'}
        @{Name='SQL Server Platform Indicators'; Services=@(); Feature=''; Log='Application'; Pack='SQL'}
        @{Name='Active Directory Certificate Services'; Services=@('CertSvc'); Feature='ADCS-Cert-Authority'; Log='Application'; Pack='CA'}
    )
}
function Find-InstalledRoles {
    # Detect using installed service metadata, configured shares/printers and role registry values.
    # Failure of detection is required UNKNOWN, not an assertion that no roles exist.
    $before=$script:Results.Count
    Invoke-HealthProbe Roles 'Role detection' {
        $services=@(Get-ReadOnlyWmi Win32_Service '' 'root\cimv2' 'Name,State,StartMode')
        if (-not $services.Count) { throw 'Service enumeration empty.' }
        $os=@(Get-ReadOnlyWmi Win32_OperatingSystem)[0]
        $roles=@()
        $map=@{'NTDS'='AD';'DNS'='DNS';'DHCPServer'='DHCP';'vmms'='HyperV';'W3SVC'='IIS';'ClusSvc'='Cluster';'CertSvc'='CA'}
        foreach ($s in $services) {
            if ($map.ContainsKey([string]$s.Name)) { $roles += $map[[string]$s.Name] }
            if ($s.Name -match '^(MSSQLSERVER|MSSQL\$)') { $roles += 'SQL' }
        }
        try { if (@(Get-ReadOnlyWmi Win32_Share 'Type=0' | Where-Object {$_.Name -notmatch '^[A-Za-z]\$$'}).Count) { $roles += 'File' } }
        catch { New-Observation 'File role detection' 'UNKNOWN' 'Share role detection failed.' }
        try { if (@(Get-ReadOnlyWmi Win32_Printer 'Shared=True' 'root\cimv2' 'Name,Shared').Count) { $roles += 'Print' } }
        catch { New-Observation 'Print role detection' 'UNKNOWN' 'Print role detection failed.' }
        if ([int]$os.ProductType -gt 1) {
            if ((Get-ReadRegistry 'SYSTEM\CurrentControlSet\Control\Terminal Server' 'TSAppCompat') -eq 1 -or (Test-ReadRegistryKey 'SYSTEM\CurrentControlSet\Services\TermServLicensing') -or (Test-ReadRegistryKey 'SYSTEM\CurrentControlSet\Services\Tssdis') -or (Test-ReadRegistryKey 'SYSTEM\CurrentControlSet\Services\TSGateway')) { $roles += 'RDS' }
            if (Test-ReadRegistryKey 'SYSTEM\CurrentControlSet\Services\wbengine') { $roles += 'Backup' }
        }
        New-Observation 'Applicable roles' 'INFO' 'Role detection completed using service and configuration evidence.' ((@($roles | Select-Object -Unique)) -join '|')
    } $true
    $found=@($script:Results | Select-Object -Skip $before | Where-Object {$_.CheckName -eq 'Applicable roles'})
    $packs=@(); if ($found.Count -eq 1 -and $found[0].CollectionSucceeded -and $found[0].Evidence) { $packs=@($found[0].Evidence -split '\|') }
    $script:Roles=@(Get-RoleCatalog | Where-Object {$packs -contains $_.Pack})
    Invoke-HealthProbe Roles 'Installed features' {
        $os=@(Get-ReadOnlyWmi Win32_OperatingSystem)[0]
        if ([int]$os.ProductType -eq 1) { New-Observation 'Server feature inventory' 'NOT APPLICABLE' 'Client Windows; service/configuration capability detection used.'; return }
        if (Get-Module -ListAvailable ServerManager) {
            Import-Module ServerManager -ErrorAction Stop
            $features=@(Get-WindowsFeature -ErrorAction Stop | Where-Object {$_.Installed})
            New-Observation 'Installed Windows Server roles/features' 'INFO' ('Installed: '+$features.Count) (Get-EvidenceText $features @('Name','DisplayName'))
            New-Observation 'Role feature identifiers' 'INFO' 'Installed feature identifiers supplement service detection.' (($features | ForEach-Object {$_.Name}) -join '|')
        } else {
            $f=@(Get-ReadOnlyWmi Win32_ServerFeature)
            New-Observation 'Installed Windows Server features' 'INFO' ('Features: '+$f.Count) (Get-EvidenceText $f @('ID','ParentID','Name'))
        }
    }
    $featureIds=@($script:Results | Where-Object {$_.CheckName -eq 'Role feature identifiers'} | ForEach-Object {$_.Evidence -split '\|'})
    $script:Roles=@(Get-RoleCatalog | Where-Object {$packs -contains $_.Pack -or ($_.Feature -and $featureIds -contains $_.Feature)})
    Write-Phase ('Detected roles: ' + (($script:Roles | ForEach-Object {$_.Name}) -join ', '))
}
function Get-RoleHealth {
    Write-Phase 'Running role checks'
    foreach ($role in $script:Roles) {
        $roleStart=$script:Results.Count
        $context=@{Pack=$role.Pack; Name=$role.Name; Services=$role.Services; Log=$role.Log}
        if ($role.Services.Count) {
            Invoke-HealthProbe Roles ($role.Name+' services') {
                foreach ($name in $ctx.Services) {
                    $s=@(Get-ReadOnlyWmi Win32_Service ("Name='"+$name+"'"))
                    if ($s.Count -ne 1) { New-Observation $name 'UNKNOWN' 'Role service metadata unavailable.'; continue }
                    $state='PASS'
                    if ($s[0].State -ne 'Running') { $state='CRITICAL'; if ($ctx.Pack -eq 'Backup') { $state='INFO' } }
                    New-Observation $name $state ('State='+$s[0].State+'; StartMode='+$s[0].StartMode) 'Backup engine may stop when idle.' 'Investigate stopped role services before starting or changing them.'
                }
            } $true $context
        }
        switch ($role.Pack) {
            'AD' {
                Invoke-HealthProbe Roles 'Active Directory Domain Services' {
                    Require-Command Get-ADDomain ActiveDirectory
                    $domain=Get-ADDomain -ErrorAction Stop; $forest=Get-ADForest -ErrorAction Stop
                    New-Observation 'Domain, forest and FSMO visibility' 'INFO' 'Directory identity and FSMO owners.' ((Get-EvidenceText @($domain) @('DNSRoot','DomainMode','PDCEmulator','RIDMaster','InfrastructureMaster'))+"`n"+(Get-EvidenceText @($forest) @('Name','ForestMode','SchemaMaster','DomainNamingMaster')))
                    $fail=@(Get-ADReplicationFailure -Target $env:COMPUTERNAME -Scope Server -ErrorAction Stop)
                    $state='PASS'; if ($fail.Count) { $state='CRITICAL' }
                    New-Observation 'Replication failures' $state ('Failure partners: '+$fail.Count) (Get-EvidenceText $fail @('Server','Partner','FailureCount','FirstFailureTime','LastError')) 'Investigate the reported source/destination replication failures.'
                    $meta=@(Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -Scope Server -PartnerType Both -ErrorAction Stop)
                    $allDC=@(Get-ADDomainController -Filter * -ErrorAction Stop)
                    if (-not $meta.Count -and $allDC.Count -gt 1) { New-Observation 'Replication age' 'UNKNOWN' 'No partner metadata in a multi-controller domain.' }
                    elseif (-not $meta.Count) { New-Observation 'Replication age' 'NOT APPLICABLE' 'Single-controller domain; no replication partners.' }
                    foreach ($p in $meta) {
                        $state='PASS'; $age=0
                        if (-not $p.LastReplicationSuccess) { $state='UNKNOWN' }
                        else { $age=([datetime]::Now-$p.LastReplicationSuccess).TotalHours; if ($age -gt 24 -or $p.LastReplicationResult -ne 0) { $state='CRITICAL' } elseif ($age -gt 12) { $state='WARNING' } }
                        New-Observation ('Replication '+$p.PartnerType+' '+$p.Partner) $state ('Last success age hours='+[math]::Round($age,1)) (Get-EvidenceText @($p) @('Server','Partner','Partition','PartnerType','LastReplicationSuccess','LastReplicationResult','ConsecutiveReplicationFailures')) 'Compare with site-link schedules; investigate failed or stale replication.'
                    }
                } $true $context
                Invoke-HealthProbe Roles 'SYSVOL, NETLOGON and DFSR' {
                    $shares=@(Get-ReadOnlyWmi Win32_Share)
                    foreach ($name in @('SYSVOL','NETLOGON')) {
                        $s=@($shares | Where-Object {$_.Name -eq $name}); $state='PASS'; if ($s.Count -ne 1) { $state='CRITICAL' }
                        New-Observation $name $state ('Share present='+($s.Count -eq 1)) 'Share presence is an availability indicator, not complete SYSVOL consistency validation.' 'Investigate SYSVOL readiness and replication before any remediation.'
                    }
                    $ready=Get-ReadRegistry 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'SysVolReady'
                    $state='UNKNOWN'; if ($null -ne $ready) { $state='PASS'; if ($ready -ne 1) { $state='CRITICAL' } }
                    New-Observation 'SYSVOL readiness' $state ('SysVolReady='+$ready)
                    $dfsr=@(Get-ReadOnlyWmi DfsrReplicatedFolderInfo '' 'root\microsoftdfs')
                    if (-not $dfsr.Count) { throw 'UNSUPPORTED: DFSR folder state absent; FRS or provider unavailable.' }
                    foreach ($d in $dfsr) { $state='PASS'; if ($d.State -ne 4) { $state='WARNING' }; New-Observation ([string]$d.ReplicatedFolderName) $state ('DFSR state='+$d.State+' (4=Normal)') }
                } $true
                Invoke-HealthProbe Events 'DFS Replication' { Read-CuratedEvents 'DFS Replication' }
            }
            'DNS' {
                Invoke-HealthProbe Roles 'DNS Server' {
                    Require-Command Get-DnsServerZone DnsServer
                    $zones=@(Get-DnsServerZone -ErrorAction Stop)
                    if (-not $zones.Count) { New-Observation 'DNS zones' 'WARNING' 'DNS service is installed but no zones were returned.' }
                    foreach ($z in $zones) { $state='PASS'; if ($z.IsPaused -or $z.IsShutdown) { $state='CRITICAL' }; New-Observation ([string]$z.ZoneName) $state 'DNS zone state.' (Get-EvidenceText @($z) @('ZoneName','ZoneType','IsDsIntegrated','IsPaused','IsShutdown','IsReverseLookupZone')) 'Investigate paused or unloaded zones.' }
                    $f=Get-DnsServerForwarder -ErrorAction Stop
                    New-Observation 'DNS forwarders' 'INFO' 'Forwarder configuration; absence may intentionally use root hints.' (Get-EvidenceText @($f) @('IPAddress','UseRootHint','Timeout'))
                    foreach ($z in @($zones | Where-Object {-not $_.IsReverseLookupZone -and $_.ZoneName -ne 'TrustAnchors'} | Select-Object -First 5)) {
                        $answer=Resolve-DnsName -Name $z.ZoneName -Type SOA -Server 127.0.0.1 -DnsOnly -ErrorAction Stop
                        New-Observation ('SOA '+$z.ZoneName) 'PASS' 'Local DNS returned zone SOA.' (Get-EvidenceText @($answer) @('Name','PrimaryServer','SerialNumber'))
                    }
                } $true
            }
            'DHCP' {
                Invoke-HealthProbe Roles 'DHCP scopes' {
                    Require-Command Get-DhcpServerv4Scope DhcpServer
                    $scopes=@(Get-DhcpServerv4Scope -ErrorAction Stop)
                    if (-not $scopes.Count) { New-Observation 'IPv4 scopes' 'INFO' 'No IPv4 scopes configured; IPv6 scope health is outside v1.' }
                    foreach ($s in $scopes) {
                        $stat=Get-DhcpServerv4ScopeStatistics -ScopeId $s.ScopeId -ErrorAction Stop
                        $state='PASS'; if ($s.State -ne 'Active') { $state='WARNING' }
                        if ($stat.PercentageInUse -ge 95) { $state='CRITICAL' } elseif ($stat.PercentageInUse -ge 85) { $state='WARNING' }
                        New-Observation ([string]$s.ScopeId) $state ('State='+$s.State+'; Utilization='+$stat.PercentageInUse+'%') (Get-EvidenceText @($stat) @('AddressesFree','AddressesInUse','ReservedAddress','PendingOffers')) 'Review active scope capacity and failover before changing address allocation.'
                    }
                } $true
                Invoke-HealthProbe Roles 'DHCP failover' {
                    Require-Command Get-DhcpServerv4Failover DhcpServer
                    $f=@(Get-DhcpServerv4Failover -ErrorAction Stop)
                    if (-not $f.Count) { New-Observation 'DHCP failover' 'NOT APPLICABLE' 'No failover relationship configured.' }
                    foreach ($p in $f) { $state='PASS'; if ($p.State -ne 'Normal') { $state='WARNING' }; New-Observation ([string]$p.Name) $state ('State='+$p.State) (Get-EvidenceText @($p) @('PartnerServer','Mode','State','ScopeId')) 'Investigate failover communication and partner state.' }
                }
            }
            'File' {
                Invoke-HealthProbe Roles 'File Services / SMB' {
                    $shares=@(Get-ReadOnlyWmi Win32_Share 'Type=0' | Where-Object {$_.Name -notmatch '^[a-zA-Z]\$$'})
                    foreach ($s in $shares) {
                        $state='INFO'; if ($s.Status -and $s.Status -ne 'OK') { $state='WARNING' }
                        New-Observation ([string]$s.Name) $state 'Share metadata; backing-volume capacity appears in Storage. No directory contents read.' (Get-EvidenceText @($s) @('Name','Path','Status','AllowMaximum','MaximumAllowed')) 'Correlate share path with volume health and client access failures.'
                    }
                    if (-not $shares.Count) { New-Observation 'SMB shares' 'INFO' 'No non-system shares remain configured.' }
                    if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) { New-Observation 'SMB share configuration' 'INFO' 'SMB state and encryption.' (Get-EvidenceText @(Get-SmbShare -ErrorAction Stop | Where-Object {-not $_.Special}) @('Name','Path','ShareState','EncryptData','ContinuouslyAvailable')) }
                } $true
                Invoke-HealthProbe Roles 'VSS indicators' {
                    $s=@(Get-ReadOnlyWmi Win32_Service "Name='VSS' OR Name='swprv'")
                    $copies=@(Get-ReadOnlyWmi Win32_ShadowCopy '' 'root\cimv2' 'InstallDate,State,VolumeName')
                    New-Observation 'VSS services and existing snapshots' 'INFO' 'Demand-start services may be stopped. Writer health is not inferred from snapshot presence.' ((Get-EvidenceText $s @('Name','State','StartMode'))+"`n"+(Get-EvidenceText $copies @('InstallDate','State','VolumeName')))
                }
            }
            'Print' {
                Invoke-HealthProbe Roles 'Print queues' {
                    $p=@(Get-ReadOnlyWmi Win32_Printer 'Shared=True' 'root\cimv2' 'Name,PrinterStatus,DetectedErrorState,WorkOffline,Shared')
                    $jobs=@(Get-ReadOnlyWmi Win32_PrintJob '' 'root\cimv2' 'JobId,Status,TimeSubmitted')
                    foreach ($q in $p) { $state='INFO'; if ($q.WorkOffline -or $q.DetectedErrorState -gt 2 -or $q.PrinterStatus -eq 7) { $state='WARNING' }; New-Observation ([string]$q.Name) $state 'Printer queue status reported by Windows.' (Get-EvidenceText @($q) @('PrinterStatus','DetectedErrorState','WorkOffline')) 'Check physical device and queue errors before clearing jobs or restarting services.' }
                    $old=0; foreach ($j in $jobs) { if ($j.TimeSubmitted -and ([datetime]::Now-[Management.ManagementDateTimeConverter]::ToDateTime($j.TimeSubmitted)).TotalMinutes -ge 60) { $old++ } }
                    $state='INFO'; if ($old) { $state='WARNING' }
                    New-Observation 'Queued job counts' $state ('Total='+$jobs.Count+'; at least 60 minutes old='+$old) 'Job document names, owners and content are not selected.' 'Investigate old queued jobs without automatically clearing them.'
                } $true
            }
            'HyperV' {
                Invoke-HealthProbe Roles 'Hyper-V virtual machines' {
                    Require-Command Get-VM Hyper-V
                    $vms=@(Get-VM -ErrorAction Stop)
                    if (-not $vms.Count) { New-Observation 'VM inventory' 'INFO' 'No VMs configured.' }
                    foreach ($v in $vms) {
                        $state='INFO'; if ([string]$v.Status -ne 'Operating normally' -and $v.OperationalStatus -and @($v.OperationalStatus) -notcontains 'Ok') { $state='WARNING' }
                        New-Observation ([string]$v.Name) $state 'VM state; an intentionally stopped VM is not a health failure.' (Get-EvidenceText @($v) @('Name','State','Status','Version','Path','ConfigurationLocation','SnapshotFileLocation'))
                        $cp=@(Get-VMSnapshot -VMName $v.Name -ErrorAction Stop); $old=@($cp | Where-Object {$_.CreationTime -lt [datetime]::Now.AddDays(-7)})
                        $state='INFO'; if ($old.Count -gt 0 -or $cp.Count -gt 3) { $state='WARNING' }
                        New-Observation ('Checkpoints '+$v.Name) $state ('Count='+$cp.Count+'; older than seven days='+$old.Count) (Get-EvidenceText $cp @('Name','CreationTime','SnapshotType')) 'Review checkpoint retention and backing storage; no checkpoints were created or removed.'
                        New-Observation ('Integration '+$v.Name) 'INFO' 'Guest integration indicators.' (Get-EvidenceText @(Get-VMIntegrationService -VMName $v.Name -ErrorAction Stop) @('Name','Enabled','PrimaryStatusDescription','SecondaryStatusDescription'))
                        $disks=@(Get-VMHardDiskDrive -VMName $v.Name -ErrorAction Stop)
                        foreach ($disk in $disks) {
                            if (-not $disk.Path) { continue }
                            $exists=Test-Path -LiteralPath $disk.Path -ErrorAction Stop
                            $state='PASS'; if (-not $exists) { $state='WARNING' }
                            New-Observation ('VM storage '+$v.Name) $state ('Path accessible='+$exists) $disk.Path 'Investigate inaccessible storage paths and host-volume findings.'
                        }
                    }
                    New-Observation 'Virtual switches' 'INFO' 'Host virtual switch configuration.' (Get-EvidenceText @(Get-VMSwitch -ErrorAction Stop) @('Name','SwitchType','NetAdapterInterfaceDescription'))
                } $true
                Invoke-HealthProbe Roles 'Hyper-V replication' {
                    Require-Command Get-VMReplication Hyper-V
                    $r=@(Get-VMReplication -ErrorAction Stop)
                    if (-not $r.Count) { New-Observation 'VM replication' 'NOT APPLICABLE' 'No replication relationships configured.' }
                    foreach ($v in $r) { $state='PASS'; if ([string]$v.Health -ne 'Normal') { $state='WARNING' }; if ([string]$v.Health -eq 'Critical') { $state='CRITICAL' }; New-Observation ([string]$v.VMName) $state ('Health='+$v.Health+'; State='+$v.State) (Get-EvidenceText @($v) @('PrimaryServer','ReplicaServer','LastReplicationTime')) 'Investigate replica connectivity and replication backlog.' }
                }
            }
            'IIS' {
                Invoke-HealthProbe Roles 'IIS sites and pools' {
                    Require-Command Get-Website WebAdministration
                    $sites=@(Get-Website -ErrorAction Stop)
                    foreach ($s in $sites) { $state='PASS'; if ($s.State -ne 'Started') { $state='WARNING' }; New-Observation ([string]$s.Name) $state ('Site state='+$s.State) (Get-EvidenceText @($s.Bindings.Collection) @('protocol','bindingInformation')) 'Verify whether the site is intentionally stopped before making changes.' }
                    $pools=@(Get-ChildItem IIS:\AppPools -ErrorAction Stop)
                    foreach ($p in $pools) { $state='PASS'; if ($p.State -ne 'Started') { $state='WARNING' }; New-Observation ('Pool '+$p.Name) $state ('State='+$p.State) '' 'Investigate application-pool failures; no recycle was performed.' }
                    if (-not $sites.Count -and -not $pools.Count) { New-Observation 'IIS configuration' 'INFO' 'No sites or pools configured.' }
                } $true
                Invoke-HealthProbe Roles 'IIS HTTPS certificates' {
                    Require-Command Get-WebBinding WebAdministration
                    $bindings=@(Get-WebBinding -Protocol https -ErrorAction Stop)
                    if (-not $bindings.Count) { New-Observation 'HTTPS certificates' 'NOT APPLICABLE' 'No HTTPS bindings.' }
                    foreach ($b in $bindings) {
                        $hash=$b.certificateHash
                        if ($hash -is [byte[]]) { $hash=([BitConverter]::ToString($hash)).Replace('-','') }
                        $store=[string]$b.certificateStoreName; if (-not $store) { $store='My' }
                        if (-not $hash -or [string]$hash -notmatch '^[0-9a-fA-F]+$' -or $store -notmatch '^[a-zA-Z0-9]+$') { New-Observation 'HTTPS binding certificate' 'UNKNOWN' 'Certificate mapping unavailable, possibly central certificate storage.'; continue }
                        $cert=Get-Item -LiteralPath ('Cert:\LocalMachine\'+$store+'\'+$hash) -ErrorAction Stop
                        $days=($cert.NotAfter-[datetime]::Now).TotalDays; $state='PASS'; if ($days -lt 30) { $state='WARNING' }; if ($days -lt 0 -or $cert.NotBefore -gt [datetime]::Now) { $state='CRITICAL' }
                        New-Observation ([string]$b.bindingInformation) $state ('Certificate days remaining='+[math]::Floor($days)) (Get-EvidenceText @($cert) @('Subject','Thumbprint','NotBefore','NotAfter')) 'Renew or replace invalid certificates through the normal change process.'
                    }
                }
            }
            'RDS' {
                Invoke-HealthProbe Roles 'Remote Desktop Services' {
                    $services=@(Get-ReadOnlyWmi Win32_Service "Name='TermService' OR Name='TermServLicensing' OR Name='Tssdis' OR Name='TSGateway' OR Name='SessionEnv'")
                    foreach ($s in $services) { $state='INFO'; if ($s.StartMode -eq 'Auto' -and $s.State -ne 'Running' -and $s.Name -ne 'SessionEnv') { $state='WARNING' }; New-Observation ([string]$s.Name) $state ('State='+$s.State+'; StartMode='+$s.StartMode) }
                    $mode=Get-ReadRegistry 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'LicensingMode'
                    $servers=Get-ReadRegistry 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'LicenseServers'
                    $state='INFO'; if ($null -eq $mode) { $state='UNKNOWN' }
                    New-Observation 'RDS licensing configuration' $state ('Policy mode='+$mode+'; Policy servers='+$servers+'; SessionHost='+(Get-ReadRegistry 'SYSTEM\CurrentControlSet\Control\Terminal Server' 'TSAppCompat')) 'Policy-only evidence; absence may mean local or deployment configuration. CAL availability is not tested.' 'Verify deployment licensing in the RDS management tools.'
                } $true
            }
            'Backup' {
                Invoke-HealthProbe Roles 'Windows Server Backup' {
                    Require-Command Get-WBSummary WindowsServerBackup
                    $s=Get-WBSummary -ErrorAction Stop
                    if (-not $s) { throw 'Backup summary unavailable.' }
                    $state='UNKNOWN'; if ($s.LastSuccessfulBackupTime -and $s.LastSuccessfulBackupTime.Year -gt 2000) { $age=([datetime]::Now-$s.LastSuccessfulBackupTime).TotalHours; $state='PASS'; if ($age -gt 48) { $state='WARNING' }; if ($age -gt 168) { $state='CRITICAL' } }
                    New-Observation 'Latest backup evidence' $state 'WSB history only; third-party backups and recoverability are not assessed.' (Get-EvidenceText @($s) @('LastBackupTime','LastSuccessfulBackupTime','LastBackupResultHR','NextBackupTime','NumberOfVersions')) 'Validate expected backup schedule, last result and restore testing in the backup system.'
                } $true
            }
            'Cluster' {
                Invoke-HealthProbe Roles 'Failover Clustering' {
                    Require-Command Get-ClusterNode FailoverClusters
                    $nodes=@(Get-ClusterNode -ErrorAction Stop)
                    if (-not $nodes.Count) { throw 'Cluster nodes unavailable.' }
                    foreach ($n in $nodes) { $state='PASS'; if ($n.State -ne 'Up') { $state='WARNING' }; New-Observation ('Node '+$n.Name) $state ('State='+$n.State) '' 'Confirm whether maintenance explains the state; no cluster validation or remediation was run.' }
                    foreach ($g in @(Get-ClusterGroup -ErrorAction Stop)) { $state='PASS'; if ($g.State -ne 'Online') { $state='WARNING' }; if ($g.State -eq 'Failed') { $state='CRITICAL' }; New-Observation ('Group '+$g.Name) $state ('State='+$g.State+'; Owner='+$g.OwnerNode) }
                    foreach ($r in @(Get-ClusterResource -ErrorAction Stop)) { $state='INFO'; if ($r.State -eq 'Failed') { $state='CRITICAL' }; New-Observation ('Resource '+$r.Name) $state ('State='+$r.State+'; Type='+$r.ResourceType) }
                    New-Observation 'Quorum configuration' 'INFO' 'Current quorum configuration.' (Get-EvidenceText @(Get-ClusterQuorum -ErrorAction Stop) @('Cluster','QuorumType','QuorumResource'))
                } $true
            }
            'SQL' {
                Invoke-HealthProbe Roles 'SQL Server Platform Indicators' {
                    $s=@(Get-ReadOnlyWmi Win32_Service | Where-Object {$_.Name -match '^(MSSQLSERVER|MSSQL\$|SQLSERVERAGENT|SQLAgent\$)'})
                    if (-not $s.Count) { throw 'Detected SQL services no longer available.' }
                    foreach ($v in $s) { $state='INFO'; if ($v.StartMode -eq 'Auto' -and $v.State -ne 'Running') { $state='WARNING' }; New-Observation ([string]$v.Name) $state ('State='+$v.State+'; StartMode='+$v.StartMode) 'Windows-level evidence only. No SQL credentials or database queries used; database health was not tested.' 'Investigate unexpectedly stopped SQL services; use separate database monitoring for database health.' }
                    $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL',$false)
                    if (-not $key) { throw 'SQL instance registry metadata unavailable.' }
                    try { foreach ($name in $key.GetValueNames()) { $id=[string]$key.GetValue($name); if ($id -notmatch '^[a-zA-Z0-9_.-]+$') { continue }; New-Observation ('Instance '+$name) 'INFO' ('InstanceId='+$id+'; Version='+(Get-ReadRegistry ('SOFTWARE\Microsoft\Microsoft SQL Server\'+$id+'\Setup') 'Version')+'; Edition='+(Get-ReadRegistry ('SOFTWARE\Microsoft\Microsoft SQL Server\'+$id+'\Setup') 'Edition')) } } finally { $key.Close() }
                } $true
            }
            'CA' {
                Invoke-HealthProbe Roles 'Active Directory Certificate Services' {
                    $base='SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
                    $name=[string](Get-ReadRegistry $base 'Active')
                    if (-not $name) { throw 'Active CA identity unavailable.' }
                    $hashes=@(Get-ReadRegistry ($base+'\'+$name) 'CACertHash')
                    if (-not $hashes.Count) { throw 'CA certificate hashes unavailable.' }
                    foreach ($hash in $hashes) {
                        $thumb=([string]$hash).Replace(' ','')
                        if ($thumb -notmatch '^[0-9a-fA-F]+$') { throw 'CA certificate hash invalid.' }
                        $cert=Get-Item -LiteralPath ('Cert:\LocalMachine\My\'+$thumb) -ErrorAction Stop
                        $days=($cert.NotAfter-[datetime]::Now).TotalDays; $state='PASS'; if ($days -lt 60) { $state='WARNING' }; if ($days -lt 0 -or $cert.NotBefore -gt [datetime]::Now) { $state='CRITICAL' }
                        New-Observation ('CA '+$name) $state ('Certificate days remaining='+[math]::Floor($days)) (Get-EvidenceText @($cert) @('Subject','Thumbprint','NotBefore','NotAfter')) 'Review CA renewal planning through the certificate services change process.'
                    }
                } $true
            }
        }
        # System/Application already analyzed; role-specific channels are collected only for detected roles.
        if (@('System','Application') -notcontains $role.Log) { Invoke-HealthProbe Events ($role.Name+' events') { Read-CuratedEvents $ctx.Log } $false $context }
        for ($j=$roleStart;$j -lt $script:Results.Count;$j++) { $script:Results[$j].Source=$role.Name }
    }
}

function New-ReportTable {
    param($Rows,[string[]]$Columns,[int]$Limit=200)
    $items=@($Rows); if (-not $items.Count) { return '<p>No findings in this section.</p>' }
    # Wide technical grids become two-column records so PDF exports cannot squeeze status
    # labels and event IDs into one-character-wide columns. No CSS support is required.
    if ($Columns.Count -gt 4) {
        $blocks=New-Object Text.StringBuilder
        foreach ($r in @($items | Select-Object -First $Limit)) {
            $fields=@(); foreach ($c in $Columns) { $fields += @{Field=$c;Value=$r.$c} }
            [void]$blocks.Append((New-ReportTable $fields @('Field','Value'))+'<p></p>')
        }
        if ($items.Count -gt $Limit) { [void]$blocks.Append('<p>Additional records omitted: '+($items.Count-$Limit)+'. Findings still contribute to score and coverage.</p>') }
        return $blocks.ToString()
    }
    $html=New-Object Text.StringBuilder
    [void]$html.Append('<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%;font-size:13px"><thead><tr>')
    foreach ($c in $Columns) { [void]$html.Append('<th style="text-align:left">'+(ConvertTo-HtmlText $c)+'</th>') }
    [void]$html.Append('</tr></thead><tbody>')
    foreach ($r in @($items | Select-Object -First $Limit)) {
        [void]$html.Append('<tr>')
        foreach ($c in $Columns) { [void]$html.Append('<td style="vertical-align:top">'+((ConvertTo-HtmlText $r.$c) -replace '\r?\n','<br>')+'</td>') }
        [void]$html.Append('</tr>')
    }
    [void]$html.Append('</tbody></table>')
    if ($items.Count -gt $Limit) { [void]$html.Append('<p>Additional rows omitted: '+($items.Count-$Limit)+'. Findings still contribute to score and coverage.</p>') }
    return $html.ToString()
}
function Add-ReportSection {
    param($Sections,[string]$Heading,[string]$Html,[int]$Level=2)
    [void]$Sections.Add(@{'resource-type'='Document::Heading'; content=$Heading; level=$Level; sort=$Sections.Count})
    [void]$Sections.Add(@{'resource-type'='Document::Text'; content=$Html; sort=$Sections.Count})
}
function New-HealthReport {
    param($Identity,$Score)
    $sections=New-Object Collections.ArrayList
    $summary=@()
    foreach ($p in @(@('Computer',$Identity.Computer),@('Device type / roles',$Identity.Role),@('OS',$Identity.OS),@('Assessment UTC',$Identity.Timestamp),@('PowerShell',$Identity.PowerShell),@('Overall Status',$Score.Status),@('Health Score',$Score.Score),@('Assessment Coverage',([string]$Score.Coverage+'%')),@('Critical',$Score.Critical),@('Warnings',$Score.Warnings),@('Unknown / Unsupported',$Score.Unknown))) { $summary += @{Metric=$p[0];Value=$p[1]} }
    $banner='<p><strong>DHC managed report schema 1</strong> | Assessment attempt: '+(ConvertTo-HtmlText $Identity.Timestamp)+'</p>'
    if ($Identity.Unsupported) { $banner += '<p><strong>UNSUPPORTED - Full Device Health Assessment Could Not Run</strong></p><p>Required PowerShell: 5.1 or later. Baseline health and server roles could not be assessed. No remediation was attempted.</p>' }
    if ($Score.Incomplete) { $banner += '<p style="background:#fff1d6;padding:12px"><strong>ASSESSMENT INCOMPLETE - Unable to Assess</strong><br>Health score withheld because required assessment areas could not be evaluated or usable coverage is below the configured minimum.</p>' }
    Add-ReportSection $sections 'Device Health Assessment' $banner 1
    Add-ReportSection $sections 'Executive Summary' (New-ReportTable $summary @('Metric','Value'))
    Add-ReportSection $sections 'Health Score and Status' ('<p><strong>Health Score: '+(ConvertTo-HtmlText $Score.Score)+'</strong> | '+(ConvertTo-HtmlText $Score.Status)+'</p><p>Weighted evidence score. Unknown checks earn no credit. Any critical finding overrides the numeric status. This report describes observed health, not a guarantee of future reliability.</p>')
    $risk=@($script:Results | Where-Object {$_.Status -eq 'CRITICAL' -or $_.Status -eq 'WARNING'} | Sort-Object Severity,Weight -Descending)
    Add-ReportSection $sections 'Top Risks' (New-ReportTable @($risk | Select-Object -First 10) @('Status','CheckName','Summary','Recommendation'))
    $actions='<ol>'
    foreach ($r in @($risk | Where-Object {$_.Recommendation} | Select-Object -First 15)) { $actions += '<li><strong>'+(ConvertTo-HtmlText $r.CheckName)+':</strong> '+(ConvertTo-HtmlText $r.Recommendation)+'</li>' }
    $actions += '</ol><p>No remediation was attempted. Investigate evidence before authorizing changes.</p>'
    Add-ReportSection $sections 'Recommended Technician Actions' $actions
    $coverageRows=@()
    foreach ($cat in @($script:Results | Group-Object Category)) { $s=Get-AssessmentScore $cat.Group $script:Config.MinimumCoverage; $coverageRows += @{Domain=$cat.Name; Coverage=([string]$s.Coverage+'%'); MissingRequired=($s.Missing -join ', ')} }
    Add-ReportSection $sections 'Assessment Coverage' ('<p>Required unavailable areas: '+(ConvertTo-HtmlText ($Score.Missing -join ', '))+'. Minimum coverage: '+$script:Config.MinimumCoverage+'%.</p>'+(New-ReportTable $coverageRows @('Domain','Coverage','MissingRequired')))
    foreach ($pair in @(@('Identity','System Overview'),@('Hardware','Hardware and Performance'),@('Storage','Storage'),@('Windows','Windows Health and Critical Services'),@('Patch','Patch and Reboot Posture'),@('Security','Security Posture'),@('Network','Network, DNS and Time'),@('Events','Event Log Analysis'))) {
        $rows=@($script:Results | Where-Object {$_.Category -eq $pair[0] -and $_.Applicable})
        $sectionHtml=New-ReportTable $rows @('CheckName','Status','Summary','Evidence','Recommendation')
        if ($pair[0] -eq 'Events') {
            $totalGroups=0; $groups=@()
            foreach ($r in $rows) { $totalGroups += $r.EventGroupCount; $groups += @($r.EventGroups) }
            $selected=@($groups | Sort-Object @{Expression={$_.Level}},@{Expression={$_.Last};Descending=$true},@{Expression={$_.Count};Descending=$true} | Select-Object -First $script:Config.MaxEventGroups)
            $sectionHtml += New-ReportTable $selected @('Log','Provider','EventID','Level','Count','First','Last','Summary','Action')
            $sectionHtml += '<p>Additional event groups omitted from display: '+[math]::Max(0,$totalGroups-$selected.Count)+'. Omitted findings still influence severity. Raw messages are intentionally not collected.</p>'
        }
        Add-ReportSection $sections $pair[1] $sectionHtml
    }
    $roleRows=@($script:Results | Where-Object {$_.Category -eq 'Roles'})
    if ($script:Roles.Count) {
        Add-ReportSection $sections 'Server Role Health' '<p>Applicable role packs detected from Windows evidence. SQL results cover platform indicators only.</p>'
        foreach ($role in $script:Roles) {
            # Role pack rows carry an explicit role tag assigned by orchestration.
            $rows=@($roleRows | Where-Object {$_.Source -eq $role.Name})
            Add-ReportSection $sections $role.Name (New-ReportTable $rows @('CheckName','Status','Summary','Evidence','Recommendation')) 3
        }
    }
    Add-ReportSection $sections 'Detailed Findings' (New-ReportTable @($script:Results | Where-Object {$_.Applicable}) @('Category','Subcategory','CheckName','Status','Required','CollectionSucceeded','CollectionTime') 400)
    Add-ReportSection $sections 'Unsupported / Unable to Assess' (New-ReportTable @($script:Results | Where-Object {-not $_.CollectionSucceeded}) @('Category','CheckName','Status','Summary','Recommendation'))
    $metadata=@(@{Property='Engine';Value=$script:EngineVersion},@{Property='SupportMatrixLastUpdated';Value=$script:SupportMatrixLastUpdated},@{Property='Assessment UTC';Value=$Identity.Timestamp},@{Property='Safety';Value='Read-only collection; no remediation. Optional local HTML file only when requested.'},@{Property='Event privacy';Value='Provider/ID summaries only; raw event messages omitted.'},@{Property='Revision history';Value='Native publish API is used. User-visible revision history requires tenant validation; no custom history is maintained.'})
    foreach ($key in @($script:Config.Keys | Sort-Object)) { $metadata += @{Property=('DHC_'+$key);Value=$script:Config[$key]} }
    Add-ReportSection $sections 'Assessment Metadata' (New-ReportTable $metadata @('Property','Value'))
    $html='<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Device Health Assessment</title></head><body style="font-family:Segoe UI,Arial,sans-serif;color:#243447;max-width:1280px;margin:32px auto;padding:0 24px"><nav><details><summary>Contents</summary><ul>'
    foreach ($s in $sections) { if ($s.'resource-type' -eq 'Document::Heading') { $html += '<li><a href="#section-'+$s.sort+'">'+(ConvertTo-HtmlText $s.content)+'</a></li>' } }
    $html += '</ul></details></nav>'
    foreach ($s in $sections) {
        if ($s.'resource-type' -eq 'Document::Heading') { $html += '<h'+$s.level+' id="section-'+$s.sort+'">'+(ConvertTo-HtmlText $s.content)+'</h'+$s.level+'>' }
        else { $html += $s.content }
        if ([Text.Encoding]::UTF8.GetByteCount([string]$s.content) -gt 500000) { throw 'Report section exceeds safety size limit.' }
    }
    $html += '</body></html>'
    if ([Text.Encoding]::UTF8.GetByteCount($html) -gt 4000000) { throw 'Report exceeds 4 MB safety limit.' }
    return @{Sections=@($sections.ToArray());Html=$html}
}

function ConvertTo-GlueJson {
    param($Value,[switch]$LegacySerializer)
    if ($PSVersionTable.PSVersion.Major -ge 3 -and -not $LegacySerializer) { return (ConvertTo-Json -InputObject $Value -Depth 40 -Compress) }
    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    $serializer=New-Object Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength=8388608; $serializer.RecursionLimit=100
    return $serializer.Serialize($Value)
}
function ConvertFrom-GlueJson {
    param([string]$Value,[switch]$LegacySerializer)
    if ($PSVersionTable.PSVersion.Major -ge 3 -and -not $LegacySerializer) { return (ConvertFrom-Json -InputObject $Value -ErrorAction Stop) }
    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    $serializer=New-Object Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength=8388608; $serializer.RecursionLimit=100
    return $serializer.DeserializeObject($Value)
}
function Assert-GlueId { param($Id) if ([string]$Id -notmatch '^[1-9][0-9]{0,18}$') { throw 'IT Glue returned an invalid resource ID.' } }
function Invoke-GlueTransport {
    param([string]$Method,[string]$Path,$Data,$Connection)
    # Only relative paths assembled by this component; API keys never follow redirects.
    if ($Path -notmatch '^/[a-zA-Z0-9_/?=&%\[\].-]+$') { throw 'Invalid API path.' }
    $request=[Net.HttpWebRequest]::Create($Connection.Endpoint+$Path)
    $request.Method=$Method; $request.Accept='application/vnd.api+json'; $request.AllowAutoRedirect=$false
    $request.Timeout=30000; $request.ReadWriteTimeout=30000
    $request.Headers.Add('x-api-key',$Connection.Key)
    $response=$null
    try {
        if ($null -ne $Data) {
            $request.ContentType='application/vnd.api+json'
            $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-GlueJson @{data=$Data}))
            $request.ContentLength=$bytes.Length
            $stream=$request.GetRequestStream(); try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Close() }
        } elseif ($Method -eq 'PATCH' -or $Method -eq 'POST') { $request.ContentLength=0 }
        $response=$request.GetResponse()
        $status=[int]$response.StatusCode
        if ($status -lt 200 -or $status -gt 299) { return @{Status=$status;Body=$null} }
        if ($status -eq 204) { return @{Status=$status;Body=$null} }
        $reader=New-Object IO.StreamReader($response.GetResponseStream(),[Text.Encoding]::UTF8)
        try {
            $buffer=New-Object char[] 4096; $body=New-Object Text.StringBuilder
            while (($n=$reader.Read($buffer,0,$buffer.Length)) -gt 0) { [void]$body.Append($buffer,0,$n); if ($body.Length -gt 8388608) { throw 'API response size limit.' } }
            return @{Status=$status;Body=(ConvertFrom-GlueJson $body.ToString())}
        } finally { $reader.Close() }
    } catch {
        $status=0
        if ($_.Exception.Response) { $status=[int]$_.Exception.Response.StatusCode; $_.Exception.Response.Close() }
        # Discard raw error body/exception. They may echo credentials or sensitive HTML.
        return @{Status=$status;Body=$null}
    } finally { if ($response) { $response.Close() }; $request.Abort() }
}
function Invoke-GlueRequest {
    param([string]$Method,[string]$Path,$Data,$Connection)
    for ($attempt=0;$attempt -lt 4;$attempt++) {
        $r=Invoke-GlueTransport $Method $Path $Data $Connection
        if ($r.Status -ge 200 -and $r.Status -lt 300) {
            if ($r.Status -eq 204 -and $Method -eq 'DELETE') { return $null }
            if ($null -eq $r.Body -or $r.Body.errors -or $null -eq $r.Body.data) { throw 'IT Glue returned an invalid success response; mutation outcome may be ambiguous.' }
            return $r.Body
        }
        if ($Method -eq 'GET' -and ($r.Status -eq 429 -or $r.Status -ge 500 -or $r.Status -eq 0) -and $attempt -lt 3) { Start-Sleep -Seconds ([int][math]::Pow(2,$attempt+1)); continue }
        $meaning=@{0='Transport/TLS failure or invalid response; mutation outcome may be ambiguous';401='Authentication rejected';403='Access forbidden';404='Resource/API unavailable';422='API validation rejected';429='Rate limit reached';500='API server failure'}
        $detail='HTTP request rejected'; if ($meaning.ContainsKey([int]$r.Status)) { $detail=$meaning[[int]$r.Status] }
        Write-Phase ('IT Glue '+$Method+' failed (HTTP '+$r.Status+'): '+$detail+'. Response content withheld.')
        throw ('IT Glue '+$Method+' failed (HTTP '+$r.Status+'): '+$detail+'. Response content withheld.')
    }
}
function Get-GlueCollection {
    param([string]$Path,$Connection)
    $sep='?'; if ($Path.Contains('?')) { $sep='&' }
    $seen=@{}
    for ($page=1;$page -le 1000;$page++) {
        $r=Invoke-GlueRequest GET ($Path+$sep+'page[number]='+$page+'&page[size]=100') $null $Connection
        $items=@($r.data)
        foreach ($item in $items) {
            Assert-GlueId $item.id
            if ($seen.ContainsKey([string]$item.id)) { throw 'IT Glue pagination returned repeated resource IDs.' }
            $seen[[string]$item.id]=$true; $item
        }
        # Do not follow server-controlled next URLs. Numeric pages preserve the endpoint allowlist.
        if (-not $r.links.next -and $items.Count -lt 100) { return }
        if ($items.Count -eq 0) { throw 'Invalid pagination: next link on an empty page.' }
    }
    throw 'IT Glue pagination exceeded its safety bound.'
}
function Find-ExactGlueResource {
    param([string]$Path,[string]$Name,$Connection)
    $all=@(Get-GlueCollection $Path $Connection)
    $matches=@($all | Where-Object {[string]$_.attributes.name -ieq $Name})
    if ($matches.Count -gt 1) { throw 'Duplicate exact IT Glue names found; resolve duplicate folders/documents before retrying.' }
    if ($matches.Count -eq 1) { Assert-GlueId $matches[0].id; return $matches[0] }
    return $null
}
function Get-OrCreateGlueResource {
    param([string]$ListPath,[string]$CreatePath,[string]$Name,$Body,$Connection)
    $r=Find-ExactGlueResource $ListPath $Name $Connection
    if ($r) { return $r }
    try { $created=(Invoke-GlueRequest POST $CreatePath $Body $Connection).data; Assert-GlueId $created.id }
    catch {
        # Never repeat POST, even when reconciliation finds nothing (eventual consistency).
        $r=Find-ExactGlueResource $ListPath $Name $Connection
        if (-not $r) { throw 'Create outcome not confirmed. No POST retry; check IT Glue before rerunning.' }
        return $r
    }
    $r=Find-ExactGlueResource $ListPath $Name $Connection
    if (-not $r -or [string]$r.id -ne [string]$created.id) { throw 'Created resource could not be uniquely reconciled.' }
    return $r
}
function Get-SectionAttributes {
    param($Section)
    $a=@{'resource-type'=[string]$Section.attributes.'resource-type';content=[string]$Section.attributes.content;sort=[int]$Section.attributes.sort}
    if ($a.'resource-type' -eq 'Document::Heading') { $a.level=[int]$Section.attributes.level }
    return $a
}
function ConvertTo-ComparableHtml {
    param([string]$Html)
    # Ignore presentation-only rewrites, not missing text, rows, links or semantic structure.
    # Never execute HTML or resolve external entities. Reject unparseable markup conservatively.
    if ($Html -match '<!DOCTYPE|<!ENTITY|<\?') { return $null }
    $normalized=$Html -replace '&nbsp;','&#160;' -replace '(?i)<br\s*/?>','<br />' -replace '(?i)<hr\s*/?>','<hr />'
    $xml=New-Object Xml.XmlDocument
    $xml.XmlResolver=$null; $xml.PreserveWhitespace=$false
    try { $xml.LoadXml('<dhc-root>'+$normalized+'</dhc-root>') } catch { return $null }
    return (ConvertTo-ComparableNode $xml.DocumentElement)
}
function ConvertTo-ComparableNode {
    param($Node)
    if ($Node.NodeType -eq [Xml.XmlNodeType]::Text -or $Node.NodeType -eq [Xml.XmlNodeType]::CDATA) {
        return (ConvertTo-HtmlText (([string]$Node.Value -replace '\s+',' ').Trim()))
    }
    if ($Node.NodeType -ne [Xml.XmlNodeType]::Element) { return '' }
    $name=$Node.LocalName.ToLowerInvariant()
    if ($name -eq 'b') { $name='strong' }; if ($name -eq 'i') { $name='em' }
    $children=''; foreach ($child in $Node.ChildNodes) { $children += ConvertTo-ComparableNode $child }
    if (@('dhc-root','thead','tbody','tfoot') -contains $name) { return $children }
    $attrs=''
    foreach ($attr in @($Node.Attributes | Sort-Object Name)) {
        if (@('style','class','border','cellpadding','cellspacing','width','height','align','valign') -contains $attr.Name.ToLowerInvariant()) { continue }
        $attrs += ' '+$attr.Name.ToLowerInvariant()+'="'+(ConvertTo-HtmlText $attr.Value)+'"'
    }
    return ('<'+$name+$attrs+'>'+$children+'</'+$name+'>')
}
function Get-SectionDifference {
    param($Actual,$Expected)
    $a=Get-SectionAttributes $Actual; $fields=@()
    if ($a.'resource-type' -ne $Expected.'resource-type') { $fields += 'resource-type' }
    if ($a.sort -ne $Expected.sort) { $fields += 'sort' }
    if ($a.'resource-type' -eq 'Document::Heading' -and $a.level -ne $Expected.level) { $fields += 'level' }
    if (-not (Test-SectionContentEquivalent $a.content ([string]$Expected.content) $a.'resource-type')) { $fields += ('content (expected chars='+([string]$Expected.content).Length+'; returned chars='+$a.content.Length+')') }
    return ($fields -join ', ')
}
function Test-SectionContentEquivalent {
    param([string]$Actual,[string]$Expected,[string]$Type)
    if (($Actual -replace '\s+',' ').Trim() -ceq ($Expected -replace '\s+',' ').Trim()) { return $true }
    if ($Type -ne 'Document::Text') { return $false }
    $a=ConvertTo-ComparableHtml $Actual; $b=ConvertTo-ComparableHtml $Expected
    return ($null -ne $a -and $null -ne $b -and $a -ceq $b)
}
function Test-SectionEquivalent {
    param($Actual,$Expected)
    $a=Get-SectionAttributes $Actual
    return ($a.'resource-type' -eq $Expected.'resource-type' -and $a.sort -eq $Expected.sort -and (Test-SectionContentEquivalent $a.content ([string]$Expected.content) $a.'resource-type') -and ($a.'resource-type' -ne 'Document::Heading' -or $a.level -eq $Expected.level))
}
function Save-GlueSection {
    param([string]$Path,$Desired,$Existing,$Connection)
    $body=@{type='document-sections';attributes=$Desired}
    if ($Existing) {
        Assert-GlueId $Existing.id
        $target=$Path+'/'+$Existing.id
        $before=(Invoke-GlueRequest GET $target $null $Connection).data
        if (-not (Test-SectionEquivalent $before (Get-SectionAttributes $Existing))) { throw 'Concurrent section change detected; update cancelled.' }
        if (Test-SectionEquivalent $before $Desired) { return $before }
        try { [void](Invoke-GlueRequest PATCH $target $body $Connection) }
        catch {
            $r=(Invoke-GlueRequest GET $target $null $Connection).data
            if (-not (Test-SectionEquivalent $r $Desired)) { throw 'Section update not confirmed; document may require manual review.' }
        }
        $result=(Invoke-GlueRequest GET $target $null $Connection).data
    } else {
        try { $result=(Invoke-GlueRequest POST $Path $body $Connection).data; Assert-GlueId $result.id }
        catch {
            $candidates=@(Get-GlueCollection $Path $Connection | Where-Object {Test-SectionEquivalent $_ $Desired})
            if ($candidates.Count -ne 1) { throw 'Section create outcome ambiguous. No create retry; manual review required.' }
            $result=$candidates[0]
        }
        $result=(Invoke-GlueRequest GET ($Path+'/'+$result.id) $null $Connection).data
    }
    Assert-GlueId $result.id
    if (-not (Test-SectionEquivalent $result $Desired)) { throw ('Section readback differs: '+(Get-SectionDifference $result $Desired)+'. Section ID='+$result.id+'; sort='+$Desired.sort+'.') }
    return $result
}
function Publish-HealthReport {
    param($Report,$Identity,$Connection,[string]$OrganizationId)
    Assert-GlueId $OrganizationId
    $base='/organizations/'+$OrganizationId+'/relationships'
    Write-Phase 'Locating Device Health Checks folder'
    $folder=Get-OrCreateGlueResource ($base+'/document_folders') ($base+'/document_folders') 'Device Health Checks' @{type='document-folders';attributes=@{name='Device Health Checks'}} $Connection
    Assert-GlueId $folder.id
    if ([string]$folder.attributes.'organization-id' -ne $OrganizationId) { throw 'Folder organization mismatch.' }
    Write-Phase 'Locating computer document'
    $list=$base+'/documents?filter[document_folder_id]='+$folder.id
    $doc=Get-OrCreateGlueResource $list ($base+'/documents') $Identity.Computer @{type='documents';attributes=@{name=$Identity.Computer;public=$false;is_uploaded=$false;document_folder_id=$folder.id}} $Connection
    Assert-GlueId $doc.id
    $docPath=$base+'/documents/'+$doc.id
    $doc=(Invoke-GlueRequest GET $docPath $null $Connection).data
    if ([string]$doc.attributes.'organization-id' -ne $OrganizationId -or [string]$doc.attributes.'document-folder-id' -ne [string]$folder.id -or [string]$doc.attributes.name -ine $Identity.Computer -or $doc.attributes.public -or $doc.attributes.'is-uploaded' -or $doc.attributes.archived) { throw 'Document scope/type/access validation failed.' }
    $path='/documents/'+$doc.id+'/relationships/sections'
    $old=@(Get-GlueCollection $path $Connection | Sort-Object {[int]$_.attributes.sort})
    if ($old.Count -gt 0) {
        if ($old.Count -lt 2 -or $old[0].attributes.content -ne 'Device Health Assessment' -or $old[1].attributes.content -notmatch 'DHC managed report schema 1') { throw 'Existing document is not recognized as a DHC-managed report. No sections changed.' }
        foreach ($s in $old) { if (@('Document::Heading','Document::Text') -notcontains $s.attributes.'resource-type') { throw 'Existing document contains unsupported section types. No sections changed.' } }
    }
    $changed=New-Object Collections.ArrayList
    $saved=New-Object Collections.ArrayList
    $stage='freshness guard'
    $warning=@{'resource-type'='Document::Text';sort=1;content=('<p><strong>DHC managed report schema 1 - UPDATE INCOMPLETE</strong></p><p>Latest assessment attempt: '+(ConvertTo-HtmlText $Identity.Timestamp)+'. Report replacement is in progress or failed. Remaining content may describe an earlier assessment; do not treat it as current. Manual review is required if this notice persists.</p>')}
    try {
        Write-Phase 'Updating document sections'
        # Establish and publish a visible freshness guard before modifying report content.
        if ($old.Count -eq 0) {
            $h=Save-GlueSection $path $Report.Sections[0] $null $Connection
            $w=Save-GlueSection $path $warning $null $Connection
            $old=@($h,$w)
        } else { $w=Save-GlueSection $path $warning $old[1] $Connection }
        [void](Invoke-GlueRequest PATCH ($docPath+'/publish') $null $Connection)
        for ($i=0;$i -lt $Report.Sections.Count;$i++) {
            $stage='section sort '+$i+' ('+$Report.Sections[$i].'resource-type'+')'
            $existing=$null; if ($i -lt $old.Count) { $existing=$old[$i] }
            if ($i -eq 1) { $existing=$w }
            $desired=$Report.Sections[$i]
            if ($i -eq 1) { $desired=$warning }
            if ($existing -and $existing.attributes.'resource-type' -ne $desired.'resource-type') { throw 'Managed section type/order mismatch; manual review required.' }
            $previous=$null; if ($existing) { $previous=Get-SectionAttributes $existing }
            $record=@{Existing=$existing;Before=$previous;After=$desired;Id=$null}
            [void]$changed.Add($record)
            $s=Save-GlueSection $path $desired $existing $Connection
            $record.Id=$s.id; [void]$saved.Add($s)
        }
        # Entire replacement has been written and read back before removing surplus old sections.
        $stage='surplus section cleanup'
        for ($i=$old.Count-1;$i -ge $Report.Sections.Count;$i--) {
            $current=(Invoke-GlueRequest GET ($path+'/'+$old[$i].id) $null $Connection).data
            if (-not (Test-SectionEquivalent $current (Get-SectionAttributes $old[$i]))) { throw 'Concurrent section edit detected; removal cancelled.' }
            [void](Invoke-GlueRequest DELETE ($path+'/'+$old[$i].id) $null $Connection)
        }
        # Replace the freshness guard last, only after all report content has been verified.
        $stage='final banner and verification'
        [void](Save-GlueSection $path $Report.Sections[1] $saved[1] $Connection)
        $final=@(Get-GlueCollection $path $Connection | Sort-Object {[int]$_.attributes.sort})
        if ($final.Count -ne $Report.Sections.Count) { throw 'Final section count mismatch.' }
        for ($i=0;$i -lt $final.Count;$i++) { if (-not (Test-SectionEquivalent $final[$i] $Report.Sections[$i])) { throw 'Final report verification failed.' } }
        Write-Phase 'Publishing document'
        $stage='final publish'
        $published=(Invoke-GlueRequest PATCH ($docPath+'/publish') $null $Connection).data
        Assert-GlueId $published.id
        $verify=(Invoke-GlueRequest GET $docPath $null $Connection).data
        if ([string]$verify.id -ne [string]$doc.id -or -not $verify.attributes.'published-at') { throw 'Publication metadata not confirmed.' }
        # Confirm uniqueness again, catching concurrent creates; no arbitrary winner.
        [void](Find-ExactGlueResource ($base+'/document_folders') 'Device Health Checks' $Connection)
        [void](Find-ExactGlueResource $list $Identity.Computer $Connection)
        return [string]$doc.id
    } catch {
        # Report only our bounded diagnostic vocabulary, never arbitrary response/exception text.
        $message=[string]$_.Exception.Message
        $safeReason='Unexpected local error ('+$_.Exception.GetType().Name+').'
        if ($message -match '^Section readback differs: [a-zA-Z0-9 (),=;.-]+$' -or $message -match '^IT Glue (GET|POST|PATCH|DELETE) failed \(HTTP [0-9]+\): [a-zA-Z0-9 /;.-]+$' -or $message -match '^(Concurrent section change detected; update cancelled\.|Section update not confirmed; document may require manual review\.|Section create outcome ambiguous\. No create retry; manual review required\.|Final section count mismatch\.|Final report verification failed\.)$') { $safeReason=$message }
        Write-Phase ('Publication failure at '+$stage+'; document ID='+$doc.id+'. '+$safeReason)
        Write-Phase 'Publication failed. Attempting a guarded restoration; document may require manual review.'
        # Restore only existing, still-identifiable sections whose content matches this attempt.
        # Deleted surplus sections and uncertain creates are not recreated blindly.
        for ($i=$changed.Count-1;$i -ge 0;$i--) {
            $r=$changed[$i]
            if (-not $r.Existing -or [int]$r.Before.sort -eq 1) { continue }
            try {
                $now=(Invoke-GlueRequest GET ($path+'/'+$r.Existing.id) $null $Connection).data
                if (Test-SectionEquivalent $now $r.After) { [void](Save-GlueSection $path $r.Before $now $Connection) }
            } catch { Write-Phase 'A prior section could not be safely restored.' }
        }
        try {
            if ($old.Count -ge 2) {
                $current=(Invoke-GlueRequest GET ($path+'/'+$old[1].id) $null $Connection).data
                # Do not overwrite a concurrent human edit while attempting a warning.
                if ((Test-SectionEquivalent $current $warning) -or (Test-SectionEquivalent $current $Report.Sections[1])) {
                    [void](Save-GlueSection $path $warning $current $Connection); [void](Invoke-GlueRequest PATCH ($docPath+'/publish') $null $Connection)
                } else { throw 'Concurrent summary change; warning not written.' }
            }
        } catch { Write-Phase 'Freshness warning could not be confirmed in IT Glue. Treat the document as unreliable.' }
        throw 'IT Glue document update failed; final document is not reliable. Manual review required.'
    }
}

function Invoke-DeviceHealthMain {
    param([bool]$SkipUpload,[string]$ReportPath,[string]$APIEndpoint)
    Initialize-HealthEngine
    try {
        Write-Phase 'Detecting environment'
        if (-not $env:COMPUTERNAME) { throw 'Windows COMPUTERNAME is unavailable.' }
        $script:Config=Get-HealthConfiguration
        if (-not $APIEndpoint) { $APIEndpoint=[Environment]::GetEnvironmentVariable('DHC_APIEndpoint') }
        if (-not $APIEndpoint) { $APIEndpoint='https://api.itglue.com' }
        if (@('https://api.itglue.com','https://api.eu.itglue.com','https://api.au.itglue.com') -notcontains $APIEndpoint) { throw 'DHC_APIEndpoint must be an exact supported HTTPS API endpoint.' }
        if (-not $SkipUpload) {
            if (-not $script:Secret.Trim()) { throw 'Datto variable strITGLUE is missing.' }
            Assert-GlueId $env:itGlueOrgID
            # TLS 1.2 only. Enum numeric form permits legacy parsing; unsupported CLR fails safely.
            try { [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]3072 }
            catch { throw 'This runtime cannot enable TLS 1.2 securely; publication unavailable.' }
        }
        $identity=@{Computer=$env:COMPUTERNAME;OS=[Environment]::OSVersion.VersionString;Role='Unknown';PowerShell=$PSVersionTable.PSVersion.ToString();Timestamp=[DateTime]::UtcNow.ToString('o');Unsupported=$false}
        $runtime=Get-RuntimeDecision $PSVersionTable.PSVersion ([IntPtr]::Size) $env:PROCESSOR_ARCHITEW6432
        $os=$null
        try { $os=@(Get-ReadOnlyWmi Win32_OperatingSystem)[0]; if ($os.Caption) { $identity.OS=$os.Caption+' (build '+$os.BuildNumber+')'; $identity.Role='Workstation'; if ([int]$os.ProductType -gt 1) { $identity.Role='Server' } } } catch { Write-Phase 'Bootstrap OS caption unavailable; kernel version retained.' }
        if ($runtime -eq 'Legacy') {
            $identity.Unsupported=$true
            Add-HealthCheckResult Runtime 'Runtime' 'Full assessment' UNSUPPORTED 'UNSUPPORTED - Full Device Health Assessment Could Not Run' ('Detected PowerShell='+$identity.PowerShell+'; required=5.1; OS='+$identity.OS) 'Plan a supported management runtime through normal change control. No remediation was attempted.' 'Legacy bootstrap' $true 5
        } elseif ($runtime -eq 'Degraded32Bit') {
            # Explicit degradation avoids unsafe command-line re-quoting and registry-view ambiguity.
            $identity.Unsupported=$true
            Add-HealthCheckResult Runtime 'Architecture' '32-bit process on 64-bit Windows' UNSUPPORTED 'Full assessment withheld because registry and provider views may be incomplete.' 'A 64-bit Windows PowerShell host is required on 64-bit Windows.' 'Configure the Datto component to run in 64-bit PowerShell.' 'Bootstrap' $true 5
        } else {
            try { Get-BaselineHealth }
            catch { Add-HealthCheckResult Runtime 'Baseline execution' 'Unexpected baseline interruption' UNKNOWN 'Baseline collection was interrupted; the report is incomplete.' '' 'Investigate collector execution permissions and runtime.' 'Orchestration' $true 5 }
            if ($os) {
                try {
                    $edition=Get-ReadRegistry 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'EditionID'
                    $l=Get-LifecycleObservation $os $edition
                    Add-HealthCheckResult Identity 'Lifecycle' $l.Name $l.Status $l.Summary $l.Evidence $l.Recommendation 'Support matrix' $false 2
                } catch { Add-HealthCheckResult Identity Lifecycle Lifecycle UNKNOWN 'OS lifecycle identity unavailable.' }
            }
            try {
                Find-InstalledRoles
                $identity.Role += '; '+(($script:Roles | ForEach-Object {$_.Name}) -join ', ')
                Get-RoleHealth
            } catch { Add-HealthCheckResult Runtime 'Role execution' 'Unexpected role interruption' UNKNOWN 'Role collection was interrupted; report is incomplete.' '' 'Investigate role detection and execution permissions.' 'Orchestration' $true 5 }
        }
        $score=Get-AssessmentScore $script:Results $script:Config.MinimumCoverage
        Write-Phase 'Building report'
        $report=New-HealthReport $identity $score
        if ($ReportPath) {
            # The only local file write, explicitly requested for development/QA. Parent must exist.
            $fullPath=[IO.Path]::GetFullPath($ReportPath)
            [IO.File]::WriteAllText($fullPath,$report.Html,(New-Object Text.UTF8Encoding($false)))
            Write-Phase ('Local preview written: '+$fullPath)
        }
        $id='Preview only'
        if (-not $SkipUpload) { Write-Phase 'Connecting to IT Glue'; $id=Publish-HealthReport $report $identity @{Endpoint=$APIEndpoint;Key=$script:Secret} $env:itGlueOrgID }
        else { Write-Phase 'Preview only: zero IT Glue requests.' }
        $exitCode=0; if ($score.Incomplete) { $exitCode=2 }
        Write-Phase ('Computer: '+$identity.Computer+' | OS: '+$identity.OS+' | PowerShell: '+$identity.PowerShell)
        Write-Phase ('Health Status: '+$score.Status+' | Health Score: '+$score.Score+' | Coverage: '+$score.Coverage+'% | Critical: '+$score.Critical+' | Warnings: '+$score.Warnings+' | Unknown: '+$score.Unknown)
        Write-Phase ('IT Glue Document ID: '+$id+' | Exit Code: '+$exitCode)
        return $exitCode
    } catch {
        # Only our fixed error messages are logged; arbitrary provider exception text is never printed.
        Write-Phase ('Configuration/execution/publication failure. '+(Protect-Text $_.Exception.Message 500)+' | Exit Code: 1')
        return 1
    }
}

# Dot-source is an intentional test seam, not a second deployment artifact.
if ($MyInvocation.InvocationName -ne '.') {
    $code=Invoke-DeviceHealthMain ([bool]$SkipUpload) $ReportPath $APIEndpoint
    exit $code
}
