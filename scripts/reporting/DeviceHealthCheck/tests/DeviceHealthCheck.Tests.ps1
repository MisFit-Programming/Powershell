# Offline regression suite. Windows PowerShell 5.1; no Pester/module installation.
[CmdletBinding()]
param([string]$SamplePath)
$ErrorActionPreference='Stop'
$source=Join-Path (Split-Path $PSScriptRoot -Parent) 'DeviceHealthCheck.ps1'
$tokens=$null; $parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
. $source
Initialize-HealthEngine
$script:Config=Get-HealthConfiguration
$script:Assertions=0
function Assert-True { param([bool]$Value,[string]$Label) if (-not $Value) { throw ('FAIL: '+$Label) }; $script:Assertions++ }
function Assert-Throws { param([scriptblock]$Action,[string]$Pattern='.') $thrown=$false; try { & $Action | Out-Null } catch { $thrown=$true; Assert-True ($_.Exception.Message -match $Pattern) ('Error should match '+$Pattern+'; received '+$_.Exception.Message) }; Assert-True $thrown ('Expected exception '+$Pattern) }
function Reset-Results { $script:Results=New-Object Collections.ArrayList }
function Test-Case { param([string]$Name,[scriptblock]$Action) & $Action; Write-Host ('PASS '+$Name) }

Test-Case 'Parser and legacy syntax guard' {
    $text=[IO.File]::ReadAllText($source)
    Assert-True ($text -notmatch '(?m)^#requires\s+-Version') 'No parser preemption'
    Assert-True ($text -notmatch '\[pscustomobject\]|\[ordered\]|::new\s*\(|\$PSScriptRoot|\s-(?:in|notin)\s|\?\?|\?\.') 'No known PS3+ language constructs'
    $dynamic=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and -not $n.GetCommandName()},$true))
    Assert-True ($dynamic.Count -eq 0) 'No arbitrary command invocation'
    $commands=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()} | Sort-Object -Unique)
    $forbidden=@($commands | Where-Object {$_ -match '^(Set-|Remove-|Clear-|Restart-|Stop-|Start-(?!Sleep)|Install-|Uninstall-|Enable-|Disable-|Repair-|Reset-|Test-Cluster|Invoke-CimMethod|Invoke-WmiMethod)'})
    Assert-True ($forbidden.Count -eq 0) 'No endpoint mutation cmdlets'
    $code=($tokens | Where-Object {$_.Kind -ne 'Comment'} | ForEach-Object {$_.Text}) -join ' '
    Assert-True ($code -notmatch 'ServerCertificateValidationCallback|SkipCertificateCheck|/resync|/register|/fix') 'No TLS bypass or native mutating switches'
    Assert-True ($commands -notcontains 'Get-BitLockerVolume' -and $commands -notcontains 'Get-Tpm') 'Do not obtain key-protector/TPM authorization objects'
    $nativeCalls=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-ReadOnlyNative'},$true))
    Assert-True ($nativeCalls.Count -eq 2) 'Only two reviewed native query calls'
}
Test-Case 'IT Glue presentation normalization preserves content verification' {
    $wanted=@{'resource-type'='Document::Text';sort=3;content='<table border="1" style="width:100%"><thead><tr><th>Metric</th></tr></thead><tbody><tr><td><strong>A &amp; B</strong></td></tr></tbody></table>'}
    $returned=@{id='99';attributes=@{'resource-type'='Document::Text';sort=3;content='<table><tr><th>Metric</th></tr><tr><td><b>A &#38; B</b></td></tr></table>'}}
    Assert-True (Test-SectionEquivalent $returned $wanted) 'Presentation stripping, table wrappers and entity normalization accepted'
    $returned.attributes.content=$returned.attributes.content.Replace('A &#38; B','Different')
    Assert-True (-not (Test-SectionEquivalent $returned $wanted)) 'Changed evidence rejected'
    Assert-True ((Get-SectionDifference $returned $wanted) -match 'content \(expected chars=') 'Safe mismatch metadata identifies content'
    $returned.attributes.content='<table><tr><td><b>A &#38; B</b></td></tr></table>'
    Assert-True (-not (Test-SectionEquivalent $returned $wanted)) 'Missing table row rejected'
    Assert-True (-not (Test-SectionContentEquivalent '<p><a href="https://other.invalid">link</a></p>' '<p><a href="https://example.invalid">link</a></p>' 'Document::Text')) 'Changed link not ignored'
    Assert-True ($null -eq (ConvertTo-ComparableHtml '<!DOCTYPE test><p>test</p>')) 'DTD rejected'
    Assert-True ($null -eq (ConvertTo-ComparableHtml '<table><td>broken')) 'Malformed markup not accepted'
}
Test-Case 'Threshold validation and large-volume formula' {
    Assert-True ((Get-DiskStatus 10TB 1TB $script:Config) -eq 'PASS') '10TB with 1TB free passes'
    Assert-True ((Get-DiskStatus 100GB 8GB $script:Config) -eq 'CRITICAL') 'Combined critical thresholds'
    Assert-True ((Get-DiskStatus 100GB 14GB $script:Config) -eq 'WARNING') 'Combined warning thresholds'
    Assert-True ((Get-DiskStatus 4GB 1GB $script:Config) -eq 'PASS') 'Small volume with 25 percent free is not emergency critical'
    Assert-True ((Get-DiskStatus 1.95GB 0.98GB $script:Config) -eq 'PASS') 'Reported small NTFS volume false positive fixed'
    Assert-True ((Get-DiskStatus 0.25GB 0.21GB $script:Config) -eq 'PASS') 'Reported small FAT32 volume false positive fixed'
    Assert-True ((Get-DiskStatus 4GB 0.01GB $script:Config) -eq 'CRITICAL') 'Actually exhausted small volume stays critical'
    Assert-True ((Get-DiskStatus 100GB 1GB $script:Config) -eq 'CRITICAL') 'Normal-size emergency volume still critical'
    Assert-True ((Get-DiskStatus 0 0 $script:Config) -eq 'UNKNOWN') 'Invalid volume unknown'
    $old=$env:DHC_EventDays
    try { $env:DHC_EventDays='7.2'; Assert-Throws {Get-HealthConfiguration} 'Invalid DHC_EventDays'; $env:DHC_EventDays='0'; Assert-Throws {Get-HealthConfiguration} 'Invalid'; $env:DHC_EventDays='14'; Assert-True ((Get-HealthConfiguration).EventDays -eq 14) 'Valid override' } finally { $env:DHC_EventDays=$old }
}
Test-Case 'Coverage, unknowns, required failure and critical override' {
    Reset-Results
    Add-HealthCheckResult Storage 'Volumes' 'C:' PASS 'ok' '' '' 'fixture' $true 5
    Add-HealthCheckResult Security 'SMART' 'SMART' UNSUPPORTED 'absent' '' '' 'fixture' $false 5
    Add-HealthCheckResult Roles 'No role' 'No role' 'NOT APPLICABLE' 'none' '' '' 'fixture' $true 50
    $s=Get-AssessmentScore $script:Results 80
    Assert-True ($s.Coverage -eq 50 -and $s.Score -eq 'Withheld' -and $s.Incomplete) 'N/A excluded; missing does not inflate'
    $s=Get-AssessmentScore $script:Results 40
    Assert-True ($s.Score -eq '50') 'Unknown earns zero credit'
    Reset-Results
    Add-HealthCheckResult Identity 'Identity' 'Identity' PASS 'ok' '' '' 'fixture' $true 100
    Add-HealthCheckResult Events 'System' 'System' UNKNOWN 'denied' '' '' 'fixture' $true 1
    $s=Get-AssessmentScore $script:Results 80
    Assert-True ($s.Coverage -gt 98 -and $s.Score -eq 'Withheld') 'Required unavailable area withholds even above coverage threshold'
    Reset-Results
    Add-HealthCheckResult Identity 'Identity' 'Identity' PASS 'ok' '' '' 'fixture' $true 100
    Add-HealthCheckResult Storage 'Storage' 'C:' CRITICAL 'low' '' '' 'fixture' $true 1
    $s=Get-AssessmentScore $script:Results 80
    Assert-True ($s.Score -eq '99' -and $s.Status -eq 'Critical' -and -not $s.Incomplete) 'Critical overrides score but is complete'
}
Test-Case 'Collector isolation and timeout' {
    Reset-Results
    Invoke-HealthProbe Storage 'SMART unavailable' {throw 'UNSUPPORTED: unavailable'}
    Assert-True ($script:Results[0].Status -eq 'UNSUPPORTED') 'Unsupported capability'
    Invoke-HealthProbe Events 'Denied log' {throw 'access denied'} $true
    Assert-True ($script:Results[1].Status -eq 'UNKNOWN') 'Error does not pass'
    Invoke-HealthProbe Identity 'Following check' {New-Observation 'Still running' PASS 'ok'} $true
    Assert-True ($script:Results[2].Status -eq 'PASS') 'Independent check survives'
    Invoke-HealthProbe Hardware 'Timeout fixture' {Start-Sleep -Seconds 5; New-Observation 'late' PASS 'must discard'} $false @{} 1
    Assert-True ($script:Results[3].Status -eq 'UNKNOWN') 'Timeout cannot return late PASS'
    $script:TimedOutProbes=0
    Invoke-HealthProbe Storage 'Partial critical then error' {New-Observation 'Critical before failure' CRITICAL 'Observed'; throw 'later query failed'} $true
    Assert-True (@($script:Results | Where-Object {$_.CheckName -eq 'Critical before failure' -and $_.Status -eq 'CRITICAL'}).Count -eq 1) 'Earlier critical observation survives later error'
    Invoke-HealthProbe Hardware 'Recovered provider failure' { try { throw 'provider unavailable' } catch { New-Observation 'Fallback sample' PASS 'valid fallback' } } $true
    Assert-True (@($script:Results | Where-Object {$_.Subcategory -eq 'Recovered provider failure' -and -not $_.CollectionSucceeded}).Count -eq 0) 'Handled fallback error does not poison probe success'
}
Test-Case 'Runtime dispatch and legacy JSON codec' {
    foreach ($v in @('2.0','3.0','4.0','5.0')) { Assert-True ((Get-RuntimeDecision ([version]$v) 8 '') -eq 'Legacy') ('Legacy branch '+$v) }
    Assert-True ((Get-RuntimeDecision ([version]'5.1') 8 '') -eq 'Full') '5.1 engine'
    Assert-True ((Get-RuntimeDecision ([version]'5.1') 4 'AMD64') -eq 'Degraded32Bit') 'WOW64 explicit degradation'
    Assert-True ((Get-RuntimeDecision ([version]'5.1') 4 '') -eq 'Full') 'Native 32-bit OS remains supported'
    $json=ConvertTo-GlueJson @{data=@{type='document-sections';attributes=@{content='<p>Unicode: caf'+[char]233+'</p>';sort=1}}} -LegacySerializer
    $decoded=ConvertFrom-GlueJson $json -LegacySerializer
    Assert-True ($decoded.data.attributes.sort -eq 1 -and $decoded.data.type -eq 'document-sections') 'JavaScriptSerializer bootstrap round trip'
}
Test-Case 'CPU fallback retains evidence and rejects unavailable samples' {
    function Start-Sleep {param($Seconds)}
    $script:CpuFixture='healthy'; $script:CpuCalls=0
    function Get-ReadOnlyWmi {
        param($Class,$Filter,$Namespace,$Properties)
        if ($Class -eq 'Win32_PerfFormattedData_PerfOS_Processor') { throw 'Performance provider unavailable' }
        $script:CpuCalls++
        if ($script:CpuFixture -eq 'missing') { return @{LoadPercentage=$null;NumberOfLogicalProcessors=4} }
        if ($script:CpuFixture -eq 'high') { return @{LoadPercentage=95;NumberOfLogicalProcessors=4} }
        @{LoadPercentage=20;NumberOfLogicalProcessors=4}; @{LoadPercentage=60;NumberOfLogicalProcessors=4}
    }
    $sample=Get-CpuSampleObservation
    Assert-True ($sample.Status -eq 'PASS' -and $sample.Summary -match '40%' -and $script:CpuCalls -eq 3) 'Fallback averages three valid observations'
    Assert-True ($sample.Evidence -match 'fallback') 'Fallback source disclosed'
    $script:CpuFixture='high'; Assert-True ((Get-CpuSampleObservation).Status -eq 'WARNING') 'Sustained high fallback CPU warns'
    $script:CpuFixture='missing'; Assert-Throws {Get-CpuSampleObservation} 'Invalid fallback'
}
Test-Case 'HTML injection and redaction' {
    $script:Secret='ITG.fixture-secret'
    $encoded=ConvertTo-HtmlText '<script>"& ITG.fixture-secret'
    Assert-True ($encoded -notmatch '<script>|fixture-secret') 'HTML and key removed'
    Assert-True ($encoded -match '&lt;script&gt;&quot;&amp;') 'Encoding retains safe content'
    $script:Secret=''
}
Test-Case 'Known lifecycle and unknown servicing channel' {
    $l=Get-LifecycleObservation @{BuildNumber='9200';ProductType=3} 'ServerStandard'
    Assert-True ($l.Status -eq 'WARNING') 'Server 2012 recognized as beyond standard support'
    $l=Get-LifecycleObservation @{BuildNumber='99999';ProductType=3} 'ServerStandard'
    Assert-True ($l.Status -eq 'UNKNOWN') 'Future build not guessed'
    $l=Get-LifecycleObservation @{BuildNumber='26100';ProductType=1} 'IoTEnterpriseS'
    Assert-True ($l.Status -eq 'UNKNOWN') 'Unknown client channel not guessed'
}

# Preserve real implementation functions before replacing dependencies with fixtures.
$realProbe=(Get-Item function:Invoke-HealthProbe).ScriptBlock
$realWmi=(Get-Item function:Get-ReadOnlyWmi).ScriptBlock
$realRegistry=(Get-Item function:Get-ReadRegistry).ScriptBlock
$realRequire=(Get-Item function:Require-Command).ScriptBlock
$realRegistryTest=(Get-Item function:Test-ReadRegistryKey).ScriptBlock
$realTransport=(Get-Item function:Invoke-GlueTransport).ScriptBlock
$script:Scenario=''
function Get-ReadOnlyWmi {
    param($Class,$Filter,$Namespace,$Properties)
    switch ($Class) {
        Win32_OperatingSystem { [pscustomobject]@{ProductType=3;Caption='Microsoft Windows Server 2012';BuildNumber='9200';SystemDrive='C:'} }
        Win32_Service {
            $names=@('RpcSs','DcomLaunch','EventLog','Winmgmt','BFE','MpsSvc')
            if ($script:Scenario -ne 'NoRoles') { $names += @('NTDS','DNS','DHCPServer','vmms','W3SVC','WAS','ClusSvc','CertSvc','MSSQLSERVER','LanmanServer','Spooler','TermService','wbengine') }
            foreach ($n in $names) { if (-not $Filter -or $Filter -match [regex]::Escape("'"+$n+"'")) { [pscustomobject]@{Name=$n;State='Running';StartMode='Auto'} } }
        }
        Win32_Share { if ($script:Scenario -ne 'NoRoles') { [pscustomobject]@{Name='Shared';Path='C:\Shares';Type=0;Status='OK'}; [pscustomobject]@{Name='SYSVOL';Path='C:\SYSVOL';Type=0}; [pscustomobject]@{Name='NETLOGON';Path='C:\SYSVOL';Type=0} } }
        Win32_Printer { if ($script:Scenario -ne 'NoRoles') { [pscustomobject]@{Name='Printer';Shared=$true;PrinterStatus=3;DetectedErrorState=2;WorkOffline=$false} } }
        Win32_PrintJob { }
        Win32_ShadowCopy { }
        Win32_ServerFeature { [pscustomobject]@{ID=10;Name='File Server'} }
        DfsrReplicatedFolderInfo { [pscustomobject]@{ReplicatedFolderName='SYSVOL';State=4} }
        default { throw ('Fixture does not implement '+$Class) }
    }
}
function Get-ReadRegistry { param($Path,$Name) if ($Name -eq 'TSAppCompat') { if ($script:Scenario -ne 'NoRoles') {return 1}; return 0 }; if ($Name -eq 'SysVolReady') {return 1}; if ($Name -eq 'LicensingMode') {return 4}; if ($Name -eq 'Active') {return 'Test CA'}; if ($Name -eq 'CACertHash') {return @()} }
function Test-ReadRegistryKey { param($Path) return ($script:Scenario -ne 'NoRoles') }
function Require-Command {param($Name,$Module) }
function Get-Module {param($ListAvailable,$Name,$ErrorAction) }
function Get-ADDomain {param($ErrorAction) [pscustomobject]@{DNSRoot='test.invalid';PDCEmulator='DC1';RIDMaster='DC1';InfrastructureMaster='DC1'} }
function Get-ADForest {param($ErrorAction) [pscustomobject]@{Name='test.invalid';SchemaMaster='DC1';DomainNamingMaster='DC1'} }
function Get-ADReplicationFailure {param($Target,$Scope,$ErrorAction) }
function Get-ADReplicationPartnerMetadata {param($Target,$Scope,$PartnerType,$ErrorAction) [pscustomobject]@{Partner='DC2';PartnerType='Inbound';LastReplicationSuccess=(Get-Date).AddHours(-1);LastReplicationResult=0} }
function Get-ADDomainController {param($Filter,$ErrorAction) 'DC1';'DC2' }
function Get-DnsServerZone {param($ErrorAction) if ($script:Scenario -eq 'DNSFailure') {throw 'fixture denial'}; [pscustomobject]@{ZoneName='test.invalid';IsPaused=$false;IsShutdown=$false;IsReverseLookupZone=$false} }
function Get-DnsServerForwarder {param($ErrorAction) [pscustomobject]@{IPAddress='192.0.2.1';UseRootHint=$true} }
function Resolve-DnsName {param($Name,$Type,$Server,[switch]$DnsOnly,$ErrorAction) [pscustomobject]@{Name=$Name;PrimaryServer='DC1'} }
function Get-DhcpServerv4Scope {param($ErrorAction) [pscustomobject]@{ScopeId='192.0.2.0';State='Active'} }
function Get-DhcpServerv4ScopeStatistics {param($ScopeId,$ErrorAction) [pscustomobject]@{PercentageInUse=98;AddressesFree=2;AddressesInUse=98} }
function Get-DhcpServerv4Failover {param($ErrorAction) [pscustomobject]@{Name='Pair';State='Normal';PartnerServer='DHCP2'} }
function Get-VM {param($ErrorAction) [pscustomobject]@{Name='VM1';State='Running';Status='Operating normally'} }
function Get-VMSnapshot {param($VMName,$ErrorAction) [pscustomobject]@{Name='Old';CreationTime=(Get-Date).AddDays(-9)} }
function Get-VMIntegrationService {param($VMName,$ErrorAction) [pscustomobject]@{Name='Heartbeat';Enabled=$true;PrimaryStatusDescription='OK'} }
function Get-VMHardDiskDrive {param($VMName,$ErrorAction) }
function Get-VMSwitch {param($ErrorAction) [pscustomobject]@{Name='Switch';SwitchType='Internal'} }
function Get-VMReplication {param($ErrorAction) [pscustomobject]@{VMName='VM1';Health='Critical';State='Error'} }
function Get-Website {param($ErrorAction) [pscustomobject]@{Name='Website';State='Stopped';Bindings=@{Collection=@()}} }
function Get-WebBinding {param($Protocol,$ErrorAction) }
function Get-ChildItem {param($Path,$ErrorAction) if ($Path -eq 'IIS:\AppPools') { [pscustomobject]@{Name='AppPool';State='Started'} } else {throw 'Unexpected enumeration'} }
function Get-WBSummary {param($ErrorAction) [pscustomobject]@{LastSuccessfulBackupTime=(Get-Date).AddDays(-1);LastBackupResultHR=0} }
function Get-ClusterNode {param($ErrorAction) [pscustomobject]@{Name='NODE1';State='Up'} }
function Get-ClusterGroup {param($ErrorAction) [pscustomobject]@{Name='Group';State='Online';OwnerNode='NODE1'} }
function Get-ClusterResource {param($ErrorAction) [pscustomobject]@{Name='Resource';State='Failed';ResourceType='IP Address'} }
function Get-ClusterQuorum {param($ErrorAction) [pscustomobject]@{QuorumType='NodeAndFileShareMajority'} }
function Get-WinEvent {param($FilterHashtable,$MaxEvents,$ErrorAction) throw 'fixture event log unavailable' }
function Invoke-HealthProbe {
    param($Category,$Name,$Body,$Required=$false,$Context=@{},$Timeout=0)
    $cfg=$script:Config; $ctx=$Context
    try { $rows=@(& $Body); if (-not $rows.Count) {throw 'empty'} }
    catch { $rows=@(New-Observation $Name UNKNOWN 'Fixture collection failed') }
    foreach ($r in $rows) { Add-HealthCheckResult $Category $Name $r.Name $r.Status $r.Summary $r.Evidence $r.Recommendation $Name $Required 1 }
}
Test-Case 'Automatic role detection and no-role device' {
    Reset-Results; $script:Scenario='AllRoles'; Find-InstalledRoles
    Assert-True ($script:Roles.Count -eq 12) 'All twelve v1 packs detected'
    Reset-Results; $script:Scenario='NoRoles'; Find-InstalledRoles
    Assert-True ($script:Roles.Count -eq 0) 'No irrelevant role sections'
}
Test-Case 'Role collectors execute with Windows fixtures' {
    Reset-Results; $script:Scenario='AllRoles'; Find-InstalledRoles; Get-RoleHealth
    foreach ($role in $script:Roles) { Assert-True (@($script:Results | Where-Object {$_.Source -eq $role.Name -and $_.Category -eq 'Roles'}).Count -gt 0) ('Role produced results: '+$role.Name) }
    Assert-True (@($script:Results | Where-Object {$_.CheckName -eq '192.0.2.0' -and $_.Status -eq 'CRITICAL'}).Count -eq 1) 'DHCP exhaustion evaluated'
    Assert-True (@($script:Results | Where-Object {$_.CheckName -eq 'Checkpoints VM1' -and $_.Status -eq 'WARNING'}).Count -eq 1) 'Old checkpoint evaluated'
    Assert-True (@($script:Results | Where-Object {$_.CheckName -eq 'Resource Resource' -and $_.Status -eq 'CRITICAL'}).Count -eq 1) 'Cluster resource failure evaluated'
    Assert-True (@($script:Results | Where-Object {$_.CheckName -eq 'Website' -and $_.Status -eq 'WARNING'}).Count -eq 1) 'IIS site state evaluated'
    $script:Scenario='DNSFailure'; Reset-Results; Get-RoleHealth
    Assert-True (@($script:Results | Where-Object {$_.Subcategory -eq 'DNS Server' -and $_.Status -eq 'UNKNOWN'}).Count -eq 1) 'One failed role remains unknown'
    Assert-True (@($script:Results | Where-Object {$_.CheckName -eq '192.0.2.0'}).Count -eq 1) 'Following role still runs'
}
Test-Case 'Curated events, privacy, grouping, limits and critical priority' {
    function Get-WinEvent {
        param($FilterHashtable,$MaxEvents,$ErrorAction)
        Assert-True ($FilterHashtable.LogName -eq 'System' -and $FilterHashtable.Level.Count -eq 3 -and $MaxEvents -gt 0) 'Server-side bounded event filter'
        foreach ($id in @(41,41,51,51,51,2,3,4)) { [pscustomobject]@{LogName='System';ProviderName='disk';Id=$id;Level=2;TimeCreated=(Get-Date).AddMinutes(-$id);Message='PRIVATE PASSWORD SHOULD NEVER BE READ'} }
    }
    $cfg=@{}; foreach ($k in $script:Config.Keys) {$cfg[$k]=$script:Config[$k]}; $cfg.MaxEventGroups=2; $cfg.MaxEventsPerLog=7
    $obs=@(Read-CuratedEvents System)
    Assert-True ($obs[0].Status -eq 'CRITICAL') 'Repetition escalates storage severity'
    Assert-True ($obs[0].EventGroups.Count -eq 2 -and $obs[0].EventGroupCount -gt 2) 'Displayed groups bounded; total preserved'
    Assert-True ($obs[1].Status -eq 'UNKNOWN') 'Event query cap lowers coverage'
    Assert-True (($obs | Out-String) -notmatch 'PRIVATE PASSWORD') 'Raw event payload excluded'
}

# Restore collection dependencies; all remaining checks use synthetic findings and an in-memory API.
Set-Item function:Invoke-HealthProbe $realProbe
Set-Item function:Get-ReadOnlyWmi $realWmi
Set-Item function:Get-ReadRegistry $realRegistry
Set-Item function:Test-ReadRegistryKey $realRegistryTest
Set-Item function:Require-Command $realRequire
Reset-Results
$script:Roles=@()
Add-HealthCheckResult Identity 'Identity' 'Computer <test> & fixture' INFO 'Synthetic report' '' '' 'Fixture' $true 2
Add-HealthCheckResult Storage 'Volume capacity' 'C:' CRITICAL 'Free space below emergency floor' 'Size=100 GB; Free=1 GB' 'Review growth and capacity.' 'Fixture' $true 5
$identity=@{Computer='DHC-TEST';Role='Workstation';OS='Windows 11 fixture';Timestamp=[datetime]::UtcNow.ToString('o');PowerShell='5.1';Unsupported=$false}
$score=Get-AssessmentScore $script:Results
$report=New-HealthReport $identity $score
Test-Case 'Native report structure and safe local preview' {
    Assert-True ($report.Sections[0].'resource-type' -eq 'Document::Heading') 'Native heading'
    Assert-True (@($report.Sections | Where-Object {$_.content -eq 'Executive Summary' -and $_.'resource-type' -eq 'Document::Heading'}).Count -eq 1) 'Executive native heading'
    Assert-True ($report.Html -match 'href="#section-') 'Local contents clickable'
    Assert-True ($report.Html -match '&lt;test&gt; &amp;') 'Windows values encoded'
    $xmlText=$report.Html -replace '<!DOCTYPE html>','' -replace '<meta charset="utf-8">','<meta charset="utf-8" />' -replace '<br>','<br />'
    $doc=New-Object Xml.XmlDocument; $doc.XmlResolver=$null; $doc.LoadXml($xmlText)
    Assert-True ($doc.DocumentElement.Name -eq 'html') 'HTML has balanced structure'
    foreach ($a in @($doc.SelectNodes('//nav//a'))) { $anchor=$a.GetAttribute('href').Substring(1); Assert-True ($null -ne $doc.SelectSingleNode('//*[@id="'+$anchor+'"]')) ('Contents target '+$anchor) }
    if ($SamplePath) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($SamplePath),$report.Html,(New-Object Text.UTF8Encoding($false))) }
}

function Reset-Api {
    $script:Folders=@(); $script:Documents=@(); $script:Sections=@(); $script:NextId=100
    $script:Requests=New-Object Collections.ArrayList; $script:Fault=''; $script:FaultUsed=$false; $script:StatusQueue=@()
}
function New-ApiResource {param($Type,$Attributes) $script:NextId++; @{id=[string]$script:NextId;type=$Type;attributes=$Attributes} }
function Copy-Hash {param($Value) $h=@{}; foreach ($key in $Value.Keys) {$h[$key]=$Value[$key]}; $h }
function Invoke-GlueTransport {
    param($Method,$Path,$Data,$Connection)
    [void]$script:Requests.Add(@{Method=$Method;Path=$Path;Data=$Data})
    if ($script:StatusQueue.Count) { $status=$script:StatusQueue[0]; $script:StatusQueue=@($script:StatusQueue | Select-Object -Skip 1); if ($status -ne 200) {return @{Status=$status;Body=$null}} }
    $clean=$Path -replace '\?.*$',''
    if ($script:Fault -eq 'Partial' -and -not $script:FaultUsed -and $Method -eq 'PATCH' -and $clean -match '/sections/' -and $Data.attributes.sort -eq 5) { $script:FaultUsed=$true; return @{Status=422;Body=$null} }
    if ($Method -eq 'GET') {
        if ($script:Fault -eq 'Paged' -and $clean -match '/document_folders$') {
            if ($Path -match 'page\[number\]=1(?:&|$)') {
                $page=@(); for ($p=1;$p -le 100;$p++) {$page += @{id=[string]$p;attributes=@{name=('Folder '+$p)}}}
                return @{Status=200;Body=@{data=$page;links=@{next='https://untrusted.invalid/credential-trap'}}}
            }
            return @{Status=200;Body=@{data=@(@{id='101';attributes=@{name='Last'}})}}
        }
        if ($clean -match '/document_folders$') {return @{Status=200;Body=@{data=@($script:Folders)}}}
        if ($clean -match '/relationships/documents$') {return @{Status=200;Body=@{data=@($script:Documents)}}}
        if ($clean -match '/relationships/documents/(\d+)$') { $d=@($script:Documents | Where-Object {$_.id -eq $matches[1]}); if ($d.Count -ne 1) {return @{Status=404}}; return @{Status=200;Body=@{data=$d[0]}} }
        if ($clean -match '/sections$') {return @{Status=200;Body=@{data=@($script:Sections)}}}
        if ($clean -match '/sections/(\d+)$') { $sid=$matches[1]; $s=@($script:Sections | Where-Object {$_.id -eq $sid}); if ($s.Count -ne 1) {return @{Status=404}}; return @{Status=200;Body=@{data=$s[0]}} }
    }
    if ($Method -eq 'POST') {
        if ($script:Fault -eq 'EmptyCreate') {return @{Status=0}}
        $a=Copy-Hash $Data.attributes
        if ($clean -match '/document_folders$') { $a['organization-id']='42'; $r=New-ApiResource 'document-folders' $a; $script:Folders += $r }
        elseif ($clean -match '/relationships/documents$') { $a['organization-id']='42';$a['document-folder-id']=$a.document_folder_id; $a['is-uploaded']=$false; $r=New-ApiResource 'documents' $a; $script:Documents += $r }
        elseif ($clean -match '/sections$') { $r=New-ApiResource 'document-sections' $a; $script:Sections += $r }
        else {throw ('Unexpected POST '+$Path)}
        if (-not $script:FaultUsed -and ($script:Fault -eq 'Ambiguous' -or ($script:Fault -eq 'AmbiguousDocument' -and $Data.type -eq 'documents') -or ($script:Fault -eq 'AmbiguousSection' -and $Data.type -eq 'document-sections'))) {$script:FaultUsed=$true;return @{Status=0}}
        return @{Status=201;Body=@{data=$r}}
    }
    if ($Method -eq 'PATCH') {
        if ($clean -match '/publish$') { $script:Documents[0].attributes['published-at']=[datetime]::UtcNow.ToString('o');return @{Status=200;Body=@{data=$script:Documents[0]}} }
        if ($clean -match '/sections/(\d+)$') { $sid=$matches[1]; $r=@($script:Sections | Where-Object {$_.id -eq $sid})[0]; $r.attributes=Copy-Hash $Data.attributes; return @{Status=200;Body=@{data=$r}} }
    }
    if ($Method -eq 'DELETE' -and $clean -match '/sections/(\d+)$') { $sid=$matches[1]; $script:Sections=@($script:Sections | Where-Object {$_.id -ne $sid}); return @{Status=204} }
    throw ('Unexpected mock request '+$Method+' '+$Path)
}
function Start-Sleep {param($Seconds) } # No wall-clock delay for retry tests.
$conn=@{Endpoint='https://api.itglue.com';Key='ITG.fixture-key'}
Test-Case 'First publication creates native folder/document and second reuses ID' {
    Reset-Api
    $id=Publish-HealthReport $report $identity $conn '42'
    Assert-True ($script:Folders.Count -eq 1 -and $script:Documents.Count -eq 1) 'Single folder/document created'
    Assert-True ($script:Sections.Count -eq $report.Sections.Count) 'All sections present'
    $before=@($script:Requests | Where-Object {$_.Method -eq 'POST'}).Count
    $second=Publish-HealthReport $report $identity $conn '42'
    Assert-True ($id -eq $second) 'Document ID retained'
    Assert-True (@($script:Requests | Where-Object {$_.Method -eq 'POST'}).Count -eq $before) 'No second-run creates'
    Assert-True (@($script:Requests | Where-Object {$_.Path -like '*/publish'}).Count -eq 4) 'Freshness guard and final publish per run'
}
Test-Case 'Duplicate folder/document detection and invalid IDs' {
    $script:Folders += (New-ApiResource 'document-folders' (Copy-Hash $script:Folders[0].attributes))
    Assert-Throws {Publish-HealthReport $report $identity $conn '42'} 'Duplicate'
    $script:Folders=@($script:Folders[0]); $script:Documents += (New-ApiResource 'documents' (Copy-Hash $script:Documents[0].attributes))
    Assert-Throws {Publish-HealthReport $report $identity $conn '42'} 'Duplicate'
    $script:Documents=@($script:Documents[0])
    foreach ($bad in @('0','-1','abc','1/2','')) { Assert-Throws {Assert-GlueId $bad} 'invalid' }
}
Test-Case 'Ambiguous create reconciles without repeating POST' {
    Reset-Api; $script:Fault='Ambiguous'
    [void](Publish-HealthReport $report $identity $conn '42')
    Assert-True (@($script:Requests | Where-Object {$_.Method -eq 'POST' -and $_.Path -like '*/document_folders'}).Count -eq 1) 'Timed-out folder create is not retried'
    Assert-True ($script:Folders.Count -eq 1) 'No duplicate after ambiguous success'
    foreach ($fault in @('AmbiguousDocument','AmbiguousSection')) {
        Reset-Api; $script:Fault=$fault
        [void](Publish-HealthReport $report $identity $conn '42')
        Assert-True ($script:Documents.Count -eq 1 -and $script:Sections.Count -eq $report.Sections.Count) ('No duplicates after '+$fault)
        Assert-True (@($script:Requests | Where-Object {$_.Method -eq 'POST'}).Count -eq ($report.Sections.Count+2)) ('No repeated POST after '+$fault)
    }
    Reset-Api; $script:Fault='EmptyCreate'
    Assert-Throws {Publish-HealthReport $report $identity $conn '42'} 'No POST retry'
    Assert-True (@($script:Requests | Where-Object {$_.Method -eq 'POST'}).Count -eq 1) 'No confirmed creation stops safely'
    Reset-Api; [void](Publish-HealthReport $report $identity $conn '42')
}
Test-Case 'Pagination and untrusted next-link protection' {
    $script:Fault='Paged'; $before=$script:Requests.Count
    $rows=@(Get-GlueCollection '/organizations/42/relationships/document_folders' $conn)
    Assert-True ($rows.Count -eq 101) 'All pages collected'
    Assert-True (($script:Requests.Count-$before) -eq 2) 'Two bounded numeric pages'
    Assert-True (@($script:Requests | Where-Object {$_.Path -match 'untrusted'}).Count -eq 0) 'Server next URL not followed'
    $script:Fault=''
}
Test-Case 'HTTP failures, bounded safe retry and no blind mutation retry' {
    foreach ($code in @(401,403,404,422)) {
        $script:StatusQueue=@($code); $before=$script:Requests.Count
        Assert-Throws {Invoke-GlueRequest GET '/organizations/42/relationships/document_folders' $null $conn} ('HTTP '+$code)
        Assert-True (($script:Requests.Count-$before) -eq 1) ('No retry for '+$code)
    }
    foreach ($code in @(429,500)) {
        $script:StatusQueue=@($code,$code,200); $before=$script:Requests.Count
        [void](Invoke-GlueRequest GET '/organizations/42/relationships/document_folders' $null $conn)
        Assert-True (($script:Requests.Count-$before) -eq 3) ('GET retry '+$code)
    }
    $script:StatusQueue=@(500,500,500,500); $before=$script:Requests.Count
    Assert-Throws {Invoke-GlueRequest GET '/organizations/42/relationships/document_folders' $null $conn} 'HTTP 500'
    Assert-True (($script:Requests.Count-$before) -eq 4) 'GET retry bounded'
    $script:StatusQueue=@(500); $before=$script:Requests.Count
    Assert-Throws {Invoke-GlueRequest POST '/organizations/42/relationships/document_folders' @{type='document-folders';attributes=@{name='test'}} $conn} 'HTTP 500'
    Assert-True (($script:Requests.Count-$before) -eq 1) 'POST not retried'
}
Test-Case 'Partial section failure retains freshness warning and returns failure' {
    $script:Fault='Partial'; $script:FaultUsed=$false
    $oldExecutive=$report.Sections[3].content
    $report.Sections[3].content += '<p>Changed executive details.</p>'
    $report.Sections[5].content += '<p>New assessment attempt.</p>'
    Assert-Throws {Publish-HealthReport $report $identity $conn '42'} 'not reliable'
    $summary=@($script:Sections | Where-Object {$_.attributes.sort -eq 1})[0]
    Assert-True ($summary.attributes.content -match 'UPDATE INCOMPLETE') 'Failure visibly marked'
    Assert-True ($script:Sections.Count -ge $report.Sections.Count) 'No blank document'
    Assert-True (@($script:Sections | Where-Object {$_.attributes.sort -eq 3})[0].attributes.content -eq $oldExecutive) 'Earlier changed section restored from snapshot'
}
Test-Case 'Legacy unsupported report is executive-first and score withheld' {
    Reset-Results; $script:Roles=@(); $identity.Unsupported=$true; $identity.PowerShell='2.0'
    Add-HealthCheckResult Runtime Runtime 'Full assessment' UNSUPPORTED 'Requires 5.1' '' '' 'Legacy bootstrap' $true 5
    $s=Get-AssessmentScore $script:Results; $r=New-HealthReport $identity $s
    Assert-True ($s.Score -eq 'Withheld' -and $s.Incomplete) 'Unsupported withholding'
    Assert-True ($r.Html -match 'UNSUPPORTED - Full Device Health Assessment Could Not Run') 'Required unsupported title'
    Assert-True ($r.Html -match 'Required PowerShell: 5.1' -and $r.Html -match 'No remediation was attempted') 'Legacy explanation'
}
Test-Case 'Main orchestration exit codes and zero-request preview' {
    function Get-ReadOnlyWmi {param($Class,$Filter,$Namespace,$Properties) [pscustomobject]@{Caption=$script:FixtureOS;BuildNumber='9200';ProductType=3} }
    function Get-ReadRegistry {param($Path,$Name) 'ServerStandard' }
    function Get-RuntimeDecision {param($Version,$PointerSize,$Wow64) $script:FixtureRuntime }
    function Get-BaselineHealth {
        Add-HealthCheckResult Storage Storage 'C:' CRITICAL 'Low capacity' '' '' 'fixture' $true 5
        if ($script:FixtureFailure) { Add-HealthCheckResult Events System System UNKNOWN 'Denied' '' '' 'fixture' $true 5 }
    }
    function Find-InstalledRoles { $script:Roles=@() }
    function Get-RoleHealth { }
    $oldKey=$env:strITGLUE; $oldOrg=$env:itGlueOrgID
    try {
        $env:strITGLUE='ITG.fixture-key'; $env:itGlueOrgID='42'; $script:FixtureRuntime='Full'; $script:FixtureFailure=$false
        foreach ($caption in @('Windows 11 fixture','Windows Server 2012 fixture')) {
            Reset-Api; $script:FixtureOS=$caption
            $result=Invoke-DeviceHealthMain $false '' ''
            Assert-True ($result -eq 0) 'Critical health with successful collection/publication exits zero'
        }
        $before=$script:Requests.Count; $result=Invoke-DeviceHealthMain $true '' ''
        Assert-True ($result -eq 0 -and $script:Requests.Count -eq $before) 'SkipUpload makes zero API requests'
        $script:FixtureFailure=$true; $result=Invoke-DeviceHealthMain $false '' ''
        Assert-True ($result -eq 2) 'Published incomplete assessment exits two'
        foreach ($runtime in @('Legacy','Degraded32Bit')) {
            $script:FixtureRuntime=$runtime; $result=Invoke-DeviceHealthMain $false '' ''
            Assert-True ($result -eq 2) ('Published unsupported path '+$runtime)
        }
        $env:itGlueOrgID='invalid'; $result=Invoke-DeviceHealthMain $false '' ''
        Assert-True ($result -eq 1) 'Invalid configuration exits one'
    } finally {$env:strITGLUE=$oldKey; $env:itGlueOrgID=$oldOrg}
}
Write-Host ('SUCCESS: '+$script:Assertions+' assertions; offline only. Native TOC, revision history, legacy VMs and live API behavior remain manual validation items.')
