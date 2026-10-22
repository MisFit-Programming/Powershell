# Offline regression tests. No Pester or modules required. No external delivery.
# Run with Windows PowerShell 5.1.
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$source=Join-Path $root 'Invoke-TicketDiagnostics.ps1'
$errors=$null;$tokens=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
. $source
$script:assertions=0
function Assert { param([bool]$Condition,[string]$Label) if (-not $Condition) { throw "FAIL: $Label" };$script:assertions++ }
function Throws { param([scriptblock]$Action,[string]$Label) $caught=$false;try { & $Action | Out-Null } catch {$caught=$true};Assert $caught $Label }
$temp=Join-Path $env:TEMP ('CrownDiagnosticTests-'+[guid]::NewGuid().ToString())
$null=New-Item -ItemType Directory -Path $temp
$savedToken=$env:CROWN_DIAGNOSTICS_TOKEN
try {
    $env:CROWN_DIAGNOSTICS_TOKEN='unit-test-secret-123'
    Assert ((Protect-DiagnosticText 'password="two words" token=abc Bearer xyz unit-test-secret-123') -notmatch 'two words|=abc|Bearer xyz|unit-test-secret-123') 'Secret redaction'
    Assert ((Protect-DiagnosticText '{"token":"json-secret","password":"many words"} Authorization: Basic YWJjOmRlZg==') -notmatch 'json-secret|many words|YWJjOmRlZg') 'JSON secrets and Basic authorization redacted'
    Assert ((Protect-DiagnosticText '123456-123456-123456-123456-123456-123456-123456-123456') -eq '[REDACTED-RECOVERY-KEY]') 'Recovery key redaction'
    $safe=ConvertTo-SafeDiagnosticValue @{nested=@(@{value='token=hidden';unicode='caf'+[char]0xE9})}
    Assert ($safe.nested[0].value -eq 'token=[REDACTED]') 'Recursive redaction'
    Assert ($safe.nested[0].unicode -eq ('caf'+[char]0xE9)) 'Unicode preserved'
    Assert ((ConvertTo-SafeDiagnosticValue ([DayOfWeek]::Monday)) -eq 'Monday') 'Enums retain readable names'
    Assert ((ConvertTo-MarkdownLiteral '<script>|`[link]') -eq '&lt;script&gt;&#124;&#96;&#91;link&#93;') 'Markdown escaping'
    $script:WorkerFile=Join-Path $temp 'events.jsonl'
    function Get-WinEvent {
        param($FilterHashtable,$MaxEvents,$ErrorAction)
        for ($i=0;$i -lt $MaxEvents;$i++) { [pscustomobject]@{ProviderName='Unit';Id=100;Level=2;RecordId=$i;TimeCreated=(Get-Date);Message=('x'*2500)+' password=test'} }
    }
    Read-DiagnosticEvents 'System' 7 3
    $records=@(Get-Content $script:WorkerFile | ForEach-Object { $_ | ConvertFrom-Json })
    Assert (@($records[0].data).Count -eq 3) 'Event cap enforced'
    Assert ($records[1].data.Capped -eq $true) 'Event cap reported'
    Assert ($records[0].data[0].Message.Length -lt 2100) 'Message bound enforced'
    Remove-Item Function:\Get-WinEvent

    $collectors=@(
        [pscustomobject]@{Name='Storage';Source='fixture';Status='Complete';Error='';Records=@([pscustomobject]@{kind='disks';data=@([pscustomobject]@{DeviceID='C:';Size=100GB;FreeSpace=1GB})})},
        [pscustomobject]@{Name='Missing';Source='fixture';Status='TimedOut';Error='Test timeout';Records=@()},
        [pscustomobject]@{Name='Events';Source='fixture';Status='Partial';Error='';Records=$records},
        [pscustomobject]@{Name='Role';Source='fixture';Status='NotApplicable';Error='';Records=@()},
        [pscustomobject]@{Name='Empty';Source='fixture';Status='Complete';Error='';Records=@([pscustomobject]@{kind='empty';data=@()},[pscustomobject]@{kind='null';data=$null})}
    )
    $findings=@(Get-DiagnosticFindings $collectors)
    Assert (@($findings | Where-Object Id -eq 'storage.free.C:').Count -eq 1) 'Low space finding'
    Assert (@($findings | Where-Object Id -eq 'collection.Missing').Count -eq 1) 'Missing evidence finding'
    $evidence=[ordered]@{SchemaVersion='1.0';ScriptVersion='test';RunId=[guid]::NewGuid().ToString();Device='TEST-PC';TicketReference='T-1';Symptoms='<script>alert(1)</script> '+[char]0xE9;StartedUtc=[datetime]::UtcNow.ToString('o');EndedUtc=[datetime]::UtcNow.ToString('o');Collectors=$collectors;Findings=$findings}
    $bundle=Join-Path $temp 'bundle';$null=New-Item -ItemType Directory -Path $bundle
    $zip=Save-DiagnosticBundle $evidence $bundle
    Assert (Test-Path $zip) 'ZIP created'
    $report=[IO.File]::ReadAllText((Join-Path $bundle 'Report.md'))
    Assert ($report -notmatch '<script>') 'No executable HTML in report'
    Assert ($report.Contains([char]0xE9)) 'UTF8 report preserves Unicode'
    Assert ($report -match '<pre>\[\s*\]</pre>' -and $report.Contains('<pre>null</pre>')) 'Empty and null evidence render safely'
    $payload=New-DiagnosticPayload $bundle
    $p=$payload | ConvertFrom-Json
    Assert ($p.deliveryMode -eq 'full') 'Full payload generated'
    Assert ($p.runId -eq $evidence.RunId) 'Stable run ID'
    $small=New-DiagnosticPayload $bundle 2000 | ConvertFrom-Json
    Assert ($small.deliveryMode -eq 'summary-only' -and -not $small.zipBase64 -and -not $small.markdown) 'Oversize summary fallback'
    Assert ([Text.Encoding]::UTF8.GetByteCount(($small | ConvertTo-Json -Compress)) -le 2000) 'Payload byte cap'

    function Invoke-RestMethod { param($Uri,$Method,$Headers,$ContentType,$Body,$TimeoutSec,$ErrorAction) $request=[Text.Encoding]::UTF8.GetString($Body) | ConvertFrom-Json; [pscustomobject]@{runId=$request.runId;status='delivered'} }
    $delivery=Send-DiagnosticBundle $bundle 'https://example.invalid/webhook'
    Assert ($delivery.Status -eq 'Delivered') 'Confirmed delivery response'
    function Invoke-RestMethod { param($Uri,$Method,$Headers,$ContentType,$Body,$TimeoutSec,$ErrorAction) $request=[Text.Encoding]::UTF8.GetString($Body) | ConvertFrom-Json; [pscustomobject]@{runId=$request.runId;status='pending-review'} }
    Assert ((Send-DiagnosticBundle $bundle 'https://example.invalid/webhook').Status -eq 'AcceptedOrPending') 'Receipt is not delivery'
    function Invoke-RestMethod { throw '401 authentication failed' }
    Assert ((Send-DiagnosticBundle $bundle 'https://example.invalid/webhook').Status -eq 'Failed') 'Authentication failure retained'
    Assert (Test-Path $zip) 'Failed delivery preserves archive'
    Throws { Send-DiagnosticBundle $bundle 'http://example.invalid' } 'Reject plaintext webhook'
    Remove-Item Function:\Invoke-RestMethod

    # Exercise hard worker timeout and retained records without querying this device.
    $worker=Join-Path $temp 'fake-worker.ps1'
    Write-DiagnosticUtf8 $worker @'
function Invoke-DiagnosticWorker {
 param($Name,$Path,$Days)
 [IO.File]::WriteAllText($Path,'{"kind":"sample","data":{"value":42}}'+"`n")
 Start-Sleep -Seconds 15
}
'@
    $script:DiagnosticSource=$worker
    $result=Invoke-IsolatedCollector 'Fixture' $temp 7 1
    Assert ($result.Status -eq 'TimedOut') 'Worker timeout terminates child'
    Assert ($result.Records[0].data.value -eq 42) 'Partial evidence retained on timeout'
    $script:DiagnosticSource=$source
    [IO.File]::AppendAllText((Join-Path $bundle 'Report.md'),'tampered')
    Throws { New-DiagnosticPayload $bundle } 'Reject changed files during resend'
    Write-DiagnosticUtf8 (Join-Path $bundle 'Report.md') $report
    $archive=[IO.Compression.ZipFile]::Open($zip,[IO.Compression.ZipArchiveMode]::Update)
    try {
        $archive.GetEntry('Report.md').Delete()
        $entry=$archive.CreateEntry('Report.md');$writer=New-Object IO.StreamWriter($entry.Open())
        try { $writer.Write('tampered archive') } finally { $writer.Dispose() }
    } finally { $archive.Dispose() }
    Throws { New-DiagnosticPayload $bundle } 'Reject changed ZIP contents during resend'

    $env:CROWN_TEST_DOWNLOAD=Join-Path $temp 'download-fixture.ps1'
    $env:CROWN_TEST_MARKER=Join-Path $temp 'launch-marker.txt'
    Write-DiagnosticUtf8 $env:CROWN_TEST_DOWNLOAD '[IO.File]::WriteAllText($env:CROWN_TEST_MARKER,"executed")'
    function Invoke-WebRequest { param([switch]$UseBasicParsing,$Uri,$OutFile) [IO.File]::Copy($env:CROWN_TEST_DOWNLOAD,$OutFile) }
    $launcher=Join-Path $root 'Start-TicketDiagnostics.ps1'
    $expected=(Get-FileHash $env:CROWN_TEST_DOWNLOAD -Algorithm SHA256).Hash
    & $launcher -Repository 'unit/test' -Release 'v1.0.0' -ExpectedSha256 $expected -LocalOnly
    Assert (Test-Path $env:CROWN_TEST_MARKER) 'Verified release is executed'
    $env:CROWN_TEST_MARKER=Join-Path $temp 'must-not-execute.txt'
    Throws { & $launcher -Repository 'unit/test' -Release 'v1.0.0' -ExpectedSha256 ('0'*64) -LocalOnly } 'Bad release checksum rejected'
    Assert (-not (Test-Path $env:CROWN_TEST_MARKER)) 'Unverified release never executes'
    Remove-Item Function:\Invoke-WebRequest
    $env:CROWN_TEST_MARKER=$null
    $env:CROWN_TEST_DOWNLOAD=$null
    $commands=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
    Assert ($commands -notcontains 'Invoke-CimMethod' -and $commands -notcontains 'Get-WmiObject') 'No management methods or unsafe WMI inventory'
    Assert ([IO.File]::ReadAllText($source) -notmatch 'Win32_Product|Get-BitLockerVolume|Get-ADUser|Get-Content.*Security') 'Sensitive collectors absent'
    Write-Host "PASS: $script:assertions assertions. Test artifacts: $temp"
} finally { $env:CROWN_DIAGNOSTICS_TOKEN=$savedToken }
