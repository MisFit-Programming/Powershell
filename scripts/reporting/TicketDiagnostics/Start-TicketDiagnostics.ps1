#requires -Version 5.1
<# Download a versioned release, verify the independently supplied SHA256, then run. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')][string]$Repository,
    [Parameter(Mandatory)][ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+$')][string]$Release,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
    [string]$TicketReference='',
    [string]$Symptoms='',
    [string]$OutputPath="$env:ProgramData\Crown\TicketDiagnostics",
    [string]$WebhookUrl=$env:CROWN_DIAGNOSTICS_WEBHOOK,
    [string]$ResendPath,
    [ValidateRange(1,90)][int]$EventDays=7,
    [ValidateRange(10,1800)][int]$CollectionTimeoutSeconds=600,
    [ValidateRange(5,120)][int]$CollectorTimeoutSeconds=30,
    [switch]$LocalOnly
)
$ErrorActionPreference='Stop'
$directory=Join-Path $env:TEMP ('CrownDiagnosticLauncher-'+[guid]::NewGuid().ToString())
$null=New-Item -Path $directory -ItemType Directory
$file=Join-Path $directory 'Invoke-TicketDiagnostics.ps1'
[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$url="https://github.com/$Repository/releases/download/$Release/Invoke-TicketDiagnostics.ps1"
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $file
if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $ExpectedSha256) { throw 'Release checksum mismatch; downloaded script was not executed.' }
$parameters=@{TicketReference=$TicketReference;Symptoms=$Symptoms;OutputPath=$OutputPath;WebhookUrl=$WebhookUrl;EventDays=$EventDays;CollectionTimeoutSeconds=$CollectionTimeoutSeconds;CollectorTimeoutSeconds=$CollectorTimeoutSeconds;LocalOnly=$LocalOnly}
if ($ResendPath) { $parameters.ResendPath=$ResendPath }
$global:LASTEXITCODE=0
& $file @parameters
if (-not $?) { exit 1 }
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
