<#
.SYNOPSIS
Installs Datto RMM and ScreenConnect agents for onboarding.

.DESCRIPTION
Downloads and installs the Datto RMM EXE installer and the ScreenConnect MSI installer.
By default, installers are run silently and this script requires administrative privileges.

.EXAMPLE
# Run locally after download
.\Onboarding_AgentInstall.ps1

.EXAMPLE
# Run directly from GitHub (replace branch if needed)
irm https://raw.githubusercontent.com/MisFit-Programming/Powershell/main/Onboarding_AgentInstall.ps1 | iex
#>

[CmdletBinding()]
param(
    [switch]$NoCleanup
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    throw 'This script must be run from an elevated PowerShell session (Run as Administrator).'
}

$dattoUrl = 'https://zinfandel.rmm.datto.com/download-agent/windows/5354f689-d9a9-4f7d-8e54-67beebec100f'
$screenConnectUrl = 'https://support.ce-technology.com/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=Onboarding&c=&c=&c=&c=&c=&c=&c='

$dattoInstallerPath = Join-Path $env:TEMP 'DattoRMM-AgentInstall.exe'
$screenConnectInstallerPath = Join-Path $env:TEMP 'ScreenConnect-ClientSetup.msi'

Write-Host 'Downloading Datto RMM installer...'
Invoke-WebRequest -Uri $dattoUrl -OutFile $dattoInstallerPath -UseBasicParsing

Write-Host 'Installing Datto RMM...'
$dattoProcess = Start-Process -FilePath $dattoInstallerPath -ArgumentList '/quiet' -Wait -PassThru
if ($dattoProcess.ExitCode -ne 0) {
    throw "Datto RMM installer failed with exit code $($dattoProcess.ExitCode)."
}

Write-Host 'Downloading ScreenConnect installer...'
Invoke-WebRequest -Uri $screenConnectUrl -OutFile $screenConnectInstallerPath -UseBasicParsing

Write-Host 'Installing ScreenConnect...'
$screenConnectProcess = Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i `"$screenConnectInstallerPath`" /qn /norestart" -Wait -PassThru
if ($screenConnectProcess.ExitCode -ne 0) {
    throw "ScreenConnect installer failed with exit code $($screenConnectProcess.ExitCode)."
}

if (-not $NoCleanup) {
    Remove-Item -Path $dattoInstallerPath, $screenConnectInstallerPath -Force -ErrorAction SilentlyContinue
}

Write-Host 'Onboarding agent installation completed successfully.' -ForegroundColor Green
