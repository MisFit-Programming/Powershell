# MisFit Programming PowerShell Repository

IT administration scripts for Windows onboarding, browser maintenance, server monitoring, reporting, Microsoft 365, and SMB share permissions. Debian bootstrap scripts and reusable command snippets are included separately.

## Repository structure

```text
scripts/
  browsers/       Browser backup, history export, and WaveBrowser removal
  file-shares/    SMB/NTFS access review, AD group provisioning, and its guide
  integrations/   Ninja API request example
  microsoft-365/  OneDrive personal-site provisioning
  monitoring/     Network traffic and Windows Server health dashboards
  onboarding/     Windows setup and remote-management agent installation
  reporting/      Device/server HTML inventory
  utilities/      Interactive Pomodoro timer
linux/
  3cx/            Debian Bookworm and Trixie bootstrap scripts
snippets/         Standalone PowerShell command examples
tests/            Offline share-review test harness
```

## Script catalog

Paths below are relative to the repository root. Scripts are independent tools; there is no installer or shared entry point.

| Script | Purpose | Requirements, configuration, and output |
| --- | --- | --- |
| [BenchConfigure.ps1](scripts/onboarding/BenchConfigure.ps1) | Installs Windows updates, renames a computer, and attempts a domain join. | Elevated Windows PowerShell; installs `PSWindowsUpdate`. Accepts `ComputerName`, `DomainName`, `DomainUser`, and `DomainPassword`. Updates and explicit restart calls can interrupt the sequence; there is no resume mechanism. The header's `SetupComputer.ps1` example refers to this file. |
| [Onboarding_AgentInstall.ps1](scripts/onboarding/Onboarding_AgentInstall.ps1) | Downloads and silently installs Datto RMM and ScreenConnect. | Requires elevation and internet access. Installer URLs are specific to the configured organization/site; review them before use. Uses the temporary directory and removes installers unless `-NoCleanup` is supplied. |
| [Bookmark_Backup_Restore.ps1](scripts/browsers/Bookmark_Backup_Restore.ps1) | Copies bookmark and password-related files for Edge, Chrome, and Firefox; supports a restore mode. | Edit `$operationMode` (`backup` by default) and backup paths in the source. Force-closes browsers, writes dated folders under Documents/BrowserBackups, and deletes backups older than 30 days. Raw credential-file copies are not a complete or portable password migration. |
| [BrowserHistory.ps1](scripts/browsers/BrowserHistory.ps1) | Extracts Chrome, Firefox, and Edge history across Windows user profiles. | Needs access to those profiles. Downloads SQLite tooling when missing; writes `C:\temp\BrowsingHistory.csv` and uses Pacific time conversion. Review its pinned SQLite download URL and protect the exported browsing data. |
| [WaveBrowserRemoval.ps1](scripts/browsers/WaveBrowserRemoval.ps1) | Removes WaveBrowser/WebNavigator files, startup registry entries, and matching scheduled tasks. | Stops common browsers. Files and HKCU registry cleanup target the executing user; scheduled-task removal may require elevation. Review the `*Wave*` task match before running. |
| [Share-Access-Review.ps1](scripts/file-shares/Share-Access-Review.ps1) | Reviews SMB/root NTFS permissions and child ACL exceptions; optionally creates the share-permissions OU, RW/RO groups, memberships, and additive grants. | Windows PowerShell 5.1+ on the file server, with `SmbShare` and RSAT `ActiveDirectory` modules and appropriate permissions. Review-only by default; changes require `-Apply`. Produces HTML, JSON, a before snapshot, and an action journal. Read the [full guide](scripts/file-shares/Share-Access-Review.README.md). |
| [Ninja_API.ps1](scripts/integrations/Ninja_API.ps1) | Example authenticated GET request displaying organization information and error details. | Fill in `$url` and `$sessionKey`; it exits when the key is empty. The script prints request headers, including the session cookie, so avoid capturing/sharing that output with a live key. |
| [Create_One_Drive.ps1](scripts/microsoft-365/Create_One_Drive.ps1) | Requests OneDrive personal sites for licensed users in batches of 199. | Existing MSOnline and SharePoint Online cmdlets (`Connect-MsolService`, `Connect-SPOService`, `Request-SPOPersonalSite`). Define `$Credential` and replace `{URL}` with the tenant admin URL. This is a legacy template requiring configuration and tenant compatibility checks. |
| [NetworkTrafficRateMonitor.ps1](scripts/monitoring/NetworkTrafficRateMonitor.ps1) | Shows receive packet/throughput rates and optional broadcast/multicast storm detection. | Windows with `NetAdapter`. Supports adapter name patterns, physical-only filtering, sampling intervals/counts, storm thresholds, and optional CSV output. Runs until Ctrl+C unless `-Samples` is set. |
| [WindowsServerHealthMonitor.ps1](scripts/monitoring/WindowsServerHealthMonitor.ps1) | Refreshing console dashboard for CPU, memory, storage, sessions, services, connectivity, processes, and events. | Windows Server; PowerShell 5.1 compatible. Elevation gives more complete visibility. Configurable thresholds and additional services; `-NoLog` disables alert logging. Does not remediate or restart services; Ctrl+C stops it. |
| [DeviceReport.ps1](scripts/reporting/DeviceReport.ps1) | Builds an HTML inventory of server roles, AD details, and device information. | Uses Windows Server/AD cmdlets, including `Get-WindowsFeature` and `Get-ADOrganizationalUnit`. Targets `C:\Temp\DeviceReport.html`. Existing section-scoping and recursive OU traversal code needs review before relying on report completeness. |
| [Pomodoro.ps1](scripts/utilities/Pomodoro.ps1) | Interactive work/break timer with a continue prompt. | Edit duration settings in the source (25/5/15 minutes by default). Every fourth loop runs a long break instead of a work/short-break pair. |
| [3CX bookworm.txt](linux/3cx/3CX%20bookworm.txt) | Debian 12 bootstrap: adjusts apt sources, upgrades packages, and installs Datto RMM/ScreenConnect. | Bash script stored as `.txt`; requires root on Bookworm and download tools. Uses organization-specific agent URLs. Logs to `/var/log/crown-bootstrap.log` and backs up apt configuration under `/root/bootstrap-backups`. |
| [3CX Trixie.txt](linux/3cx/3CX%20Trixie.txt) | Debian 13 bootstrap with OS validation, apt-source preparation, prerequisite installation, and agent installation. | Bash script stored as `.txt`; requires root on Debian Trixie. Uses organization-specific agent URLs and the same log/backup locations as the Bookworm version. These bootstrap files install management agents, not the 3CX application itself. |
| [OneLiners.txt](snippets/OneLiners.txt) | Command example that organizes current-directory files into extension folders. | Read and run the selected command in the intended directory; it moves files. The `.txt` file includes descriptive text and is not a script to execute wholesale. |

## Getting started

```powershell
git clone https://github.com/MisFit-Programming/Powershell.git
Set-Location .\Powershell

# Finite network-monitoring example on Windows.
.\scripts\monitoring\NetworkTrafficRateMonitor.ps1 -Samples 12

# Read parameter help for scripts that provide comment-based help.
Get-Help .\scripts\file-shares\Share-Access-Review.ps1 -Full
```

Review the selected script's configuration and prerequisites first. Several scripts change the system immediately, use fixed output paths, or contain organization-specific endpoints. Use an elevated session where the catalog calls for one. PowerShell 7 compatibility is not established for every script; legacy Windows/module-dependent scripts may require Windows PowerShell 5.1.

### Share access review

Run on the intended file server with the required modules installed:

```powershell
# Review only; writes reports but does not provision access.
.\scripts\file-shares\Share-Access-Review.ps1 -OutputDirectory 'C:\Reports\SharePermissions'

# After reviewing the proposed mapping, apply it.
.\scripts\file-shares\Share-Access-Review.ps1 -OutputDirectory 'C:\Reports\SharePermissions' -Apply
```

The script maps named AD users directly present in SMB or root NTFS permissions, preserves existing permissions, and reports child-only exceptions without turning them into root group members. Its mapping combines grants from either layer; it is not an effective-access calculation and can expand access. Consult the [share-review guide](scripts/file-shares/Share-Access-Review.README.md) for exclusions, group collisions, partial failures, and report details. This implementation requires the ActiveDirectory module.

### Onboarding agent installer

From a clone, in an elevated PowerShell session:

```powershell
.\scripts\onboarding\Onboarding_AgentInstall.ps1
```

To download the current script for inspection before running:

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/MisFit-Programming/Powershell/main/scripts/onboarding/Onboarding_AgentInstall.ps1' -OutFile '.\Onboarding_AgentInstall.ps1'
# Inspect the downloaded file and its configured agent URLs, then run:
.\Onboarding_AgentInstall.ps1
```

### Debian bootstrap

On the matching Debian release, inspect the file, then run the selected variant with Bash:

```bash
sudo bash 'linux/3cx/3CX bookworm.txt'   # Debian 12
# Or, on Debian 13:
sudo bash 'linux/3cx/3CX Trixie.txt'
```

## Validation

The [offline share-review harness](tests/Share-Access-Review.Tests.ps1) mocks AD, SMB, inventory, and ACL operations. It checks output paths, preview and WhatIf, named-user mapping, provisioning, ACL preservation, rerun behavior, failure blocking, collisions, and HTML escaping. It writes temporary report files without making live infrastructure changes. Run from the repository root on Windows:

```powershell
powershell.exe -NoProfile -File .\tests\Share-Access-Review.Tests.ps1
pwsh -NoProfile -File .\tests\Share-Access-Review.Tests.ps1
```

This harness covers the share-review script only. The other scripts have not been validated against live systems as part of the folder reorganization.

## Paths and history

Scripts previously at the repository root now live at the catalog paths above; filenames are unchanged. The share-review guide moved beside its script, and the existing test harness remains in `tests/` with its source reference updated. Update scheduled tasks, RMM jobs, bookmarks, and raw GitHub URLs that use the old root paths. No root-path compatibility wrappers are included.

By default, the share-review script creates `ShareReports` beside the saved script, now under `scripts/file-shares/`. Use `-OutputDirectory` to retain a fixed report location. Other configured output paths remain unchanged.

Git history is retained through normal commits without rewriting earlier commits. To follow a moved file's history:

```powershell
git log --follow -- scripts/file-shares/Share-Access-Review.ps1
```
