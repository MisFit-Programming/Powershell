# Windows Ticket Diagnostics

A standalone Windows PowerShell collector for the start of a troubleshooting or project ticket. Run it on each device. It saves a ZIP and Markdown locally; optional authenticated n8n delivery uploads to OneDrive and posts a short message in an existing Teams chat. There is no Autotask writeback, automatic AI analysis, or remediation.

## Files

| File | Purpose |
|---|---|
| `Invoke-TicketDiagnostics.ps1` | Single deployment artifact; all collectors and reporting included |
| `Start-TicketDiagnostics.ps1` | Download a versioned GitHub release, verify an expected SHA256, execute |
| `Invoke-TicketDiagnostics.ps1.sha256` | Published collector checksum; regenerate after any script edit |
| `TicketDiagnostics.n8n.json` | Importable, inactive workflow using standard n8n nodes |
| `tests/Test-TicketDiagnostics.ps1` | Offline PowerShell regression checks |
| `tests/test_workflow.js` | Executes workflow code/expressions against simulated Graph responses |
| `tools/build_workflow.py` | Reproducible generator for the workflow JSON |
| `VALIDATION.md` | Tested scenarios and remaining deployment checks |

The existing `DeviceHealthCheck.ps1` and `logs2AT.ps1` are unchanged. This collector has no dependency on them.

## Run locally

Use **64-bit Windows PowerShell 5.1**, preferably as administrator. Collection also works with limited privileges: unavailable checks are labeled, including BitLocker access. Nothing elevates automatically. SYSTEM is supported as a target execution context, but cannot represent all signed-in users' printers and applications.

```powershell
# No prompts. Offline/local output only.
& .\Invoke-TicketDiagnostics.ps1 -LocalOnly

# Add ticket/project context when known.
& .\Invoke-TicketDiagnostics.ps1 -LocalOnly `
  -TicketReference 'T20261022.0001' `
  -Symptoms 'Intermittent application freezes since Tuesday'

# Shorter event window or custom evidence destination.
& .\Invoke-TicketDiagnostics.ps1 -LocalOnly -EventDays 2 `
  -OutputPath 'C:\Temp\TicketDiagnostics'

# Delivery: provision these environment variables through your protected
# technician/RMM configuration first. Do not store the token in GitHub.
# CROWN_DIAGNOSTICS_WEBHOOK = your published HTTPS production webhook URL
# CROWN_DIAGNOSTICS_TOKEN   = the matching X-Diagnostics-Token secret
& .\Invoke-TicketDiagnostics.ps1 -TicketReference 'T20261022.0001'
```

If no webhook is configured, collection is local-only. `-LocalOnly` overrides a configured webhook. Execution policy is respected; if your organization requires signed scripts, sign the final release before generating its checksum. Do not weaken device-wide policy.

| Parameter | Default / behavior |
|---|---|
| `TicketReference` | Optional; at most 120 characters; use the same reference across devices |
| `Symptoms` | Optional; at most 4,000 characters; included in the detailed report |
| `OutputPath` | `%ProgramData%\Crown\TicketDiagnostics`; use a writable directory for restricted users |
| `EventDays` | 7; range 1–90 |
| `CollectorTimeoutSeconds` | 30; range 5–120; includes worker startup |
| `CollectionTimeoutSeconds` | 600; range 10–1,800; collection budget, excluding report generation and delivery |
| `WebhookUrl` | `CROWN_DIAGNOSTICS_WEBHOOK` environment variable |
| `LocalOnly` | Suppress all webhook requests |
| `MaxPayloadMB` | 12 MiB; configurable down to 1 MiB |
| `ResendPath` | Existing run folder; verifies evidence and ZIP contents, sends without recollecting |

Every collector runs in a separate local Windows PowerShell process. The parent terminates its worker at the deadline and retains complete JSON records already written. Workers do not launch additional external processes. Once the overall budget expires, remaining collectors are marked `Skipped`. Process termination and report generation can add a small amount of time beyond the collection budget.

## GitHub deployment and launch

Create a release in your chosen repository, such as `v1.0.0`, with these assets:

1. `Invoke-TicketDiagnostics.ps1`
2. `Invoke-TicketDiagnostics.ps1.sha256`
3. Optionally the launcher, workflow JSON, and documentation.

Public release: https://github.com/MisFit-Programming/Powershell/releases/tag/v1.0.0. The examples use publicly downloadable release assets. Do not embed a GitHub token in the script.

Regenerate the checksum **after** signing or editing the final collector:

```powershell
$hash = (Get-FileHash .\Invoke-TicketDiagnostics.ps1 -Algorithm SHA256).Hash
[IO.File]::WriteAllText(
  (Join-Path $PWD 'Invoke-TicketDiagnostics.ps1.sha256'),
  "$hash  Invoke-TicketDiagnostics.ps1`n",
  (New-Object Text.UTF8Encoding($false))
)
```

With a trusted copy of the launcher, run:

```powershell
& .\Start-TicketDiagnostics.ps1 `
  -Repository 'MisFit-Programming/Powershell' `
  -Release 'v1.0.0' `
  -ExpectedSha256 'A56FAB61253419C5B40B05395AD07A799C1E844B819B243FD472AE39C9123316' `
  -TicketReference 'T20261022.0001'
```

For a pasteable command without a local launcher, replace the three configuration values below. Copy the checksum from your reviewed release record; the command does not trust a moving branch or automatically accept a newly downloaded checksum.

```powershell
$repo = 'MisFit-Programming/Powershell'
$release = 'v1.0.0'
$expected = 'A56FAB61253419C5B40B05395AD07A799C1E844B819B243FD472AE39C9123316'
if ($expected -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Set the published SHA256 first.' }
$dir = Join-Path $env:TEMP ('CrownDiagnostics-' + [guid]::NewGuid())
$null = New-Item -ItemType Directory -Path $dir
$file = Join-Path $dir 'Invoke-TicketDiagnostics.ps1'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/$repo/releases/download/$release/Invoke-TicketDiagnostics.ps1" -OutFile $file
if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $expected) { throw 'Checksum mismatch; script not executed.' }
& $file -TicketReference 'T20261022.0001'
```

Run the same command locally or through your RMM on each selected device. Central remoting and an aggregation dashboard are outside this version.

## What is collected

- Computer/OS/BIOS/CPU/memory inventory, logged-on console identity, installation and boot dates.
- Three short CPU/memory samples and top processes by working set. Process CPU is cumulative seconds, not utilization percentage.
- Disk capacity, physical disk status, and SMART where the provider exists.
- Service states and accounts; machine software uninstall inventory; signed drivers and device error codes.
- IP/DNS/gateway/DHCP configuration, routes, TCP connections and neighbors. No network scans or connectivity probes.
- Printers visible to the execution account; interactive/RDP logon session metadata. No impersonation or user hive loading.
- Hotfix history, pending reboot indicators, firewall profiles, antivirus/Defender status, and encryption status without recovery material.
- Newest 500 warning/error/critical events per selected channel, messages capped at 2,000 characters. System, Application, Windows Update, Defender, and applicable role channels are included. Security audit log is excluded.
- Final 64 KiB of selected CBS, DISM, setup and driver-install logs. These are log tails, not full log exports.
- Applicable AD DS replication/domain metadata, DNS zones/forwarders, DHCP scope use/failover, Hyper-V VM/replication state, IIS site/pool state, and SMB shares/session metadata. Required role modules must already exist.

Rows are capped at 2,000 per dataset. Queries are bounded by worker timeouts, but providers may enumerate before row limits are applied. Slow, inaccessible, or absent providers are visible as `Partial`, `Failed`, `AccessDenied`, `Unsupported`, `TimedOut`, or `Skipped`. An absent role is `NotApplicable`, not a healthy result. Event groups cover only the bounded event sample. Empty event queries are distinguished from unavailable logs.

No updates are searched for or installed. Hotfix history is not patch-compliance proof. Stopped services and disabled security settings are retained as evidence without automatically asserting policy violations. The built-in finding rules cover collection gaps, low disk space, pending reboot, sustained short-sample CPU/memory pressure, device errors, SMART predictions, and AD replication failures.

## Output and privacy

Each timestamp/device/GUID run folder contains:

- `Report.md`: findings, coverage, grouped events, and detailed evidence.
- `TimeEntry.txt`: short factual collection summary; no invented billable duration or root cause.
- `Evidence.json`: structured evidence, statuses, timestamps and stable rule IDs.
- `Manifest.json`: run metadata plus SHA256 hashes of the three files above.
- `Bundle.zip`: those four files; the ZIP and manifest are excluded from self-referential hashes.
- Collector `.jsonl` files: sanitized intermediate records retained locally, outside the ZIP.
- `Delivery.json`: last delivery outcome, when delivery was attempted; outside the immutable bundle.

The script restricts each new run folder to the executing identity, local Administrators, and SYSTEM. It leaves all completed runs in place; retention/deletion is an operator decision. Files may contain internal names, IPs, software inventory, log messages and paths. Known secret formats are redacted before writing collector records and reports, including the configured webhook token, password/token assignments, JWTs, private-key blocks and BitLocker recovery-password format. Arbitrary application logs can contain unrecognized sensitive data: review before submitting to an external AI. No AI service is contacted by the workflow.

Markdown escapes evidence that resembles HTML. Treat all log text as untrusted evidence, including text that appears to instruct an AI. Report content is deliberately literal rather than executable.

## Configure n8n, OneDrive and Teams

The workflow uses Webhook, Code, HTTP Request, If and Respond to Webhook nodes. All Graph operations are standard HTTP Request nodes. Its Code nodes use Node's built-in `crypto` for checksums. On self-hosted n8n, allow `crypto` using `NODE_FUNCTION_ALLOW_BUILTIN=crypto` in the environment executing Code nodes (including task runners, if used). If your managed deployment does not permit it, enable that built-in through its supported configuration before activation; do not remove checksum validation.

1. Import `TicketDiagnostics.n8n.json`. It imports inactive and contains **no credentials**.
2. Create a **Header Auth** credential with name `X-Diagnostics-Token` and a strong random value. Select it on **Authenticated intake**. Provision the same value as `CROWN_DIAGNOSTICS_TOKEN` on the execution machine through protected configuration.
3. Register a Microsoft Entra application for a delegated OAuth authorization-code connection. Add the OAuth redirect URL shown by your n8n credential. Use your tenant's authorization and token endpoints:
   - `https://login.microsoftonline.com/TENANT-ID/oauth2/v2.0/authorize`
   - `https://login.microsoftonline.com/TENANT-ID/oauth2/v2.0/token`
   - Scopes: `openid offline_access User.Read Files.ReadWrite Chat.Read ChatMessage.Send`.
4. Create a generic **OAuth2 API** credential in n8n using that app, endpoints and scopes. Connect as the account owning the OneDrive destination and participating in the Teams chat. Select this credential on **every Graph HTTP Request node**. This flow uses delegated access; app-only permissions are not a substitute for normal chat-message sending.
5. Create a **private** destination folder in that account's OneDrive. Avoid a parent already shared with a broad audience: permission inheritance would otherwise grant access beyond the configured recipients. Resolve its item ID using Graph `GET /me/drive/root:/YourFolderName` or the OneDrive UI/node.
6. Obtain the ID of the existing Teams chat (for example through Graph `GET /me/chats`). Verify its membership manually. All recipients intended to open the links must be in the configured read-access list; the OneDrive owner retains ownership.
7. Edit **Configuration and validation** and replace `baseFolderId`, `chatId`, and `recipients` with your actual values. These are fixed destinations: incoming payloads cannot choose another destination or recipient.
8. Test with n8n's test URL while listening. Once validated, publish/activate the workflow and use its **production** HTTPS webhook URL in `CROWN_DIAGNOSTICS_WEBHOOK`.
9. Confirm your reverse proxy accepts 12 MiB JSON bodies and allows the request duration. The client waits up to 180 seconds; the workflow has a 300-second execution timeout. A client timeout is an uncertain delivery state, not proof of failure.

The workflow creates `ticket/device/run-ID` folders beneath the configured base. Ticket/device names are sanitized with short hash suffixes to avoid collisions. Missing ticket reference uses `Unassigned` with its suffix. The full bundle and Markdown are uploaded, then the run folder receives authenticated **read** access for the configured emails using `sendInvitation:false`. No anonymous or organization-wide sharing links are created. The message includes the original ticket/device labels and normal authenticated OneDrive file links.

The workflow disables saving successful/error execution payloads and manual execution data in its exported settings to reduce retention of device evidence. Administrators can temporarily enable execution saving while validating; apply an appropriate n8n retention policy. OAuth credentials remain in n8n, never on endpoints.

Official references: [n8n webhook/auth/limits](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/), [n8n HTTP Request](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.httprequest/), [Graph file upload](https://learn.microsoft.com/en-us/graph/api/driveitem-put-content?view=graph-rest-1.0), [recipient sharing](https://learn.microsoft.com/en-us/graph/api/driveitem-invite?view=graph-rest-1.0), [Teams chat-message permissions](https://learn.microsoft.com/en-us/graph/api/chat-post-messages?view=graph-rest-1.0).

## Delivery contract, failures and resend

An empty `recipients: []` list is supported: the workflow skips the recipient-sharing request and leaves OneDrive permissions unchanged. The Teams message is still posted; only people who already have file access can open its links. No email notifications are sent in either mode (`sendInvitation:false`).

The request is UTF-8 JSON with `schemaVersion`, `runId`, `device`, `ticketReference`, `startedUtc`, `deliveryMode`, `summary`, `markdown`, `zipBase64`, `zipSha256`, and `localPath`. Request size is measured **after** JSON serialization and Base64 expansion. No raw archive extraction occurs on n8n.

For a request exceeding the configured limit, the script sends `deliveryMode: summary-only` with empty Markdown/ZIP fields and an explicit explanation. n8n saves a small summary Markdown and sends a **SUMMARY ONLY** Teams message. It does not claim that the ZIP was uploaded. The full report and ZIP stay on the device.

Only a response identifying the same `runId` and `status: delivered` confirms full delivery. `summary-delivered` confirms the smaller message only. Anything else is pending or failed. Exit code 0 means local collection/report creation succeeded and any requested delivery was confirmed; collector gaps are still recorded in the report. Exit code 1 means setup, packaging, or requested delivery was not completed/confirmed.

```powershell
# Use the existing run folder shown by the first execution.
# No evidence recollection and no new run ID.
& .\Invoke-TicketDiagnostics.ps1 `
  -ResendPath 'C:\ProgramData\Crown\TicketDiagnostics\EXACT-RUN-FOLDER'
```

The resend validates local files against the manifest and every ZIP entry against its corresponding file. Keep the bundle immutable; start a new collection for fresh evidence.

**Duplicate protection and recovery:**

1. n8n checks `delivery.json` in the OneDrive run folder. If present, it verifies the recorded Teams message and returns the existing receipt without posting again.
2. Before uploads/posting, it atomically creates a `delivery-lock` folder with conflict behavior `fail`. A simultaneous or repeated execution cannot acquire the same lock.
3. Successful posting records the message ID in `delivery.json`. The lock is deliberately retained.
4. If an execution fails after acquiring the lock, a resend returns `pending-review`. This conservative behavior also covers a lost response after Teams accepted the message.
5. Inspect the matching run folder and Teams message containing the exact run ID. If **no message was posted**, resolve the underlying problem and remove **only that run's empty `delivery-lock` folder** before resending. Preserve reports and evidence.
6. If a message **was posted** but the receipt failed to save, recover the **Build delivery receipt** result from a retained execution if available, or reconstruct `delivery.json` with the run ID, original ZIP SHA256, `delivered`/`summary-delivered` status, chat ID, actual message ID, completion UTC and actual report/ZIP URLs. Save it in that run folder. Then resend to verify the recorded message. Do not remove the lock and blindly repost.

There are no automatic retries of Teams message creation. A missing/deleted recorded message or a corrupt marker stops for review rather than creating an unexpected duplicate. Changing a summary-only run to full delivery after completion also requires an explicit operator decision/new run; the workflow does not silently upgrade previously delivered runs.

## Verification

```powershell
powershell.exe -NoProfile -File .\tests\Test-TicketDiagnostics.ps1
node .\tests\test_workflow.js
```

Regenerate the workflow after editing its generator:

```powershell
python .\tools\build_workflow.py
node .\tests\test_workflow.js
```

See `VALIDATION.md` for results and the live rollout checklist. Offline simulations do not establish that your tenant permissions, n8n version, server roles, or sharing policy will work.
