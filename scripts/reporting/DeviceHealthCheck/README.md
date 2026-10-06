# Windows Device Health Assessment for Datto RMM

`DeviceHealthCheck.ps1` is the single deployment artifact. It collects Windows health evidence, builds an executive-first report, and updates a **native IT Glue Document** named exactly like `COMPUTERNAME` inside the organization's **Device Health Checks** folder. It does not use Flexible Assets.

**Release status: implemented, locally tested, and live publication confirmed by the supplied Datto log/PDF.** The v1.0.2 collection and layout fixes need a tenant rerun. Native navigation and user-visible revision/history still require validation before broad deployment. Offline mocks do not establish those behaviors. See [validation checklist](tests/DeviceHealthCheck.Validation.md).

## Deployment

1. Create a Datto RMM PowerShell component containing `DeviceHealthCheck.ps1`.
2. Run under SYSTEM or an appropriately privileged account. Use **64-bit Windows PowerShell** on 64-bit Windows.
3. Configure the variables below. Store the API key as a masked/password variable. Do not put the key in command arguments or the script.
4. Pilot against a test organization and complete the tenant checklist before MSP-wide rollout. Prevent overlapping schedules for the same computer/document.

| Variable | Requirement |
|---|---|
| `strITGLUE` | IT Glue API key with organization, document folder, document, section and publish access |
| `itGlueOrgID` | Positive decimal organization ID; 1–19 digits, first digit nonzero |
| `DHC_APIEndpoint` | Optional, exactly `https://api.itglue.com` (default), `https://api.eu.itglue.com`, or `https://api.au.itglue.com` |

`-APIEndpoint` overrides the endpoint environment variable. Unknown endpoints, trailing paths, invalid thresholds, missing keys, and invalid organization IDs fail configuration validation before collection/upload. API keys are never embedded in the report, printed, or stored by the component.

Production example:

```powershell
& '.\DeviceHealthCheck.ps1'
```

Preview example (parent directory must already exist):

```powershell
& '.\DeviceHealthCheck.ps1' -SkipUpload -ReportPath 'C:\Temp\DeviceHealth.html'
```

`-SkipUpload` makes **zero IT Glue requests**, including GETs. It does not need IT Glue credentials. `-ReportPath` is optional and is the only local file write in the runtime. It writes exactly the specified file and does not create directories, remove files, or retain a history database. Treat preview files as internal infrastructure information.

## Compatibility

The complete file deliberately avoids language features introduced after Windows PowerShell 2.0: no `#requires -Version 5.1`, classes, `[ordered]`, `[pscustomobject]`, `::new()`, null operators, or `-in`/`-notin` operators.

| Environment | Behavior |
|---|---|
| PowerShell 5.1+ on Windows | Full collection with capability detection |
| PowerShell 2.0–5.0 | Bootstrap identity, Unsupported report, attempted secure publication; no full collectors |
| 32-bit PowerShell on 64-bit Windows | Explicit Unsupported/incomplete report; full collection withheld to avoid registry/provider-view errors |
| Native 32-bit Windows with 5.1 | Full collection where providers exist |
| Legacy CLR/TLS unable to use TLS 1.2 | Publishing failure, exit 1; no protocol downgrade or certificate bypass |

The target collection scope includes Windows 7 SP1, 8, 8.1, 10, 11; Server 2008 R2 SP1, 2012, 2012 R2, 2016, 2019, 2022, 2025; and future Windows releases exposing compatible APIs. **Collection compatibility does not mean Microsoft still supports the OS.** An absent cmdlet, module, class, firmware interface, or permission becomes UNKNOWN/UNSUPPORTED rather than PASS. Actual legacy OS/PowerShell execution remains a VM validation item; a modern parser check cannot prove a PowerShell 2.0 parser works.

The bootstrap uses .NET `HttpWebRequest`, TLS 1.2, and the already-installed .NET `JavaScriptSerializer` on PowerShell 2. Modern PowerShell uses built-in JSON cmdlets. Nothing installs or upgrades .NET, WMF, modules, roles, or services. Existing installed role modules may be imported into the current collector session.

The component currently chooses explicit 32-bit degradation instead of relaunching another process. This is an intentional supported option in the project requirements. Set the correct Datto execution architecture to obtain a full report.

## Architecture

The single file has independent layers:

1. Compatibility/bootstrap and validated configuration.
2. Read-only WMI, registry, native-command, encoding, and evidence utilities.
3. Bounded probes, baseline checks, role detection and role packs.
4. Standard findings and centralized scoring/coverage.
5. HTML report plus native Heading/Text section construction.
6. IT Glue transport, pagination, duplicate protection and guarded document publication.
7. Main orchestration and Datto exit handling.

Each probe runs in an isolated in-process PowerShell pipeline with a default 25-second deadline. It does not use remoting, jobs that write files, or temporary script files. WMI enumeration also has a 10-second timeout and a 2,000-row limit. A timed-out pipeline is asked to stop asynchronously; after three timeouts remaining probes become UNKNOWN, bounding repeated provider stalls. A provider stuck in unmanaged code might not stop immediately; process exit ends the component's remaining in-process work. This is not a hard real-time guarantee.

Completed observations in a probe survive later collection errors. The error adds an UNKNOWN/UNSUPPORTED result. Unrelated probes continue. Unexpected baseline/role orchestration failures add required UNKNOWN findings so an incomplete report can still be built and published.

## Threshold variables

All names are case-insensitive Windows environment variable names. Values must be whole decimal integers; invalid values fail clearly with exit 1 rather than silently changing interpretation. The error names the variable but never prints its supplied value.

| Variable | Default | Valid range | Meaning |
|---|---:|---:|---|
| `DHC_EventDays` | 7 | 1–90 | Event lookback days |
| `DHC_MaxEventGroups` | 25 | 1–100 | Global number of event groups displayed |
| `DHC_MaxEventsPerLog` | 2000 | 100–10000 | Per-log sample limit; hitting it reduces coverage |
| `DHC_DiskWarningPercent` | 15 | 1–99 | Percentage component of warning |
| `DHC_DiskCriticalPercent` | 10 | 1–99 | Percentage component of critical |
| `DHC_DiskWarningGB` | 20 | 1–1000 | Absolute component of warning |
| `DHC_DiskCriticalGB` | 10 | 1–1000 | Absolute component of critical |
| `DHC_DiskEmergencyGB` | 2 | 1–100 | Emergency floor, capped at the critical percentage of total volume capacity |
| `DHC_UptimeWarningDays` | 45 | 1–3650 | Uptime warning |
| `DHC_UptimeCriticalDays` | 90 | 1–3650 | Uptime critical |
| `DHC_PatchWarningDays` | 45 | 1–3650 | Latest reliable QFE evidence age warning |
| `DHC_PatchCriticalDays` | 90 | 1–3650 | Latest reliable QFE evidence age critical |
| `DHC_TimeWarningSeconds` | 120 | 1–86400 | Absolute measured NTP offset warning |
| `DHC_TimeCriticalSeconds` | 300 | 1–86400 | Absolute measured NTP offset critical |
| `DHC_MinimumCoverage` | 80 | 1–100 | Minimum usable weighted coverage |
| `DHC_ProbeTimeoutSeconds` | 25 | 5–120 | Deadline for each logical probe |

Warning must be less than critical for age/time thresholds. Disk critical percentage/GB must be less than warning percentage/GB; emergency GB must not exceed critical GB. Sizes labeled GB use PowerShell's binary `1GB` (GiB).

Central disk formula, in evaluation order:

```text
UNKNOWN: invalid/missing capacity data
effectiveEmergencyGB = min(emergencyGB, sizeGB * criticalPercent / 100)
CRITICAL: freeGB < effectiveEmergencyGB
       OR (freePercent < criticalPercent AND freeGB < criticalGB)
WARNING: freePercent < warningPercent AND freeGB < warningGB
PASS: otherwise
```

A 10 TB volume with 1 TB free passes this capacity rule. Small volumes with substantial percentage free are not flagged solely because their total capacity is below 2 GB; no assumption is made that an unlettered volume is a recovery or EFI partition. The rule evaluates free capacity, not storage reliability. SMART/modern storage health and storage events are separate checks.

Other deterministic v1 rules:

| Evidence | Rule |
|---|---|
| CPU | Three one-second-spaced samples; formatted performance WMI first, with validated logical-processor-weighted Win32_Processor.LoadPercentage fallback; WARNING only when every sample is at least 90%; both providers failing stays UNKNOWN |
| Memory | At least 90% physical memory used => WARNING; point-in-time observation |
| Core/role service | Expected continuously running service stopped => CRITICAL; demand-start backup engine stopped => INFO |
| Pending reboot | Any recognized reboot indicator => WARNING |
| SMART | PredictFailure true => CRITICAL; absent provider => unavailable |
| Modern storage | Provider Healthy/Warning/Unhealthy mapped directly; unknown values remain UNKNOWN |
| Firewall | Disabled profile => WARNING; includes active/inactive profile indicator |
| Defender | Normal mode without enabled antivirus/realtime protection => WARNING; passive mode is not automatically Critical |
| Encryption | BitLocker protection Off => WARNING; validate policy applicability |
| TPM | Present but disabled/inactive => WARNING |
| Secure Boot | Supported but disabled => WARNING |
| SMBv1 / RDP | Explicit SMBv1 enabled or RDP enabled without confirmed NLA => WARNING |
| Events | Warning/error group => WARNING; level 1 => CRITICAL; at least three events from exact disk/Ntfs/storport/stornvme providers => CRITICAL |
| AD replication | Nonzero replication result/failures or >24h last success => CRITICAL; >12h => WARNING; compare site schedules |
| SYSVOL | Missing SYSVOL/NETLOGON share or SysVolReady !=1 => CRITICAL; non-normal DFSR state => WARNING |
| DNS | Paused/shutdown zone => CRITICAL; no zones => WARNING |
| DHCP | >=85% utilization => WARNING; >=95% => CRITICAL; inactive scope/non-normal failover => WARNING |
| Printing | Offline/error indicators or job >=60 minutes old => WARNING |
| Hyper-V | Checkpoint >7 days old or >3 checkpoints => WARNING; abnormal replication follows reported health |
| IIS | Stopped site/pool => WARNING; invalid/expired HTTPS certificate => CRITICAL; expiry <30 days => WARNING |
| WSB | Last success >48h => WARNING; >168h => CRITICAL; missing success date => UNKNOWN |
| Cluster | Non-Up node/non-Online group => WARNING; Failed group/resource => CRITICAL; stopped resources alone are INFO |
| SQL platform | Automatic engine/agent service stopped => WARNING; no database-level conclusions |
| AD CS | CA certificate invalid/expired => CRITICAL; expiry <60 days => WARNING; historical CA certificates may also appear |

Review thresholds against each customer's policies. A WARNING recommendation never authorizes or executes a change.

## Findings, score and coverage

Every observation contains Category, Subcategory, CheckName, Status, Severity, Weight, Required, Applicable, Summary, Evidence, Recommendation, Source, CollectionTime and CollectionSucceeded. Event results also retain structured group metadata. Statuses are PASS, INFO, WARNING, CRITICAL, UNKNOWN, UNSUPPORTED, NOT APPLICABLE.

The per-probe weight is centralized in `Initialize-HealthEngine`:

| Category | Weight per probe |
|---|---:|
| Identity | 2 |
| Hardware | 3 |
| Storage | 5 |
| Windows | 4 |
| Patch | 4 |
| Security | 4 |
| Network | 3 |
| Events | 3 |
| Roles | 5 |
| Runtime | 5 |

A probe's weight is divided equally among its observations. More drives or services inside a probe do not drown out the other probes. Applicable roles introduce their own probes, so the score is an assessment of the current applicable check set, not a benchmark across different device types. Lifecycle has weight 2.

```text
denominator = sum of weights of applicable findings
coverage = 100 * sum of successfully collected applicable weights / denominator
score = floor(100 * sum(weight * credit) / denominator)
credit: PASS=1, INFO=1, WARNING=0.5, CRITICAL=0, UNKNOWN=0, UNSUPPORTED=0
```

INFO means the indicated evidence was collected, not that a comprehensive health test passed. NOT APPLICABLE is removed from both numerator and denominator. Missing checks stay in the denominator, so they cannot inflate the score. Coverage uses unrounded values when testing the threshold; display rounds to one decimal.

Required probes are system identity, CPU/memory, fixed-volume capacity, core critical services, reboot indicators, installed update evidence, endpoint protection, firewall, IP configuration, System/Application event coverage, role detection, applicable primary role checks and role services. Explicit runtime/orchestration failures are required. Any unavailable observation within a required probe withholds the official score, even if aggregate coverage exceeds 80%. Other unavailable checks reduce coverage.

When coverage is below the threshold or any required finding is unavailable, overall status is **Unable to Assess**, the official score is **Withheld**, and a prominent **ASSESSMENT INCOMPLETE** banner appears. Otherwise 90–100 is Healthy, 75–89 Attention Required, 50–74 At Risk, and below 50 Critical. **Any Critical finding overrides a numerical noncritical status.** Known Critical findings remain visible even when the official score is withheld.

## Role coverage

Roles are detected from service/configuration evidence, shared printers, non-system SMB shares, and installed ServerManager features when available. ServerManager is not required; WMI server-feature inventory is a fallback. Only applicable role sections appear.

| Pack | Read-only evidence |
|---|---|
| Active Directory Domain Services | NTDS, domain/forest/FSMO visibility, local inbound/outbound partner metadata, replication failures/age, SYSVOL/NETLOGON, DFSR state and logs |
| DNS Server | DNS service, zones and pause/shutdown state, forwarders, up to five local SOA resolution queries, DNS events |
| DHCP Server | DHCP service, IPv4 scopes, utilization, state, failover, operational events |
| File Services / SMB | Server service, share metadata/state/encryption, baseline volume health, existing VSS snapshots/services, SMB events |
| Print Server | Spooler, shared printer state, aggregate queued jobs/old jobs, PrintService events; no document/owner fields |
| Hyper-V | VMMS, VM states, integration metadata, replication, checkpoint age/count, switches and configured disk path existence |
| IIS | W3SVC/WAS, site/pool state, bindings and locally resolvable HTTPS certificate validity; System/Application failures |
| Remote Desktop Services | Session Host/licensing/broker/gateway indicators, role services, policy licensing indicators, session-manager events; no session content |
| Windows Server Backup | Engine presence/service, backup summary and recent backup events |
| Failover Clustering | Service, nodes, groups/resources, quorum, operational events; no validation/remediation |
| SQL Server Platform Indicators | Windows engine/agent services, registry instance/version/edition metadata and Application events; no SQL credentials or queries |
| Active Directory Certificate Services | CertSvc, active CA name, configured CA certificate hashes and certificate validity, Application events; no enrollment |

Legacy roles lacking corresponding management modules are detected but their richer checks become unavailable. AD checks target the assessed controller, not a forest-wide assessment. DHCPv6, RDS CAL inventory, VSS writer interrogation, application-specific health, guest OS health and SQL database health are outside these v1 checks. Hyper-V path checks inspect only configured paths, never directory trees. Share paths are reported for correlation with baseline volume results; client access and effective permissions are not tested.

## Event analysis and data handling

System, Application and applicable role logs are filtered server-side by log, start time and levels 1–3. The Security log is not read. Events are grouped by log/provider/ID/level, then prioritized by level, recency and repetition. The report displays at most `DHC_MaxEventGroups` **across all logs**. Every group contributes to aggregate log severity; hidden groups do not silently disappear from evaluation. Sample caps and omitted group counts are visible.

DCOM 10016 is suppressed as known informational permission noise. No root cause is inferred from an event ID. To avoid leaking document names, command lines, passwords or tokens from arbitrary application payloads, **raw event messages are not read into the report**. The report supplies a deterministic sanitized summary, provider/ID, count, first/last timestamp, and an investigation action. Referenced events can be inspected locally by a technician when needed.

All collected values are treated as text and HTML-encoded. HTML uses simple tables and conservative inline styling, with status words visible without color. Row/output caps are explicit; findings beyond display caps still affect scoring. No JavaScript, remote images, external fonts or CSS are used.

## IT Glue update and failure behavior

The implementation follows the [official IT Glue API documentation](https://api.itglue.com/developer/) as inspected on 2026-10-06. Native headings are intended to populate IT Glue's document Contents panel, described in the [IT Glue document guide](https://help.itglue.kaseya.com/help/Content/2-using/documents/quick-guide-for-documents.html). Actual tenant rendering remains unverified.

1. Build and size-check the complete report in memory.
2. List all organization folders with pagination and find an exact case-insensitive `Device Health Checks` match. Duplicate names anywhere in the organization fail. Create only when absent, then reconcile uniqueness.
3. List documents using the documented `filter[document_folder_id]`. Find the exact case-insensitive computer name. Duplicate names fail; valid IDs, organization, folder, document type, public flag and archive state are checked.
4. Read the document and all current section metadata. Refuse to overwrite a nonempty document that is not recognized as this component's managed schema. There are no undocumented revision endpoints or Flexible Asset calls.
5. Write and publish a visible **UPDATE INCOMPLETE** freshness guard before changing report content. Existing content stays available with the warning. This intentionally causes an intermediate publish in addition to final publication; its effect on tenant revision counts must be tested.
6. Reuse existing Heading/Text section IDs where possible; append only additional sections. Read back each change. Check the current section against its snapshot before writing to detect concurrent edits. The API has no documented atomic compare-and-swap; a race remains possible between check and write.
7. After all replacement sections are verified, remove only surplus sections from the managed report. Finalize the new executive banner last, verify the complete section sequence, then call the documented publish operation and validate publication metadata.
8. On failure, restore only still-identifiable existing sections whose current contents match this attempt's writes. Do not blindly recreate deleted sections or repeat uncertain creates. Keep/reapply the freshness guard where safely possible. Return exit 1 and explicitly request manual review; do not claim rollback was transactional.

No API response body or arbitrary structured validation detail is dumped into Datto. Errors provide method, HTTP status and a fixed safe explanation. This intentionally forgoes potentially sensitive echoed field values. GET retries use 2/4/8-second backoff, at most four attempts, for transport failures, 429 and 5xx. Other responses fail promptly. POST is never automatically retried. An ambiguous POST is reconciled by listing the resource and requiring a unique match; if not confirmed, stop and inspect before rerunning. Ambiguous PATCH is read back, not blindly retried. DELETE failure stops publication.

Pagination uses bounded numbered pages and validates IDs/repetition. Server-provided redirect/next URLs are never followed with the API key. Requests use UTF-8, `x-api-key`, the documented JSON:API media type, 30-second transport timeouts, TLS 1.2 and normal certificate validation. Responses are size-bounded. HTML readback comparison tolerates whitespace/entity normalization, removal of presentation-only attributes, table section wrappers, and equivalent b/strong or i/em markup. It still verifies text, rows/cells, semantic elements, link attributes, section type, order and heading level. Unparseable or materially changed content fails visibly. Failure logs identify the document, section/stage, HTTP status when available, and differing fields/character counts without dumping report content.

**History limitation:** The documentation states what the publish API does, but does not establish that every API publish produces the user-visible revision entry required here. No tenant was available to test this. This release does **not** claim revision/history acceptance. The manual checklist tests two assessments, retained document ID, native heading navigation, and visible prior versions. If the tenant API fails that requirement, record the observed limitation; do not invent a revision endpoint or custom historical database.

## Exit codes and operations

| Code | Meaning |
|---:|---|
| 0 | Sufficiently complete collection and successful publication; health may still be Critical |
| 1 | Invalid configuration or execution/publishing failure prevented a reliable final document |
| 2 | Report published but unsupported/materially incomplete |

Preview mode uses equivalent completeness codes, with upload intentionally skipped. Datto's job runner may visually categorize both nonzero codes as failures; the console explains which occurred.

Major phases and a final summary include computer, OS, PowerShell, status, score/Withheld, coverage, counts, document ID and exit code. No raw event payloads are logged. If an API outage prevents updating a document, no script can guarantee that stale content was replaced; the component reports failure and explicitly flags the document as unreliable.

Runtime targets are under five minutes on an ordinary workstation and under ten on an ordinary server. API rate limits, large role inventories and inaccessible providers can exceed these targets. WMI, event, row and output caps limit resource use; no recursive scans occur. Multiple detected roles add probes. Optional raw time status uses two allowlisted `w32tm /query` operations, each bounded to ten seconds. NTP measurement is a single read-only UDP query, rejects unsynchronized/invalid replies and >2-second round trips, and is not proof Windows Time selected that peer or is continuously synchronized.

## Read-only assurance and limitations

See [command/method review](tests/DeviceHealthCheck.ReadOnlyReview.md) for the source audit and automated mutation guard. The endpoint assessment path uses getters, queries and in-memory operations. It never writes registry/configuration, installs software, initiates updates, repairs trust, changes services/roles, or alters client data. Only requested preview output and authorized remote IT Glue documentation writes are intentional mutations.

No script can promise the OS, a third-party provider, antivirus, or the network stack will produce absolutely no incidental logging/cache activity while servicing reads. The component does not invoke diagnostic procedures whose purpose includes temporary test writes. Native executable execution is a closed allowlist containing only `w32tm.exe /query /status /verbose` and `/query /source`. Timeout cleanup may terminate only that child query process, never a Windows service or an unrelated process.

Known assessment limits:

- Windows SecurityCenter2 registration is client-only and does not verify third-party agent protection. Servers without usable Defender evidence may have required endpoint protection UNKNOWN; validate in the EDR console.
- QFE installed-update dates cover only available CBS/QFE evidence, not all updates, patch applicability, or compliance. The script never searches for updates. Unparseable/localized/future dates are not treated as recent patches.
- SMART may be hidden by virtualization, RAID or storage controllers. Modern provider health and disk model inventory are independent observations.
- Local administrator membership is direct membership; nested effective privileges are not expanded.
- Gateway ICMP failure is informational. Domain DNS checks resolve the domain and DNS-server checks query SOA; no temporary registrations or dynamic-update tests are used.
- Lifecycle matrix version is `SupportMatrixLastUpdated = 2026-10-06`. It deliberately recognizes only explicitly known build/edition pairs. Modern Windows client servicing channels, unknown editions, future builds and ESU entitlement are not guessed.
- Role and report caps can omit displayed rows; review cap notices. A provider timeout cannot be interpreted as absence of a role or a healthy result.
- There is no distributed document lock, transaction, guaranteed rollback, or custom history. Avoid concurrent Datto runs and manual edits during publication.
- Existing same-name documents must be empty or component-managed. Migration of a human-authored document is intentionally not automatic.

Lifecycle sources: [Windows Server releases](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info), [Server 2012/R2 end of support](https://learn.microsoft.com/en-us/lifecycle/announcements/windows-server-2012-r2-end-of-support), and [Microsoft lifecycle products](https://learn.microsoft.com/en-us/lifecycle/products/). The matrix describes standard support only, not ESU licensing.

## Troubleshooting

| Symptom | Investigation |
|---|---|
| Missing key/invalid organization | Correct masked Datto variables and positive organization ID |
| HTTP 401/403 | Verify key validity, API access and target organization permissions |
| HTTP 404/422 | Verify tenant supports the documented native Documents/Sections APIs and exact schema; do not fall back to undocumented endpoints |
| TLS/transport failure on old Windows | Verify existing .NET/TLS/root-certificate/network capability through normal maintenance; no downgrade is attempted |
| Duplicate folders/documents | Resolve duplicates deliberately in IT Glue; the script never chooses the first match |
| UPDATE INCOMPLETE remains | Review affected sections and Datto failure output before retrying; API writes are not atomic |
| Low coverage or required UNKNOWN | Review Unsupported / Unable to Assess, privileges, module availability and provider limits |
| 32-bit unsupported banner | Run Datto's component with 64-bit Windows PowerShell |
| HTML readback mismatch | Capture a sanitized synthetic example in a test tenant; adapt only after verifying IT Glue's sanitizer behavior |

## Tests

Run the dependency-free offline suite with Windows PowerShell 5.1:

```powershell
powershell.exe -NoProfile -NonInteractive -File .\tests\DeviceHealthCheck.Tests.ps1 -SamplePath .\tests\DeviceHealthCheck.sample.html
```

The tests never contact IT Glue or modify Windows roles. They cover fixtures for role detection/evaluation, missing providers, scoring, legacy dispatch/JSON, HTML safety, API duplicates/errors/retries, ambiguous creation, partial updates, and main exit codes. They also scan the parsed source for mutating commands and unsupported language constructs. See [test results](tests/DeviceHealthCheck.TestResults.md) and the full [37-scenario validation matrix](tests/DeviceHealthCheck.Validation.md). `tests/DeviceHealthCheck.sample.html` is synthetic; `tests/DeviceHealthCheck.local-preview.html`, when generated, contains real local infrastructure evidence.

### v1.0.2 live-report follow-up

The supplied IT Glue export and Datto log confirm end-to-end publication of document [withheld] with exit 2. The required missing evidence was CPU sampling. v1.0.2 adds a read-only sampling fallback, caps the emergency disk floor for small volumes, and renders technical grids wider than four fields as two-column records for PDF readability. Native TOC click behavior and revision history remain unverified. Domain secure-channel failure and Windows Time stale-sync evidence are retained as findings; no repair is performed.
