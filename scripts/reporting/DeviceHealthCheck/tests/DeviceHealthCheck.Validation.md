# Acceptance and manual validation

Status date: 2026-10-06. **No test IT Glue tenant was available; the user explicitly requested live checks remain pending.** Do not describe mocked API outcomes as tenant verification. No Windows role was installed, changed or broken to create these tests.

Run `DeviceHealthCheck.Tests.ps1` under Windows PowerShell 5.1. Review its output and `DeviceHealthCheck.TestResults.md`. The following matrix accounts for all 37 requested scenarios.

| # | Scenario | Automated evidence | Remaining manual validation |
|---:|---|---|---|
| 1 | Windows 11 / PowerShell 5.1 | Real local SkipUpload run on Windows 11 Pro build 26300; main orchestration fixture | SYSTEM-context pilot, normal supported Windows 11 build, live publish |
| 2 | Server 2012 / 5.1 | Runtime dispatch, Server 2012 lifecycle/main fixtures | Actual Server 2012 VM with 5.1, local preview and publish |
| 3 | Server 2012 / below 5.1 | Legacy dispatch, unsupported report, successful mocked publish => 2 | Actual PowerShell 3.0/4.0 engine; secure TLS bootstrap |
| 4 | Server 2008 R2 / Windows 7 | PS2 syntax guard, legacy JSON round trip, unsupported dispatch | Actual 2.0 parser and installed .NET/TLS combinations; 5.1 collection on legacy VMs |
| 5 | Domain controller | Detection, FSMO/replication/DFSR fixture execution | Read-only healthy/stale replication on lab DCs; both partner directions |
| 6 | DNS server | Detection, zones/SOA fixture, failed query isolation | Existing lab DNS role and known paused-zone evidence |
| 7 | DHCP server | Detection, 98% exhaustion Critical fixture, failover fixture | Existing scopes/failover, no lease modifications |
| 8 | File server | Detection and metadata/VSS fixtures | Share path/volume correlation, modern/legacy SMB providers |
| 9 | Hyper-V | Old checkpoint WARNING, replication Critical fixture | Actual VM integration/storage/switch evidence; no VM changes |
| 10 | IIS | Stopped site WARNING fixture, pool/binding execution | HTTPS hash mapping, expired/valid fixtures or existing lab certificates |
| 11 | RDS | Detection, service/licensing fixture | Session Host/broker/licensing/gateway combinations and localized data |
| 12 | Cluster node | Node/group/quorum fixture; Failed resource Critical | Existing lab cluster read access; no Test-Cluster |
| 13 | No roles | Detection fixture verifies zero role packs | Workstation and minimal server preview |
| 14 | One role query fails | DNS failure => UNKNOWN; following DHCP check runs | Access-denied read on an existing lab capability |
| 15 | Event log inaccessible | Probe failure UNKNOWN, event fixture errors, required coverage withholding | SYSTEM/event-log ACL variations without changing production ACLs |
| 16 | SMART unavailable | Unsupported collector fixture; actual local capability behavior | VM/RAID/controller combinations |
| 17 | Folder absent | Mock creation and uniqueness reconciliation | First publish to empty test organization |
| 18 | Folder exists | Mock second publication reuses folder | Existing target folder in test tenant |
| 19 | Document absent | Mock native document and section creation | First publish, correct private native document type |
| 20 | Document exists | Mock second run reuses document ID, no POST | Same document ID after a second real assessment |
| 21 | Duplicate documents | Mock exact-name duplicates fail | Deliberately created duplicates in test tenant only |
| 22 | Duplicate folders | Mock exact-name duplicates fail | Same name at root/nested levels in test tenant |
| 23 | HTTP 401 | No-retry failure fixture | Restricted/invalid test key, no key in Datto output |
| 24 | HTTP 403 | No-retry failure fixture | Test key lacking required scope |
| 25 | HTTP 404 | No-retry failure fixture | Tenant availability and deleted test document race |
| 26 | HTTP 422 | No-retry failure and partial section fault fixtures | Actual validation response; no sensitive body logged |
| 27 | HTTP 429 | Bounded GET retry fixture | Observe tenant throttling safely; do not load-test production |
| 28 | HTTP 500 | Retry success and four-attempt failure fixtures | Controlled test proxy/stub only; do not disrupt IT Glue |
| 29 | Ambiguous POST timeout | Mock commit-then-timeout folder reconciliation; single POST | Controlled test transport for folder/document/section ambiguity |
| 30 | Partial section failure | Guarded recovery, visible incomplete warning and failure fixture | Inspect old/new sections, interrupted upload and tenant revision behavior |
| 31 | Coverage below threshold | Weighted denominator and withholding fixtures | Review report banner and score omission |
| 32 | Critical but complete | Critical overrides 99 score; main exits 0 after mock publication | Verify Datto treats component execution independently of health |
| 33 | Invalid override | Decimal/out-of-range invalid; valid override accepted | Datto variable binding and helpful variable-only error |
| 34 | HTML special characters | Encoding/redaction and synthetic report fixtures | Tenant sanitizer with safe synthetic names containing `<`, `>`, `&`, quotes |
| 35 | 32-bit PowerShell on x64 | Degraded dispatch and main report/exit fixture | Native 32-bit execution was blocked by local signing policy; use an approved signed script in lab |
| 36 | Native TOC | Native Heading schema and local anchor assertions | **Pending IT Glue UI click verification** |
| 37 | Revision/history after second run | Two mocked publications retain document ID and call publish | **Pending IT Glue UI revision/history verification** |

Additional v1 packs: Print Server, Windows Server Backup, SQL Server Platform Indicators and AD CS are included in automatic detection/collector fixtures. Actual provider schemas, CA certificate store mapping, SQL instance metadata, WSB history and print queue evidence need lab validation. No database queries or print-job document names are used.

## Tenant acceptance procedure — pending

Use an explicitly designated test organization, a masked environment variable for the key, and a synthetic or lab computer. Never paste API keys into logs, tickets, test fixture files or this repository.

1. Confirm the current official API schemas at `https://api.itglue.com/developer/`. The docs contain both hyphenated JSON examples and underscore parameter descriptions; verify actual accepted folder/document/section field spellings against the tenant. Do not add an undocumented fallback.
2. Run an initial assessment. Record only organization ID, folder ID, document ID, assessment timestamp and result code. Confirm folder name exactly `Device Health Checks`, document name exactly computer name, and private native document type.
3. Open the document. Confirm Heading/Text sections and intentional sort order, clear summary, correct evidence, no opaque uploaded file, and no script/CSS dependencies.
4. Click at least five entries in the native Contents panel, including a role H3. Confirm each navigates to its native heading. Local HTML anchor success does not establish this.
5. Inspect safe synthetic special characters. Confirm encoded data is displayed as text and not interpreted as markup; compare server-sanitized HTML with the component's readback checks.
6. Run a second assessment with changed **synthetic evidence** or a naturally changed lab state. Record that the document ID is identical and no duplicate folders/documents/sections exist.
7. Open native revision/history UI. Record whether a prior user-visible version exists, whether its content is the first assessment, and whether restoration/viewing works through the UI. **Do not infer this from a PATCH response or `published-at` alone.** The freshness guard creates an intermediate publish; document exactly how many revisions appear and their contents.
8. If API publications do not generate the expected history, record the tenant/version/date and observed limitation. Keep acceptance unfulfilled; no invented revision endpoint or custom history workaround.
9. Run an incomplete synthetic assessment. Confirm today's timestamp, score Withheld, conspicuous incomplete banner and prior content no longer presented as today's healthy report. Check exit 2.
10. Inject a section-write failure through a controlled test transport. Confirm exit 1, manual-review warning and that the document is neither blank nor falsely current. Review recovery after an uncertain create and after a surplus-section deletion failure.
11. Test interrupted jobs, concurrent manual edit detection, a deleted document, and two nearly simultaneous same-host runs. Document the residual nontransactional race; schedule one writer per device.
12. Validate US/EU/AU endpoint selection on available regional test accounts. Confirm TLS certificate validation and absence of credential-bearing redirects.

Record results in a separate operational test record containing no API keys or raw sensitive report payloads. Broad deployment requires signoff on actual Windows compatibility and the IT Glue behaviors above.

## Legacy VM procedure — pending

- Snapshot an existing lab VM through its normal management process before testing; do not add snapshot creation to this component.
- Use the OS's existing PowerShell/runtime. Do not install WMF to make the legacy path pass.
- Run the unmodified file first with `-SkipUpload`. Confirm the whole file parses under 2.0 and emits the exact Unsupported title, computer, OS, detected PowerShell, UTC timestamp, required 5.1, unassessed areas and no-remediation statement.
- If the existing .NET stack supports secure TLS 1.2, validate native document publication and exit 2. Otherwise expect a sanitized publishing failure/exit 1. No TLS downgrade, certificate bypass or dependency installation is acceptable.
- For Server 2012/5.1 and Win7/2008R2/5.1, validate generic checks continue when modern cmdlets are absent. Missing capabilities must be unavailable findings, never PASS.
- Use an approved signing/deployment method where execution policy requires signing. Do not change endpoint policy as part of this component.
