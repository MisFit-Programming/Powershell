# Read-only engineering review

Reviewed source: `DeviceHealthCheck.ps1`, version 1.0.0, 2026-10-06. This is a source-level assurance record plus automated regression checks, **not** a claim of exhaustive formal verification or fleet-wide runtime validation.

## Command inventory and rationale

| Commands / operations | Review |
|---|---|
| `Get-Command`, `Get-Module`, `Import-Module`, `Add-Type -AssemblyName` | Inspect/import already installed commands/assemblies into this process. No module/package/feature installation. No compiler source supplied to Add-Type. |
| `Get-Item function:...` | Read definitions of this script's fixed helper functions to initialize isolated collectors. No dynamic user-supplied collector code. |
| `Get-Item Cert:\LocalMachine\...` | Certificate metadata reads only. No private-key export, enrollment or certificate store writes. Thumbprint/store components validated. |
| `Get-ChildItem IIS:\AppPools` | IIS configuration enumeration only. No filesystem traversal or app-pool state changes. |
| `Get-WinEvent -FilterHashtable -MaxEvents` | Bounded read of named System/Application/applicable role logs, levels 1–3 and lookback. Never Security. Raw message property is not read. |
| `Get-PhysicalDisk`, `Get-SmbServerConfiguration`, `Get-SmbShare` | Storage/SMB configuration and health getters only. No setters or storage actions. |
| `Get-MpComputerStatus`, `Confirm-SecureBootUEFI` | Read security posture. BitLocker and TPM use explicitly projected WMI properties, avoiding cmdlets that can return key protectors or OwnerAuth. No recovery keys, TPM owner authorization, product keys or credential data. |
| `Test-ComputerSecureChannel` | Domain-member read-only query; `-Repair` never supplied; not run on DCs. |
| `Resolve-DnsName ... -Type SOA -DnsOnly` | DNS lookup only. No temporary records, dynamic-update tests or registration commands. |
| `Get-ADDomain`, `Get-ADForest`, `Get-ADDomainController`, `Get-ADReplicationFailure`, `Get-ADReplicationPartnerMetadata` | Directory metadata/replication reads. No DCDIAG, setters or AD writes. |
| `Get-DnsServerZone`, `Get-DnsServerForwarder` | Server DNS configuration reads. |
| `Get-DhcpServerv4Scope`, `Get-DhcpServerv4ScopeStatistics`, `Get-DhcpServerv4Failover` | DHCP metadata/statistics reads; no lease/reservation/option actions. |
| `Get-VM`, `Get-VMSnapshot`, `Get-VMIntegrationService`, `Get-VMHardDiskDrive`, `Get-VMSwitch`, `Get-VMReplication` | Hyper-V getters. The word Snapshot appears only in the getter. No checkpoint creation, VM lifecycle, migration or replication changes. |
| `Test-Path -LiteralPath` | Existence of configured VM disk paths only. No recursion, file-content access or write test. |
| `Get-Website`, `Get-WebBinding` | IIS reads. No recycle/start/stop or configuration writes. |
| `Get-WBSummary` | Existing backup history read. No backup launch, policy change or test restore. |
| `Get-ClusterNode`, `Get-ClusterGroup`, `Get-ClusterResource`, `Get-ClusterQuorum` | Cluster getters. `Test-Cluster` is never invoked. No role/resource/quorum changes. |
| `Get-WindowsFeature` | Existing server role inventory, with WMI fallback. No Install-/Remove-WindowsFeature. |
| `Select-Object`, `Where-Object`, `ForEach-Object`, `Sort-Object`, `Group-Object`, `Measure-Object` | In-memory selection, grouping and aggregation. |
| `New-Object` | In-memory result objects, lists, readers, WMI queries, read-only COM/ADSI interfaces, sockets, serializers and HTTP requests. Constructors and subsequent methods reviewed below. |
| `ConvertTo-Json`, `ConvertFrom-Json` | In-memory serialization. Legacy bootstrap uses an installed .NET serializer. |
| `Start-Sleep` | Short CPU sample spacing and bounded API retry delays. |
| `Write-Host` | Sanitized operational messages, never raw provider/API payloads. |
| Internal script functions | Wrappers around the reviewed operations, result/evaluation/report creation and authorized remote IT Glue publication. |

The offline suite enumerates parsed command ASTs and rejects mutation verbs, unknown dynamic command invocation and known post-PowerShell-2 syntax. It also scans active tokens (excluding comments) for certificate-validation bypass and mutating native switches. No evaluation command accepts a user-supplied scriptblock from Datto variables.

## .NET / COM / ADSI methods

- WMI uses `ManagementObjectSearcher.Get()` and field projection. `ManagementScope` targets only the local machine; finite connection/enumeration timeouts and a row cap apply. Class names are validated and `Win32_Product` is explicitly prohibited because of its repair side effects. No WMI/CIM methods are invoked.
- Registry access is `LocalMachine.OpenSubKey(path, false)`, `GetValue`, `GetValueNames` and `Close`. No writable keys or SetValue/CreateSubKey/Delete operations exist. Reboot rename entries are tested for presence and their paths are not reported.
- Firewall COM `HNetCfg.FwPolicy2` uses CurrentProfileTypes/FirewallEnabled property reads only. The indexed `FirewallEnabled(profile)` getter is not assigned. COM references are released.
- ADSI's `Invoke('Members')` enumerates direct local Administrators group members. Reflection `InvokeMember('AdsPath','GetProperty',...)` reads their names/paths. No `SetInfo`, Add/Remove or other ADSI mutations exist.
- NTP uses one UDP client request to a configured peer; DNS and ICMP use lookup/Ping APIs. Network responses are validated/bounded; no dynamic DNS registration or Windows Time resync occurs. These actions generate read-only diagnostic network traffic.
- `Diagnostics.Process.Start()` is confined to **two exact allowlisted argument strings** for `%SystemRoot%\System32\w32tm.exe`: `/query /status /verbose` and `/query /source`. It never runs a shell or arbitrary executable. No user text is inserted into the native argument list. Standard output/error are asynchronously drained. A ten-second timeout may call `Kill()` only on the exact process instance created for this query, never a service/unrelated process.
- The PowerShell pipeline `Create/AddScript/AddArgument/BeginInvoke/EndInvoke/BeginStop` operates on hardcoded local collector bodies in isolated in-process runspaces. Timeout cleanup stops only that collector pipeline. It does not invoke Stop-Service or create a persistent task/service.
- `HttpWebRequest.GetRequestStream/Write/GetResponse` intentionally modifies **remote IT Glue documentation** as authorized. Endpoint allowlisting, no redirects, finite limits, normal certificate validation and exact scope/ID checks constrain it. Raw response errors are discarded. No Windows configuration is written by the transport.
- `IO.File.WriteAllText` appears once: behind explicit `-ReportPath` for a requested HTML preview. There are no other local report/cache/temp/history writes, directory creation, file deletion or permission modifications.
- String, math, date, collection, UTF-8, HTML escaping, JSON serialize/deserialize and disposal methods operate only on memory/read handles. TLS selection changes this PowerShell process's HTTP policy, not machine registry configuration.

## Adversarial findings addressed

- A later low-severity event group could overwrite an earlier critical aggregate; severity now only escalates.
- Role results lacked their parent role tag; the report now assigns every role observation to its applicable native section.
- A single-log display limit did not enforce the requested global event limit; the report now selects globally while retaining total omitted counts and severity.
- A late probe exception could hide earlier critical evidence; the collector catch now emits a structured failure after completed observations.
- Unknown checks could otherwise boost a score if excluded; they remain in the denominator and earn zero credit. Required unknowns override the official score.
- Uncertain create retries could duplicate documentation; POST is never retried and a unique readback match is required.
- An intermediate upload could present old green content as current; a published freshness guard precedes changes, final summary is written last, and failed updates return exit 1.
- Blind restoration could overwrite a human edit; pre-write snapshot checks and guarded readback comparisons refuse mismatched content. The residual API check/write race is documented.
- Returning HTTP success without content verification could conceal sanitization; section readbacks and final sequence/count checks must agree, or publication fails visibly.
- OS build alone could misclassify client/server/channel lifecycle; the matrix uses product type, known build and edition, and leaves unknown channels unclassified.
- Server antivirus could wrongly rely on SecurityCenter2; that namespace is queried only on client Windows. Unknown server protection can withhold the official score.

## Boundaries of assurance

The component contains no remediation path. Read-only OS/provider queries can cause ordinary provider initialization, audit logging or network caching as an incidental platform behavior; the component does not deliberately perform temporary test writes. Third-party management modules' internal implementations were not formally audited. Actual role/legacy-VM and live IT Glue behavior remains subject to the validation checklist. Do not claim transactional publication, a complete security audit, database health, guaranteed backup recoverability or verified native history from these tests.
