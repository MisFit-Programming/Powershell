# Test results

Date: 2026-10-06. Runtime tested: Windows PowerShell **5.1.26100.9444**, Windows 11 Pro build **26300**, 64-bit. No external testing module was installed. No production Windows roles or IT Glue resources were modified.

## Automated regression suite

**PASS — 169 assertions (v1.0.2).** Run with Windows PowerShell 5.1 using `DeviceHealthCheck.Tests.ps1`. Full console output is retained locally and is not published because it includes the executing workstation name. The generated `DeviceHealthCheck.sample.html` contains synthetic findings.

Verified:

- Whole-file parsing on Windows PowerShell 5.1 and static guard against known post-2.0 language syntax.
- Legacy/full/WOW64 dispatch; .NET JavaScriptSerializer bootstrap round trip.
- Threshold validation, combined absolute/percentage disk logic, emergency floor and invalid capacity.
- Weighted score, unknown credit, coverage denominator, N/A exclusion, required-area withholding and critical override.
- Collector exception isolation, timeout handling, preservation of critical evidence before a later failure.
- Known lifecycle build/edition classification and unknown-channel behavior.
- Detection of all twelve role packs and no-role fixtures; role queries executed with Windows fixtures, including DHCP exhaustion, old checkpoints, failed cluster resource and stopped IIS site.
- Event filtering/grouping/privacy/display bounds and capped collection coverage.
- Native Heading/Text section construction, HTML encoding/redaction, balanced markup and every local Contents target.
- First/second mocked publication retains one document ID, creates no duplicate sections on the second run and calls the documented publish path.
- Duplicate folders/documents, invalid IDs, bounded pagination and refusal to follow untrusted pagination URLs.
- HTTP 401/403/404/422 no-retry handling, transient 429/500 GET retries and bounded exhaustion.
- Ambiguous folder, document and section creates reconcile without repeating POST; unconfirmed creates stop.
- Partial section update failure restores prior changed content where deterministic and retains a visible incomplete warning.
- Main exit code 0 for complete Critical health, 2 for published incomplete/unsupported, 1 for configuration failure; SkipUpload makes zero API requests.
- Parsed command/method review and guards against endpoint mutation cmdlets, TLS bypasses, arbitrary command invocation and secret-bearing BitLocker/TPM getter objects.

The API tests replace transport with an in-memory store. They prove the component's control flow under the modeled API contract; **they do not prove actual IT Glue schema acceptance, HTML sanitizer behavior, native Contents navigation or revision creation**. Role fixtures likewise do not replace execution on real role providers.

## Actual local collection

A full read-only preview was run on this Windows 11 machine with Windows PowerShell 5.1, using the current account rather than Datto SYSTEM. The final measured run completed in **25.9 seconds**, returned component exit **0**, and reported **Critical**, score **69**, coverage **80%**, with six unavailable observations. This demonstrates that health severity does not determine process failure. It is not a comprehensive diagnosis of this endpoint, and observations can change between runs.

Earlier runs with unavailable required evidence correctly produced **Unable to Assess / Withheld / exit 2**. Optional missing capabilities and denied security reads remained unavailable findings. Build 26300 remained lifecycle UNKNOWN rather than being assigned a guessed support date.

`DeviceHealthCheck.local-preview.html` contains actual local evidence and should remain internal. Its markup was parsed successfully as balanced XML after normalizing HTML void elements. Synthetic report navigation targets were checked automatically. Browser visual inspection was **not completed**: the browser tool rejected local-file URLs, and no workaround was used.

## Unverified / blocked checks

- **Live IT Glue acceptance pending:** the user confirmed no test tenant was available and requested these checks be documented as pending. No credentials were requested in chat; no live API writes were attempted.
- **Native revision/history pending:** no claim that API publish creates the desired user-visible historical revision. See the explicit two-assessment procedure in `DeviceHealthCheck.Validation.md`.
- **Native Contents navigation pending:** native Heading sections are generated, but clicking the tenant's Contents panel was not tested.
- **Legacy OS and actual PowerShell 2.0–4.0 parser/runtime pending:** dispatch and codec tests execute under 5.1; actual legacy VMs are required.
- **Actual 32-bit launch blocked:** local signing policy rejected the unsigned component before it ran. No execution-policy change was made. The explicit degradation branch is covered by fixtures.
- **Server role integration pending:** actual Server 2008 R2/2012 and other server builds, provider permissions/schema differences and all twelve installed role combinations require the supplied lab checklist.
- **Fleet timing pending:** the local workstation timing does not establish runtime across large or degraded servers.

## Release conclusion

Implementation and available local/offline validation are complete. The artifact is ready for controlled lab/tenant acceptance, **not a claim that every production acceptance criterion has been independently verified**. Use the 37-scenario checklist and read-only review before broad Datto deployment.

## v1.0.1 publication follow-up

A user-supplied live screenshot showed native headings and an executive table saved before an incomplete publication. This establishes partial native document creation, not successful end-to-end publication, clickable TOC behavior, or revision history. Strict raw HTML comparison was a plausible failure point; the previous catch hid its cause. v1.0.1 accepts bounded presentation normalization, retains semantic/content checks, and logs safe failure stage/mismatch details. Seven regression assertions verify formatting normalization, changed/missing evidence rejection, link preservation and malformed/DTD rejection. Tenant rerun is required to confirm the reported failure is resolved.

## v1.0.2 actual tenant evidence and follow-up

The user provided a successful Datto publish log (document [withheld], exit 2) and an eleven-page IT Glue PDF export. The export identifies CPU sampling as the required unavailable area. Its two small-volume critical findings are false positives from the uncapped 2 GB emergency floor; their reported free percentages were 50.2% and 85.1%. Regression tests now cover both values, actual exhaustion on small and normal volumes, fallback CPU sampling, sustained high load, and invalid fallback data. The export confirms end-to-end native publication; revision/history and TOC click navigation are still not established by a static PDF. Source page 3 was rendered and inspected; wide-grid wrapping was confirmed. Technical grids now use two-column records, with markup/anchor tests passing; tenant export rendering of this new layout requires the next run.
