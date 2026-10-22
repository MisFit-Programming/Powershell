# Validation record

Date: October 22, 2026. Release candidate: 1.0.0.

Follow-up: optional empty recipients added and verified. The 38-node workflow passes 145 mock assertions, including successful delivery without invoking the sharing API when `recipients: []`. Live Teams delivery remains unverified.

## Completed

- Windows PowerShell 5.1 parser and offline regression suite: 34 assertions passed, including rejecting tampered ZIPs and refusing execution on a mismatched release checksum.
- Workflow test harness: 139 assertions passed against the exported workflow's real JavaScript, expressions and branch connections, with simulated Graph responses.
- Live local Windows 11 Pro collection under a **non-administrator account**, with no webhook: 24 collectors processed, approximately 42 seconds. 16 complete, 5 not applicable, 3 limited or failed. The inaccessible encryption provider and missing/limited storage/log data were recorded rather than hidden.
- That run produced a 94,161-byte ZIP, a 551,297-byte Markdown report, structured evidence and manifest. All archive entries matched local files, manifest hashes verified, and a full delivery payload was generated without sending it.
- Hard timeout regression: a controlled worker emitted evidence and then stalled; the parent killed it and retained the evidence.
- Regression coverage includes empty/null data, literal HTML/Markdown escaping, Unicode, recursive secret redaction, readable enum values, bounded events/messages, summary-only fallback, matching run IDs, authentication failure, uncertain receipts, immutable resend verification, and no automatic remediation commands.
- Workflow failure simulation covers report/ZIP uploads, sharing, Teams posting and receipt persistence. Completed retries use the stored message ID. Ambiguous/failed runs preserve a lock and cannot blindly repost.
- Export parameter shapes were checked against official n8n HTTP Request/Webhook source. Text responses explicitly use the `body` field, including status codes.

The Windows workstation run preceded the final small additions for readable enums, explicit uptime days, null-value regression coverage and access-denied classification. Those changes are covered by regression checks and/or the final targeted worker check; no claim is made of a second complete platform rollout.

## Not yet validated in a live environment

- Windows Server 2016, 2019, 2022 and 2025, and Windows 10.
- Elevated administrator and SYSTEM runs.
- Live AD DS, DNS, DHCP, Hyper-V and IIS providers. The workstation correctly reported those roles absent; it exercised local SMB observations.
- Importing/activating this workflow on the user's n8n version, enabling `crypto` in its Code runtime, and connecting OAuth/Header Auth credentials.
- Real Entra consent, OneDrive private-folder permissions and Teams chat access.
- Actual recipient access to both uploaded files.
- GitHub release publication and download from the eventual repository.

## Pilot checklist

1. Publish the reviewed collector and matching checksum to the chosen GitHub release. Verify the launcher rejects a deliberately wrong checksum before deployment.
2. Import the workflow; configure its folder, chat, recipients and credentials. Confirm the destination folder has no unintended inherited sharing. Keep the workflow inactive until configuration is complete.
3. Send a pilot full bundle through the test webhook. Confirm ZIP and Markdown match the local run, recipients can open both, and the message's time-entry text is useful.
4. Resend the same bundle. Confirm one Teams message, one set of files, and the same stored message ID.
5. Test authentication rejection, oversized summary delivery, revoked upload/sharing rights, a failed Teams post, and a failure after posting but before receipt persistence. Follow the recovery instructions in README; never clear a lock without checking Teams for the run ID.
6. Run on an elevated workstation, under SYSTEM via RMM, and on a representative server with installed roles. Check coverage and role observations. Keep per-user evidence limitations visible.
7. Run two devices with the same ticket reference; verify separate device/run folders and messages.
8. Activate the production webhook and provision its URL/token through protected endpoint configuration. Define local/OneDrive retention operationally; the collector does not delete old evidence.

Offline tests establish code behavior under modeled conditions; they do not establish tenant consent, server compatibility, or successful live publication.
