# Share access review and provisioning

Run [Share-Access-Review.ps1](Share-Access-Review.ps1) **on the file server**, in an elevated Windows PowerShell 5.1 or PowerShell 7 session. The account needs share/NTFS administration permissions and permission to create the OU/groups and update group membership. Install the Windows SmbShare and RSAT ActiveDirectory modules beforehand; the script does not install anything.

The examples below assume your current directory is `scripts/file-shares` in the cloned repository:

```powershell
Set-Location .\scripts\file-shares

# Review only: inventories shares, scans child ACLs and reports the proposed mapping.
.\Share-Access-Review.ps1

# Perform the reviewed provisioning and collect before/after snapshots.
.\Share-Access-Review.ps1 -Apply

# Optional explicit DC, additional excluded shares and report destination.
.\Share-Access-Review.ps1 -DomainController 'DC01.example.com' `
    -ExcludeShare 'NETLOGON','SYSVOL','print$','Backups' `
    -OutputDirectory 'C:\Reports\SharePermissions' -Apply

# Preview with the same parameters; reports are still written.
.\Share-Access-Review.ps1 -Apply -WhatIf
```

## Behavior

- Inventories every local SMB share, including hidden, administrative and excluded shares. Special shares are always excluded from modification. NETLOGON, SYSVOL and the printer-driver share `print$` are excluded by default. Supplying `-ExcludeShare` replaces that default list, so include them in your custom list if applicable. Exclusions use exact, case-insensitive share names.
- Only ordinary local drive paths such as `D:\Shares\Data` are eligible for filesystem review/provisioning. Virtual/device paths, including SQL FILESTREAM paths under `\\?\GLOBALROOT\Device\RsFx...`, and other unsupported paths are report-only. Their available SMB ACLs and exclusion reasons are reported; no filesystem access or permission changes are attempted. These shares do not prevent ordinary folder shares from being provisioned. SQL FILESTREAM access is managed through SQL Server; see [Microsoft's FILESTREAM security documentation](https://learn.microsoft.com/en-us/sql/relational-databases/blob/filestream-sql-server#filestream-security).
- Creates the protected `OU=Share Permissions` directly beneath the selected AD domain root if required.
- Creates domain-local security groups `DLSG_FS_<SHARE>_RW` and `DLSG_FS_<SHARE>_RO`, including empty groups when there are no mapped users.
- Grants RW **SMB Change + NTFS Modify**, and RO **SMB Read + NTFS ReadAndExecute**. NTFS grants apply to the root and inherit to subfolders and files that accept inheritance. It does not reset child ACLs or enable inheritance on protected children.
- Maps named **user objects from the selected AD domain** referenced directly in SMB or root NTFS ACLs. Inherited root entries naming users count; inherit-only entries do not. Groups, local accounts, computers, well-known principals and accounts from other domains are not copied or expanded.
- Any content-write, append, delete or permission-management NTFS bit maps to RW; content read/list maps to RO. SMB Full/Change maps to RW; Read maps to RO. RW wins when a user has both. Custom metadata-only permissions and unresolved identities are reported without mapping. A named user with a root/SMB deny entry is left for manual review.
- Records explicit or inheritance-protected ACLs on **both files and directories** below eligible shares. These never supply group members. Reparse points are reported and not followed. Recursive scanning of special/excluded shares is skipped to avoid traversing entire administrative drive shares; their root details remain in the report.
- Preserves existing direct permissions, unrelated ACL entries, group members, folder ownership and inheritance settings. Existing equal/higher managed-group grants are retained. Conflicting/lower SMB grants and managed-group denies fail for manual review. A failed run may have partial changes; reruns complete missing steps without duplicating the successful grants/members.

## Review the proposed access

This deliberately follows the requested union of named users from SMB and root NTFS. It is **not an effective-access calculation**. A user with access at only one layer will gain a grant at both layers; a partial write ACE becomes Modify; inheritable root access can extend access into descendants. Full-control users keep their original FullControl ACEs while the new RW group receives Modify. Existing group-based access and denies are not evaluated. No original ACE or membership is removed.

Preflight blocks all changes if an eligible share's inventory or mapping fails, names collide, an existing managed group contains non-user members, or a root grant could affect an excluded share's root through an alias/parent path. Failed ACL reads on report-only/excluded shares are logged as warnings and do not block provisioning. Apply-time failures are recorded and other plans continue. Previously managed groups belonging to another server/share are rejected using their description marker. Existing unmarked groups must be domain-local security groups in the correct OU; review their reported memberships before applying.

Group names use an uppercase share name with unsupported characters replaced by `_`. Very long names receive a stable hash suffix. Collisions between scopes/shares stop provisioning. Because the requested names do not include a server name, identical share names on different servers need separate planning; the script does not silently reuse a group marked for another server.

## Reports and logs

By default each run writes unique files under `ShareReports` next to the saved script. When pasted into a console or run as an unsaved selection, it uses `ShareReports` under the current filesystem folder instead. You can always set `-OutputDirectory` explicitly; relative paths resolve against the current PowerShell location. From a non-filesystem location, specify a filesystem output path.

- `ShareReview-<run>.html`: collapsible before/after share ACLs, NTFS roots, child exceptions, proposed mappings, memberships, actions, exclusions and errors.
- `ShareReview-<run>.json`: structured version of the report with NTFS security descriptors.
- `ShareReview-<run>.before.json`: inventory saved before provisioning.
- `ShareReview-<run>.actions.jsonl`: append-only action journal written during execution.

Preview runs have a before snapshot and proposed plan; after ACLs are collected in Apply mode. Exit code `0` means complete, `1` means errors/incomplete work. No automatic rollback is attempted. Scanning every descendant can take substantial time on large shares; progress is displayed during the scan.

## Validation

The offline harness in [tests/Share-Access-Review.Tests.ps1](../../tests/Share-Access-Review.Tests.ps1) mocks all infrastructure I/O and verifies preview/WhatIf, named-only mapping, child-only/deny/inherit-only exclusions, OU/group creation, ACL preservation, idempotent reruns, failure blocking, name collisions and HTML escaping. From the repository root, run `powershell.exe -NoProfile -File .\tests\Share-Access-Review.Tests.ps1` or `pwsh -NoProfile -File .\tests\Share-Access-Review.Tests.ps1` on Windows. It does not validate real AD replication, server permissions or filesystem inheritance propagation.

Implementation references: [Microsoft SMB grant documentation](https://learn.microsoft.com/en-us/powershell/module/smbshare/grant-smbshareaccess), [AD membership documentation](https://learn.microsoft.com/en-us/powershell/module/activedirectory/add-adgroupmember), and [additive filesystem ACL rules](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemsecurity.addaccessrule).
