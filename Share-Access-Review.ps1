#requires -Version 5.1
<#
.SYNOPSIS
Reviews local SMB shares and adds domain-local RW/RO groups using named ACL users.
.DESCRIPTION
Run elevated on the Windows file server. Default is preview; -Apply enables AD,
SMB and NTFS changes. -WhatIf also previews. Reports are always written.
Requires SmbShare and RSAT ActiveDirectory modules. No modules are installed.
Existing permissions and members are never removed. Child ACLs are report-only;
new inheritable root ACEs naturally propagate to children that inherit.
Exit 0 = complete, 1 = errors/partial failure. There is no automatic rollback.
.EXAMPLE
.\Share-Access-Review.ps1
.EXAMPLE
.\Share-Access-Review.ps1 -Apply -ExcludeShare 'NETLOGON','SYSVOL','Backups'
.EXAMPLE
.\Share-Access-Review.ps1 -Apply -WhatIf
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [switch]$Apply,
    [string]$DomainController,
    [string[]]$ExcludeShare = @('NETLOGON','SYSVOL'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'ShareReports')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:failed = $false
$script:events = New-Object 'System.Collections.Generic.List[object]'
$script:mappings = New-Object 'System.Collections.Generic.List[object]'
$script:memberships = New-Object 'System.Collections.Generic.List[object]'
$script:principalCache = @{}
$before = @(); $after = @(); $plans = @(); $ouDN = ''; $ad = @{}
$mode = 'Preview'; if ($Apply -and -not $WhatIfPreference) { $mode = 'Apply' }
$runId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
$null = [IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($OutputDirectory))
$basePath = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) "ShareReview-$runId"

function Log {
    param([string]$Status, [string]$Target, [string]$Detail)
    $row = [pscustomobject]@{Time=(Get-Date).ToString('o'); Status=$Status; Target=$Target; Detail=$Detail}
    $script:events.Add($row)
    if ($Status -eq 'Error') { $script:failed = $true }
    [IO.File]::AppendAllText("$basePath.actions.jsonl", (($row | ConvertTo-Json -Compress) + [Environment]::NewLine), [Text.Encoding]::UTF8)
}
function Escape-Ldap {
    param([string]$Value)
    $Value.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29').Replace([string][char]0,'\00')
}
function Sid-Of {
    param($Identity)
    $text = [string]$Identity
    if ($text -match '^S-\d-') { return ([Security.Principal.SecurityIdentifier]::new($text)).Value }
    ([Security.Principal.NTAccount]::new($text)).Translate([Security.Principal.SecurityIdentifier]).Value
}
function Ntfs-Rows {
    param($Acl)
    foreach ($rule in $Acl.Access) {
        $sid = ''; try { $sid = Sid-Of $rule.IdentityReference } catch { }
        [pscustomobject]@{Identity=[string]$rule.IdentityReference; SID=$sid; Rights=[string]$rule.FileSystemRights
            Mask=[long]$rule.FileSystemRights; Type=[string]$rule.AccessControlType; IsInherited=$rule.IsInherited
            Inheritance=[string]$rule.InheritanceFlags; Propagation=[string]$rule.PropagationFlags
            AppliesToRoot=(($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0)}
    }
}
function Smb-Rows {
    param([string]$Name, [string]$Scope)
    foreach ($ace in @(Get-SmbShareAccess -Name $Name -ScopeName $Scope -ErrorAction Stop)) {
        $sid=''; try { $sid=Sid-Of $ace.AccountName } catch { }
        [pscustomobject]@{Identity=[string]$ace.AccountName; SID=$sid; Rights=[string]$ace.AccessRight; Type=[string]$ace.AccessControlType}
    }
}
function Child-Exceptions {
    param([string]$Path, [string]$Label)
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Path); $count=0
    while ($stack.Count) {
        $directory=$stack.Pop()
        try { $children = @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) }
        catch {
            Log 'Error' $directory "Cannot enumerate children: $($_.Exception.Message)"
            [pscustomobject]@{Path=$directory; Kind='ScanError'; Protected=$null; Owner=''; Sddl=''; ACL=@(); Error=$_.Exception.Message}
            continue
        }
        foreach ($child in $children) {
            $count++
            if (($count % 500) -eq 0) { Write-Progress -Activity "Reviewing $Label" -Status "$count child objects reviewed" }
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Log 'Skipped' $child.FullName 'Reparse point: not traversed or modified.'
                [pscustomobject]@{Path=$child.FullName; Kind='ReparsePoint'; Protected=$null; Owner=''; Sddl=''; ACL=@(); Error='Not traversed'}
                continue
            }
            try {
                $acl=Get-Acl -LiteralPath $child.FullName -ErrorAction Stop
                $rules=@(Ntfs-Rows $acl)
                if ($acl.AreAccessRulesProtected -or @($rules | Where-Object { -not $_.IsInherited }).Count) {
                    $kind='File'; if ($child.PSIsContainer) { $kind='Directory' }
                    [pscustomobject]@{Path=$child.FullName; Kind=$kind; Protected=$acl.AreAccessRulesProtected; Owner=$acl.Owner; Sddl=$acl.Sddl; ACL=$rules; Error=''}
                }
            } catch {
                Log 'Error' $child.FullName "Cannot read child ACL: $($_.Exception.Message)"
                [pscustomobject]@{Path=$child.FullName; Kind='ScanError'; Protected=$null; Owner=''; Sddl=''; ACL=@(); Error=$_.Exception.Message}
            }
            if ($child.PSIsContainer) { $stack.Push($child.FullName) }
        }
    }
    Write-Progress -Activity "Reviewing $Label" -Completed
    Log 'Scanned' $Label "$count child objects examined. Unique/explicit ACLs retained; no child users promoted."
}
function Inventory {
    param([string]$Phase)
    foreach ($share in @(Get-SmbShare -ErrorAction Stop | Sort-Object ScopeName,Name)) {
        $label="$($share.ScopeName)/$($share.Name)"
        $reason=''; $valid=$true; $smb=@(); $ntfs=@(); $exceptions=@(); $sddl=''; $owner=''; $protected=$false
        if ($share.Special) { $reason='Special/administrative share' }
        elseif ($share.Name -in $ExcludeShare) { $reason='Explicitly excluded share' }
        elseif ([string]::IsNullOrWhiteSpace($share.Path)) { $reason='No filesystem path' }
        try { $smb=@(Smb-Rows $share.Name $share.ScopeName) }
        catch { $valid=$false; Log 'Error' $label "$Phase SMB ACL: $($_.Exception.Message)" }
        if ($share.Path) {
            try {
                $item=Get-Item -LiteralPath $share.Path -Force -ErrorAction Stop
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $reason='Root is a reparse point' }
                $acl=Get-Acl -LiteralPath $share.Path -ErrorAction Stop
                $ntfs=@(Ntfs-Rows $acl); $sddl=$acl.Sddl; $owner=$acl.Owner; $protected=$acl.AreAccessRulesProtected
                if (-not $reason) { $exceptions=@(Child-Exceptions $share.Path "$Phase $label") }
            } catch { $valid=$false; Log 'Error' $label "$Phase NTFS root: $($_.Exception.Message)" }
        }
        if ($reason) { Log 'Skipped' $label "$Phase : $reason. Root details reported; recursive scan skipped." }
        [pscustomobject]@{Name=$share.Name; Scope=$share.ScopeName; Path=$share.Path; Description=$share.Description
            Special=[bool]$share.Special; Exclusion=$reason; RootReadable=$valid; State=[string]$share.ShareState
            EncryptData=$share.EncryptData; FolderEnumerationMode=[string]$share.FolderEnumerationMode
            Owner=$owner; InheritanceBlocked=$protected; Sddl=$sddl; SMB=$smb; NTFS=$ntfs; Exceptions=$exceptions}
    }
}
function Resolve-NamedUser {
    param([string]$SID)
    if ($script:principalCache.ContainsKey($SID)) { return $script:principalCache[$SID] }
    $result=[pscustomobject]@{User=$null; Reason='Not a named user in the target AD domain'}
    if ($SID -and $SID.StartsWith("$domainSID-", [StringComparison]::OrdinalIgnoreCase)) {
        $users=@(Get-ADUser -Filter { SID -eq $SID } -Properties Enabled @ad)
        if ($users.Count -eq 1) { $result=[pscustomobject]@{User=$users[0]; Reason='Named AD user'} }
    }
    $script:principalCache[$SID]=$result
    $result
}
function Classify-Ntfs {
    param([long]$Mask)
    # WriteData, AppendData, WriteEA, DeleteChild, WriteAttributes, Delete,
    # ChangePermissions, TakeOwnership. Metadata-only read is not promoted.
    if (($Mask -band 0xD0156) -ne 0) { return 'RW' }
    if (($Mask -band 1) -ne 0) { return 'RO' }
    return ''
}
function Map-Users {
    param($Share)
    $selected=@{}; $label="$($Share.Scope)/$($Share.Name)"
    $denied=@(@($Share.SMB)+@($Share.NTFS) | Where-Object { $_.Type -eq 'Deny' } | ForEach-Object { $_.SID } | Where-Object { $_ })
    foreach ($source in @('SMB','NTFS')) {
        foreach ($ace in @($Share.$source)) {
            $bucket=''; $reason=''; $user=$null
            if ($ace.Type -ne 'Allow') { $reason='Deny ACE: not mapped' }
            elseif ($source -eq 'NTFS' -and -not $ace.AppliesToRoot) { $reason='Inherit-only ACE does not grant root access' }
            elseif (-not $ace.SID) { $reason='Unresolved trustee: not mapped' }
            else {
                $resolved=Resolve-NamedUser $ace.SID; $user=$resolved.User
                if (-not $user) { $reason=$resolved.Reason }
                elseif ($ace.SID -in $denied) { $reason='Named user has a root/SMB deny: manual review, not mapped' }
                else {
                    if ($source -eq 'SMB') {
                        if ($ace.Rights -in @('Full','Change')) { $bucket='RW' }
                        elseif ($ace.Rights -eq 'Read') { $bucket='RO' }
                    } else { $bucket=Classify-Ntfs $ace.Mask }
                    if ($bucket) {
                        $reason='Direct named-user ACL entry (not expanded from group membership)'
                        if (-not $selected.ContainsKey($ace.SID) -or $bucket -eq 'RW') { $selected[$ace.SID]=[pscustomobject]@{User=$user; Bucket=$bucket} }
                    } else { $reason='Custom/metadata-only rights: manual review, not mapped' }
                }
            }
            $script:mappings.Add([pscustomobject]@{Share=$label; Source=$source; Identity=$ace.Identity; SID=$ace.SID; Rights=$ace.Rights; Candidate=$bucket; Reason=$reason})
        }
    }
    @($selected.Values | Sort-Object {$_.User.SamAccountName})
}
function Group-Name {
    param([string]$ShareName, [string]$Bucket)
    $stem=($ShareName -replace '[^a-zA-Z0-9_-]','_').ToUpperInvariant()
    if ($stem.Length -gt 48) {
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($ShareName)))).Replace('-','').Substring(0,8) }
        finally { $sha.Dispose() }
        $stem=$stem.Substring(0,39)+'_'+$hash
    }
    "DLSG_FS_${stem}_$Bucket"
}
function Get-ManagedGroup {
    param([string]$Name)
    $found=@(Get-ADGroup -LDAPFilter "(sAMAccountName=$(Escape-Ldap $Name))" -Properties Members,Description @ad)
    if ($found.Count -gt 1) { throw "Ambiguous group: $Name" }
    if ($found.Count) {
        $g=$found[0]
        if ([string]$g.GroupCategory -ne 'Security' -or [string]$g.GroupScope -ne 'DomainLocal' -or
            ($g.DistinguishedName -split '(?<!\\),',2)[1] -ine $ouDN) { throw "Existing $Name is not a DomainLocal security group in $ouDN." }
        $g
    }
}
function Record-Members {
    param($Group, [string]$Phase)
    $all=@(Get-ADGroupMember -Identity $Group.DistinguishedName @ad)
    if (-not $all.Count) {
        $script:memberships.Add([pscustomobject]@{Phase=$Phase; Group=$Group.SamAccountName; Member='(empty)'; Type=''; SID=''; DN=''})
    }
    foreach ($member in $all) {
        $script:memberships.Add([pscustomobject]@{Phase=$Phase; Group=$Group.SamAccountName; Member=$member.SamAccountName; Type=$member.ObjectClass; SID=[string]$member.SID; DN=$member.DistinguishedName})
    }
}
function Ensure-Smb {
    param($Share, [string]$SID, [string]$Right)
    $existing=@(Smb-Rows $Share.Name $Share.Scope)
    $ours=@($existing | Where-Object { $_.SID -eq $SID })
    if (@($ours | Where-Object {$_.Type -eq 'Deny'}).Count) { throw 'Managed group has an SMB deny; review manually.' }
    $rank=@{Read=1; Change=2; Full=3}
    if (@($ours | Where-Object { $_.Type -eq 'Allow' -and $rank[$_.Rights] -ge $rank[$Right] }).Count) {
        Log 'Unchanged' $Share.Name "SMB $SID already has $Right or greater; retained."; return
    }
    if ($ours.Count) { throw 'Existing managed-group SMB rights are lower than requested; retained for manual review.' }
    $account=$null
    for ($attempt=0; $attempt -lt 6; $attempt++) {
        try { $account=([Security.Principal.SecurityIdentifier]::new($SID)).Translate([Security.Principal.NTAccount]).Value; break }
        catch { if ($attempt -eq 5) { throw }; Start-Sleep -Seconds 5 }
    }
    Grant-SmbShareAccess -Name $Share.Name -ScopeName $Share.Scope -AccountName $account -AccessRight $Right -Force -ErrorAction Stop | Out-Null
    $verify=@(Smb-Rows $Share.Name $Share.Scope)
    if (-not @($verify | Where-Object { $_.SID -eq $SID -and $_.Type -eq 'Allow' -and $rank[$_.Rights] -ge $rank[$Right] }).Count) { throw 'SMB grant verification failed.' }
    foreach ($old in $existing) {
        if (-not @($verify | Where-Object { $_.Identity -eq $old.Identity -and $_.Type -eq $old.Type -and $_.Rights -eq $old.Rights }).Count) { throw 'SMB baseline permission changed unexpectedly.' }
    }
    Log 'Granted' $Share.Name "SMB $Right to $account; verified existing ACEs retained."
}
function Ensure-Ntfs {
    param([string]$Path, [string]$SID, [string]$Rights)
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    $old=@(Ntfs-Rows $acl); $oldOwner=$acl.Owner; $oldProtected=$acl.AreAccessRulesProtected
    $mask=[long][Security.AccessControl.FileSystemRights]$Rights
    $ours=@($old | Where-Object { $_.SID -eq $SID })
    if (@($ours | Where-Object {$_.Type -eq 'Deny'}).Count) { throw 'Managed group has an NTFS deny; review manually.' }
    $sufficient=@($ours | Where-Object {
        $_.Type -eq 'Allow' -and ($_.Mask -band $mask) -eq $mask -and $_.AppliesToRoot -and
        $_.Inheritance -eq 'ContainerInherit, ObjectInherit' -and $_.Propagation -eq 'None'
    })
    if ($sufficient.Count) { Log 'Unchanged' $Path "NTFS $SID already has inheritable $Rights or greater."; return }
    $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($SID),
        [Security.AccessControl.FileSystemRights]$Rights,
        [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    $check=Get-Acl -LiteralPath $Path -ErrorAction Stop; $rows=@(Ntfs-Rows $check)
    if ($check.Owner -ne $oldOwner -or $check.AreAccessRulesProtected -ne $oldProtected) { throw 'NTFS owner/inheritance changed unexpectedly.' }
    foreach ($ace in $old) {
        if (-not @($rows | Where-Object {
            $_.Identity -eq $ace.Identity -and $_.Type -eq $ace.Type -and $_.IsInherited -eq $ace.IsInherited -and
            $_.Inheritance -eq $ace.Inheritance -and $_.Propagation -eq $ace.Propagation -and ($_.Mask -band $ace.Mask) -eq $ace.Mask
        }).Count) { throw 'NTFS baseline permission failed preservation verification.' }
    }
    if (-not @($rows | Where-Object { $_.SID -eq $SID -and $_.Type -eq 'Allow' -and ($_.Mask -band $mask) -eq $mask -and $_.AppliesToRoot -and $_.Inheritance -eq 'ContainerInherit, ObjectInherit' -and $_.Propagation -eq 'None' }).Count) { throw 'NTFS grant verification failed.' }
    Log 'Granted' $Path "NTFS inheritable $Rights to $SID; existing permissions retained."
}
function Html { param($Value) [Net.WebUtility]::HtmlEncode([string]$Value) }
function Table {
    param([object[]]$Rows,[string[]]$Columns)
    if (-not $Rows.Count) { return '<p>None</p>' }
    ($Rows | Select-Object -Property $Columns | ConvertTo-Html -Fragment) -join "`n"
}
function Inventory-Html {
    param([object[]]$Items)
    foreach ($item in $Items) {
        '<details><summary>'+ (Html "$($item.Scope)/$($item.Name) - $($item.Path)") +'</summary>'
        Table @($item) @('Description','Special','Exclusion','RootReadable','State','EncryptData','FolderEnumerationMode','Owner','InheritanceBlocked')
        '<h4>SMB ACL</h4>'; Table @($item.SMB) @('Identity','SID','Rights','Type')
        '<h4>NTFS root ACL</h4>'; Table @($item.NTFS) @('Identity','SID','Rights','Type','IsInherited','Inheritance','Propagation')
        '<h4>Child explicit / unique ACLs and scan exceptions</h4>'
        foreach ($child in @($item.Exceptions)) {
            '<details><summary>'+(Html "$($child.Kind): $($child.Path)")+'</summary>'
            Table @($child) @('Protected','Owner','Error')
            Table @($child.ACL) @('Identity','SID','Rights','Type','IsInherited','Inheritance','Propagation')
            '</details>'
        }
        '</details>'
    }
}

try {
    Import-Module SmbShare -ErrorAction Stop
    Import-Module ActiveDirectory -ErrorAction Stop
    if (-not $DomainController) { $DomainController=(Get-ADDomainController -Discover -Writable -ErrorAction Stop).HostName | Select-Object -First 1 }
    $ad=@{Server=$DomainController; ErrorAction='Stop'}
    $domain=Get-ADDomain @ad; $domainSID=[string]$domain.DomainSID
    $ouDN="OU=Share Permissions,$($domain.DistinguishedName)"
    Log 'Started' $env:COMPUTERNAME "Mode=$mode; DC=$DomainController; OU=$ouDN"
    $before=@(Inventory 'Before')
    [IO.File]::WriteAllText("$basePath.before.json", (ConvertTo-Json -InputObject $before -Depth 16), [Text.Encoding]::UTF8)
    $names=@{}
    foreach ($share in $before) {
        if ($share.Exclusion -or -not $share.RootReadable) { continue }
        $label="$($share.Scope)/$($share.Name)"
        try {
            # An inheritable grant must not change an excluded share's root via
            # an alias or a parent path that is also shared.
            $rootPath=[IO.Path]::GetFullPath($share.Path).TrimEnd('\')
            foreach ($excluded in @($before | Where-Object {$_.Exclusion -and $_.Path})) {
                $excludedPath=[IO.Path]::GetFullPath($excluded.Path).TrimEnd('\')
                if ($excludedPath -ieq $rootPath -or $excludedPath.StartsWith($rootPath+'\',[StringComparison]::OrdinalIgnoreCase)) {
                    throw "Root grant could affect excluded share $($excluded.Name) at $excludedPath. Exclude this parent/alias share as well."
                }
            }
            $mapped=@(Map-Users $share)
            foreach ($bucket in @('RW','RO')) {
                $name=Group-Name $share.Name $bucket
                if ($names.ContainsKey($name)) { throw "Group name collision: $name ($label and $($names[$name])). Exclude one share or rename it." }
                $names[$name]=$label
                $group=Get-ManagedGroup $name
                $users=@($mapped | Where-Object {$_.Bucket -eq $bucket} | ForEach-Object {$_.User})
                if ($group) {
                    $marker="Share permissions: $env:COMPUTERNAME / $label / $bucket"
                    if ($group.Description -like 'Share permissions: *' -and $group.Description -ine $marker) {
                        throw "Group $name is marked for another server/share: $($group.Description)."
                    }
                    Record-Members $group 'Before'
                    $current=@(Get-ADGroupMember -Identity $group.DistinguishedName @ad)
                    if (@($current | Where-Object {$_.ObjectClass -ne 'user'}).Count) { throw "Existing $name has non-user members. Retained; review manually before granting it access." }
                    foreach ($member in $current) {
                        if ([string]$member.SID -notin @($users | ForEach-Object {[string]$_.SID})) { Log 'Warning' $name "Existing member retained outside current mapping: $($member.SamAccountName)" }
                    }
                }
                foreach ($user in $users) {
                    if (-not $user.Enabled) { Log 'Warning' $name "Named user $($user.SamAccountName) is disabled; mapping retained." }
                }
                $plans += [pscustomobject]@{Share=$share; Label=$label; Bucket=$bucket; Name=$name; Group=$group; Users=$users}
                Log 'Planned' $name "Share=$label; named users=$(@($users | ForEach-Object {$_.SamAccountName}) -join ', '); $(if($bucket -eq 'RW'){'SMB Change; NTFS Modify'}else{'SMB Read; NTFS ReadAndExecute'})"
            }
        } catch { Log 'Error' $label $_.Exception.Message }
    }
    if ($script:failed) { throw 'Preflight was incomplete. No AD/SMB/NTFS changes made; review report errors.' }
    $ou=@(Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$(Escape-Ldap $ouDN))" @ad)
    if (-not $ou.Count -and $plans.Count) { Log 'Planned' $ouDN 'Create protected OU at domain root.' }
    if ($mode -eq 'Apply' -and $plans.Count -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Create OU/groups, add mapped named users, and add SMB/NTFS grants for all planned shares')) {
        if (-not $ou.Count) {
            New-ADOrganizationalUnit -Name 'Share Permissions' -Path $domain.DistinguishedName -ProtectedFromAccidentalDeletion $true @ad | Out-Null
            Log 'Created' $ouDN 'Protected OU created.'
        }
        foreach ($plan in $plans) {
            try {
                $share=$plan.Share
                $live=Get-SmbShare -Name $share.Name -ScopeName $share.Scope -ErrorAction Stop
                if ($live.Special -or $live.Path -ine $share.Path) { throw 'Share changed after inventory.' }
                $group=Get-ManagedGroup $plan.Name
                if (-not $group) {
                    $group=New-ADGroup -Name $plan.Name -SamAccountName $plan.Name -GroupCategory Security -GroupScope DomainLocal -Path $ouDN -Description "Share permissions: $env:COMPUTERNAME / $($plan.Label) / $($plan.Bucket)" -PassThru @ad
                    Log 'Created' $plan.Name 'DomainLocal security group created.'
                }
                if (@(Get-ADGroupMember -Identity $group.DistinguishedName @ad | Where-Object {$_.ObjectClass -ne 'user'}).Count) {
                    throw 'Group contains a non-user member at apply time; no further changes to this group.'
                }
                foreach ($user in $plan.Users) {
                    $current=Get-ADGroup -Identity $group.DistinguishedName -Properties Members @ad
                    if ($user.DistinguishedName -notin @($current.Members)) {
                        Add-ADGroupMember -Identity $group.DistinguishedName -Members $user.DistinguishedName @ad
                        Log 'Added' $plan.Name "Named user $($user.SamAccountName) [$($user.SID)]"
                    } else { Log 'Unchanged' $plan.Name "Named user $($user.SamAccountName) already a member." }
                }
                $current=Get-ADGroup -Identity $group.DistinguishedName -Properties Members @ad
                if (@($plan.Users | Where-Object {$_.DistinguishedName -notin @($current.Members)}).Count) { throw 'Named-user membership verification failed.' }
                $smbRight='Read'; $ntfsRight='ReadAndExecute'
                if ($plan.Bucket -eq 'RW') { $smbRight='Change'; $ntfsRight='Modify' }
                Ensure-Smb $share ([string]$group.SID) $smbRight
                Ensure-Ntfs $share.Path ([string]$group.SID) $ntfsRight
                Log 'Verified' $plan.Name 'Membership, SMB and root NTFS grants verified.'
            } catch { Log 'Error' $plan.Name $_.Exception.Message }
        }
    } elseif ($mode -eq 'Preview') { Log 'Preview' 'Run' 'No AD, SMB or NTFS changes made. Run with -Apply to provision.' }
    else { Log 'Skipped' 'Run' 'No plans or changes declined.' }
} catch { Log 'Error' 'Run' $_.Exception.Message }
finally {
    if ($mode -eq 'Apply' -and $before.Count) {
        try { $after=@(Inventory 'After') } catch { Log 'Error' 'After inventory' $_.Exception.Message }
    }
    foreach ($plan in $plans) {
        try { $group=Get-ManagedGroup $plan.Name; if ($group) { Record-Members $group 'After' } }
        catch { Log 'Error' $plan.Name "Membership report: $($_.Exception.Message)" }
    }
    try {
        $status='Complete'; if ($script:failed) { $status='Incomplete / errors' }
        $planRows=@(foreach ($p in $plans) { [pscustomobject]@{Share=$p.Label; Group=$p.Name; Bucket=$p.Bucket; NamedUsers=(@($p.Users | ForEach-Object {$_.SamAccountName}) -join ', ')} })
        $report=[pscustomobject]@{Run=$runId; Server=$env:COMPUTERNAME; DomainController=$DomainController; OU=$ouDN; Mode=$mode; Status=$status
            Plan=$planRows; Before=$before; After=$after; Mappings=$script:mappings.ToArray(); Memberships=$script:memberships.ToArray(); Actions=$script:events.ToArray()}
        [IO.File]::WriteAllText("$basePath.json", (ConvertTo-Json -InputObject $report -Depth 18), [Text.Encoding]::UTF8)
        $html=@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Share access review</title>
<style>body{font:15px Segoe UI,Arial,sans-serif;margin:30px;background:#f4f7fa;color:#17324d}h1,h2{color:#174c78}table{border-collapse:collapse;width:100%;background:white;margin:12px 0;display:block;overflow-x:auto}th,td{border:1px solid #ccd9e6;padding:9px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#e4edf7}details{background:white;padding:14px;margin:10px 0;border:1px solid #ccd9e6}summary{cursor:pointer;font-weight:600}.note{background:#fff3d6;padding:16px}@media print{table{display:table}body{margin:8px}}</style></head><body>
<h1>SMB and NTFS share access review</h1><p>$(Html $env:COMPUTERNAME) | $(Html $mode) | $(Html $status) | $(Html $runId)</p>
<p>Domain controller: $(Html $DomainController) | OU: $(Html $ouDN) | Shares: $($before.Count)</p>
<div class="note">Mappings use named AD users on SMB or root NTFS allow entries. RW wins over RO. This is not an effective-access calculation: mapping a user from either permission layer into groups on both layers can increase their access. Group-based denies and membership effects are not evaluated. Child-only access never adds a user to root groups. Existing permissions and members are retained. Root grants inherit to unprotected descendants; protected child ACLs remain unchanged. Reparse points and recursive scans of special/excluded shares are skipped.</div>
<h2>Group plan and final named-user mapping</h2>$(Table $planRows @('Share','Group','Bucket','NamedUsers'))
<h2>ACL mapping evidence and skipped principals</h2>$(Table @($script:mappings.ToArray()) @('Share','Source','Identity','SID','Rights','Candidate','Reason'))
<h2>Group memberships</h2>$(Table @($script:memberships.ToArray()) @('Phase','Group','Member','Type','SID','DN'))
<h2>Actions, warnings, skipped objects and errors</h2>$(Table @($script:events.ToArray()) @('Time','Status','Target','Detail'))
<h2>Before</h2>$((Inventory-Html $before) -join "`n")
<h2>After</h2>$((Inventory-Html $after) -join "`n")
<p>After ACL snapshots are collected in Apply mode only. JSON files contain complete reported ACL data and NTFS security descriptors. The action journal is written throughout the run. Failed runs can contain partial changes; no automatic rollback is attempted.</p>
</body></html>
"@
        [IO.File]::WriteAllText("$basePath.html",$html,[Text.Encoding]::UTF8)
        Write-Host "HTML report: $basePath.html"
        Write-Host "JSON data:   $basePath.json"
    } catch { $script:failed=$true; Write-Warning "Report write failed: $($_.Exception.Message)" }
}
if ($script:failed) { exit 1 }
exit 0
