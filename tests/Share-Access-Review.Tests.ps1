#requires -Version 5.1
# Offline harness: all AD, SMB, inventory and ACL I/O is mocked. No live changes.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Microsoft.PowerShell.Core\Import-Module Microsoft.PowerShell.Security
$source=Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/file-shares/Share-Access-Review.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$testOutput=Join-Path ([IO.Path]::GetTempPath()) ('ShareAccessReviewTests-PS'+$PSVersionTable.PSVersion.Major+'-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($testOutput)
$global:testState=@{Groups=@{}; OU=$false; Writes=0; Smb=@{}; Acl=@{}; FailScan=$false; Collision=$false}
$domainSid='S-1-5-21-111-222-333'
$global:testUsers=@{}
foreach ($pair in @(@('alice',1001),@('bob',1002),@('childonly',1003),@('denied',1004),@('inheritonly',1005))) {
    $sid="$domainSid-$($pair[1])"
    $global:testUsers[$sid]=[pscustomobject]@{SamAccountName=$pair[0]; SID=$sid; DistinguishedName="CN=$($pair[0]),DC=test,DC=invalid"; Enabled=$true; ObjectClass='user'}
}
function New-TestAcl {
    param([string]$Sid,[string]$Rights,[string]$Propagation='None')
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($Sid),[Security.AccessControl.FileSystemRights]$Rights,[Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',[Security.AccessControl.PropagationFlags]$Propagation,[Security.AccessControl.AccessControlType]::Allow))
    return $acl
}
$global:testState.Acl['X:\Data']=New-TestAcl "$domainSid-1001" 'Modify'
$global:testState.Acl['X:\Data'].AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new("$domainSid-1005"),[Security.AccessControl.FileSystemRights]::Modify,[Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',[Security.AccessControl.PropagationFlags]::InheritOnly,[Security.AccessControl.AccessControlType]::Allow))
$global:testState.Acl['X:\Data\Private']=New-TestAcl "$domainSid-1003" 'FullControl'
$global:testState.Acl['X:\Excluded']=New-TestAcl "$domainSid-1001" 'Modify'
$global:testState.Smb['Data']=@(
    [pscustomobject]@{AccountName="$domainSid-1001"; AccessRight='Read'; AccessControlType='Allow'},
    [pscustomobject]@{AccountName="$domainSid-1002"; AccessRight='Read'; AccessControlType='Allow'},
    [pscustomobject]@{AccountName="$domainSid-1004"; AccessRight='Full'; AccessControlType='Allow'},
    [pscustomobject]@{AccountName="$domainSid-1004"; AccessRight='Read'; AccessControlType='Deny'},
    [pscustomobject]@{AccountName='S-1-1-0'; AccessRight='Full'; AccessControlType='Allow'},
    [pscustomobject]@{AccountName="$domainSid-513"; AccessRight='Read'; AccessControlType='Allow'}
)
function Import-Module { param($Name,$ErrorAction) }
function Get-ADDomain { param($Server,$ErrorAction) [pscustomobject]@{DistinguishedName='DC=test,DC=invalid';DomainSID='S-1-5-21-111-222-333'} }
function Get-ADUser {
    param($Filter,$Properties,$Server,$ErrorAction)
    # The function under test supplies a SID variable used by the filter.
    if ($global:testUsers.ContainsKey($SID)) { $global:testUsers[$SID] }
}
function Get-ADOrganizationalUnit { param($LDAPFilter,$Server,$ErrorAction) if ($global:testState.OU) { [pscustomobject]@{Name='Share Permissions'} } }
function New-ADOrganizationalUnit { param($Name,$Path,$ProtectedFromAccidentalDeletion,$Server,$ErrorAction) $global:testState.OU=$true; $global:testState.Writes++ }
function Get-ADGroup {
    param($LDAPFilter,$Identity,$Properties,$Server,$ErrorAction)
    if ($Identity) { $global:testState.Groups.Values | Where-Object {$_.DistinguishedName -eq $Identity} }
    elseif ($LDAPFilter -match '^\(sAMAccountName=(.+)\)$' -and $global:testState.Groups.ContainsKey($Matches[1])) { $global:testState.Groups[$Matches[1]] }
}
function New-ADGroup {
    param($Name,$SamAccountName,$GroupCategory,$GroupScope,$Path,$Description,[switch]$PassThru,$Server,$ErrorAction)
    $sid='S-1-5-32-545'; if ($Name.EndsWith('_RO')) { $sid='S-1-5-32-546' }
    $g=[pscustomobject]@{Name=$Name;SamAccountName=$Name;GroupCategory=$GroupCategory;GroupScope=$GroupScope;Description=$Description;DistinguishedName="CN=$Name,$Path";SID=$sid;Members=@()}
    $global:testState.Groups[$Name]=$g; $global:testState.Writes++; $g
}
function Add-ADGroupMember {
    param($Identity,$Members,$Server,$ErrorAction)
    $g=Get-ADGroup -Identity $Identity; $g.Members+=@($Members); $global:testState.Writes++
}
function Get-ADGroupMember {
    param($Identity,$Server,$ErrorAction)
    $g=Get-ADGroup -Identity $Identity
    foreach ($dn in $g.Members) { $global:testUsers.Values | Where-Object {$_.DistinguishedName -eq $dn} }
}
function Get-SmbShare {
    param($Name,$ScopeName,$ErrorAction)
    $all=@(
        [pscustomobject]@{Name='Data';ScopeName='*';Path='X:\Data';Description='<unsafe & text>';Special=$false;ShareState='Online';EncryptData=$false;FolderEnumerationMode='Unrestricted'},
        [pscustomobject]@{Name='ADMIN$';ScopeName='*';Path='X:\Excluded';Description='Admin';Special=$true;ShareState='Online';EncryptData=$false;FolderEnumerationMode='Unrestricted'},
        [pscustomobject]@{Name='SYSVOL';ScopeName='*';Path='X:\Excluded';Description='Excluded';Special=$false;ShareState='Online';EncryptData=$false;FolderEnumerationMode='Unrestricted'}
    )
    if ($global:testState.Collision) {
        $all+= [pscustomobject]@{Name='Data';ScopeName='ClusterScope';Path='X:\Data';Description='Collision';Special=$false;ShareState='Online';EncryptData=$false;FolderEnumerationMode='Unrestricted'}
    }
    if ($Name) { $all | Where-Object {$_.Name -eq $Name -and $_.ScopeName -eq $ScopeName} } else { $all }
}
function Get-SmbShareAccess { param($Name,$ScopeName,$ErrorAction) if ($global:testState.Smb.ContainsKey($Name)) { $global:testState.Smb[$Name] } }
function Grant-SmbShareAccess {
    param($Name,$ScopeName,$AccountName,$AccessRight,[switch]$Force,$ErrorAction)
    $global:testState.Smb[$Name]+=[pscustomobject]@{AccountName=$AccountName; AccessRight=$AccessRight; AccessControlType='Allow'}; $global:testState.Writes++
}
function Get-Item { param($LiteralPath,[switch]$Force,$ErrorAction) [pscustomobject]@{Attributes=[IO.FileAttributes]::Directory} }
function Get-ChildItem {
    param($LiteralPath,[switch]$Force,$ErrorAction)
    if ($global:testState.FailScan) { throw 'Simulated unreadable child directory' }
    if ($LiteralPath -eq 'X:\Data') { [pscustomobject]@{FullName='X:\Data\Private';Attributes=[IO.FileAttributes]::Directory;PSIsContainer=$true} }
}
function Get-Acl {
    param($LiteralPath,$ErrorAction)
    # Return a detached copy, like the real cmdlet.
    $copy=[Security.AccessControl.DirectorySecurity]::new()
    $copy.SetSecurityDescriptorSddlForm($global:testState.Acl[$LiteralPath].Sddl)
    $copy
}
function Set-Acl { param($LiteralPath,$AclObject,$ErrorAction) $global:testState.Acl[$LiteralPath]=$AclObject; $global:testState.Writes++ }
function Assert { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw "ASSERT: $Message" } }
function Read-Result {
    param([string]$Directory)
    $file=Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $Directory -Filter '*.json' | Where-Object {$_.Name -notlike '*.before.json'} | Sort-Object LastWriteTimeUtc | Select-Object -Last 1
    Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
}

# Exercise the actual startup code without running AD/SMB commands or exit.
$sourceText=[IO.File]::ReadAllText($source)
$startupEnd=$sourceText.IndexOf('$script:failed = $false')
Assert ($startupEnd -gt 0) 'startup marker exists'
$startup=[scriptblock]::Create($sourceText.Substring(0,$startupEnd)+"`n"+'$OutputDirectory')
Push-Location -LiteralPath $testOutput
try {
    $fallback=& { $PSScriptRoot=''; & $startup }
    Assert ($fallback -eq (Join-Path $testOutput 'ShareReports')) 'pasted/unsaved code uses current filesystem folder'
    $probeRoot=Join-Path $testOutput 'saved-script'
    $null=[IO.Directory]::CreateDirectory($probeRoot)
    $probePath=Join-Path $probeRoot 'Startup-Probe.ps1'
    [IO.File]::WriteAllText($probePath,$startup.ToString())
    $saved=& $probePath
    Assert ($saved -eq (Join-Path $probeRoot 'ShareReports')) 'saved script uses its own folder'
    $relative=& { $PSScriptRoot=''; & $startup -OutputDirectory '.\custom-reports' }
    Assert ($relative -eq (Join-Path $testOutput 'custom-reports')) 'explicit relative output uses PowerShell location'
    $explicit=& { $PSScriptRoot=''; & $startup -OutputDirectory $testOutput }
    Assert ($explicit -eq $testOutput) 'explicit absolute output is preserved'
} finally { Pop-Location }

& $source -DomainController 'mock-dc' -OutputDirectory "$testOutput\preview"
Assert ($LASTEXITCODE -eq 0) 'preview exit'
Assert ($global:testState.Writes -eq 0) 'preview performed no writes'
$r=Read-Result "$testOutput\preview"
Assert (@($r.Before).Count -eq 3) 'special and excluded shares inventoried'
Assert (@($r.Plan).Count -eq 2) 'two groups only for Data'
Assert (($r.Plan | Where-Object {$_.Bucket -eq 'RW'}).NamedUsers -eq 'alice') 'RW from NTFS beats SMB read'
Assert (($r.Plan | Where-Object {$_.Bucket -eq 'RO'}).NamedUsers -eq 'bob') 'RO named users only; no child, group, inherit-only or denied users'
Assert (@(($r.Before | Where-Object {$_.Name -eq 'Data'}).Exceptions).Count -eq 1) 'child exception reported'
$htmlFile=Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath "$testOutput\preview" -Filter '*.html' | Select-Object -Last 1
Assert ((Get-Content $htmlFile.FullName -Raw) -match '&lt;unsafe &amp; text&gt;') 'HTML escapes metadata'

& $source -DomainController 'mock-dc' -OutputDirectory "$testOutput\whatif" -Apply -WhatIf
Assert ($LASTEXITCODE -eq 0 -and $global:testState.Writes -eq 0) 'WhatIf performed no writes'
$excludedBefore=$global:testState.Acl['X:\Excluded'].Sddl
& $source -DomainController 'mock-dc' -OutputDirectory "$testOutput\apply" -Apply -Confirm:$false
Assert ($LASTEXITCODE -eq 0) 'apply exit'
Assert ($global:testState.OU -and $global:testState.Groups.Count -eq 2) 'OU and groups created'
Assert ($global:testState.Acl['X:\Excluded'].Sddl -eq $excludedBefore) 'excluded roots untouched'
$r=Read-Result "$testOutput\apply"
Assert (@($r.After).Count -eq 3) 'after inventory'
Assert (@($r.Memberships | Where-Object {$_.Phase -eq 'After'}).Count -eq 2) 'verified memberships reported'
$writes=$global:testState.Writes
& $source -DomainController 'mock-dc' -OutputDirectory "$testOutput\rerun" -Apply -Confirm:$false
Assert ($LASTEXITCODE -eq 0 -and $global:testState.Writes -eq $writes) 'rerun is idempotent'
$global:testState.FailScan=$true
& $source -DomainController 'mock-dc' -OutputDirectory "$testOutput\failure" -Apply -Confirm:$false
Assert ($LASTEXITCODE -eq 1 -and $global:testState.Writes -eq $writes) 'incomplete scan blocks writes and fails'
$global:testState.FailScan=$false; $global:testState.Collision=$true
& $source -DomainController 'mock-dc' -OutputDirectory "$testOutput\collision" -Apply -Confirm:$false
Assert ($LASTEXITCODE -eq 1 -and $global:testState.Writes -eq $writes) 'group collision blocks writes'
Write-Host "PASS: output-path fallback, offline preview, WhatIf, apply, rerun, failure, collision, ACL preservation, named-only mapping and HTML encoding on PowerShell $($PSVersionTable.PSVersion)."
