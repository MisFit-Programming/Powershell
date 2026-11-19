#Requires -Version 5.1
<#
.SYNOPSIS
  Verify and migrate a visible OneDrive tree using the Windows desktop sync clients.
.DESCRIPTION
  Audit is the default. Migrate requires -PilotFiles N or -FullMigration.
  Run under the sync account with both clients running and application writes frozen.
  Use -Mode Audit to inventory the visible files and review the local reports.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceRoot,
    [Parameter(Mandatory)][string]$DropboxRoot,
    [string]$DestinationRoot,
    [string]$DestinationFolderName = 'OneDrive-Migration',
    [ValidateSet('Audit','Migrate')][string]$Mode = 'Audit',
    [ValidateRange(0,100000000)][int]$PilotFiles = 0,
    [string[]]$PilotPath = @(),
    [switch]$FullMigration,
    [ValidateRange(1,65536)][int]$MinimumFreeGB = 10,
    [ValidateRange(1,4096)][int]$MaxPendingFiles = 32,
    [ValidateRange(1,1125899906842624)][long]$MaxPendingBytes = 16GB,
    [ValidateRange(1,2880)][int]$SyncTimeoutMinutes = 30,
    [ValidateRange(1,300)][int]$PollSeconds = 5,
    [string]$StateRoot = (Join-Path $env:LOCALAPPDATA 'OneDriveDropboxLocalMigration'),
    [ValidateRange(0,300)][int]$DropboxActionDelaySeconds = 15
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Mode -eq 'Migrate' -and (($PilotFiles -gt 0) -eq $FullMigration.IsPresent)) {
    throw 'Select either -PilotFiles N or -FullMigration for a migration.'
}
if ($Mode -eq 'Audit' -and ($PilotFiles -or $FullMigration)) { throw 'PilotFiles and FullMigration require -Mode Migrate.' }
if ($PilotPath.Count -and ($PilotPath.Count -ne $PilotFiles -or $Mode -ne 'Migrate')) { throw 'PilotPath must name exactly PilotFiles source-relative paths.' }
$options = @{}
foreach ($p in $MyInvocation.MyCommand.Parameters.Keys) {
    if (Get-Variable -Name $p -Scope 0 -ErrorAction SilentlyContinue) { $options[$p] = $ExecutionContext.SessionState.PSVariable.GetValue($p) }
}

# The foreground owns the dashboard. A blocking placeholder read or provider call
# on the worker cannot prevent the heartbeat from being rendered.
$worker = {
param($options, $view)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
foreach ($name in $options.Keys) { Set-Variable -Name $name -Value $options[$name] }
if (-not ('ODDB2.Native' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ODDB2 {
  public class Entry {
    public string Id;
    public uint Attributes, Tag, Links;
    public long Size, Ticks, Change;
  }
  public class Cloud {
    public bool Synced, Online;
    public long Resident, Root;
    public int Pin;
    public string Token;
  }
  public class Registration {
    public long Id;
    public string Name;
  }
  public static class Native {
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicInfo { public long Created, Accessed, Written, Changed; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TagInfo { public uint Attributes, Tag; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandle {
      public uint Attr, CreatedLo, CreatedHi, AccessLo, AccessHi, WriteLo, WriteHi,
        Volume, SizeHi, SizeLo, Links, IndexHi, IndexLo;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share,
      IntPtr sa, uint mode, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle h, out ByHandle i);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int c, out TagInfo i, int n);
    [DllImport("kernel32.dll", EntryPoint="GetFileInformationByHandleEx", SetLastError=true)]
    private static extern bool GetBasicInfo(SafeFileHandle h, int c, out BasicInfo i, int n);
    [DllImport("cldapi.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
    private static extern int CfGetSyncRootInfoByPath(string path, int c, [Out] byte[] b, int n, out int used);
    [DllImport("cldapi.dll", ExactSpelling=true)]
    private static extern int CfGetPlaceholderInfo(SafeFileHandle h, int c, [Out] byte[] b, int n, out int used);
    [DllImport("cldapi.dll", ExactSpelling=true)]
    private static extern int CfSetPinState(SafeFileHandle h, int pin, int flags, IntPtr overlapped);

    private static SafeFileHandle Open(string path, uint share) {
      // OPEN_REPARSE_POINT | BACKUP_SEMANTICS. Never request file data.
      var h = CreateFile(path, 0x80, share, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
      if (h.IsInvalid) {
        int err = Marshal.GetLastWin32Error(); h.Dispose();
        throw new Win32Exception(err, path + ": " + new Win32Exception(err).Message);
      }
      return h;
    }
    private static Entry Meta(SafeFileHandle h) {
      ByHandle i; TagInfo tag; BasicInfo basic;
      if (!GetFileInformationByHandle(h,out i) || !GetFileInformationByHandleEx(h,9,out tag,8) || !GetBasicInfo(h,0,out basic,40))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      return new Entry {
        Id=String.Format("{0:X8}-{1:X8}{2:X8}",i.Volume,i.IndexHi,i.IndexLo),
        Size=((long)i.SizeHi << 32) | i.SizeLo, Attributes=tag.Attributes, Tag=tag.Tag,
        Links=i.Links, Change=basic.Changed, Ticks=DateTime.FromFileTimeUtc(((long)i.WriteHi << 32) | i.WriteLo).Ticks
      };
    }
    public static Entry StreamMeta(SafeFileHandle h) { return Meta(h); }
    public static Entry Stat(string path) {
      try { using (var h = Open(path,7)) return Meta(h); }
      catch (Win32Exception e) { if (e.NativeErrorCode==2 || e.NativeErrorCode==3) return null; throw; }
    }
    public static Registration RegisterInfo(string path) {
      byte[] b = new byte[8192]; int n;
      Marshal.ThrowExceptionForHR(CfGetSyncRootInfoByPath(path,1,b,b.Length,out n));
      if(n < 540) throw new IOException("Incomplete sync root information");
      return new Registration {Id=BitConverter.ToInt64(b,0),
        Name=System.Text.Encoding.Unicode.GetString(b,28,512).TrimEnd('\0')};
    }
    private static Cloud ReadCloud(SafeFileHandle h, long root) {
      byte[] b = new byte[8192]; int n;
      Marshal.ThrowExceptionForHR(CfGetPlaceholderInfo(h,1,b,b.Length,out n));
      if(n<60 || BitConverter.ToInt64(b,48)!=root) throw new IOException("Unexpected sync root identity");
      var c = new Cloud {Root=root, Resident=BitConverter.ToInt64(b,0), Pin=BitConverter.ToInt32(b,32)};
      c.Synced = BitConverter.ToInt32(b,36)==1 && BitConverter.ToInt64(b,16)==0 && c.Pin!=3;
      int identityLength = BitConverter.ToInt32(b,56);
      if(identityLength < 0 || identityLength > n-60) throw new IOException("Invalid placeholder identity length");
      if(identityLength > 0) {
        using(var sha=System.Security.Cryptography.SHA256.Create())
          c.Token=BitConverter.ToString(sha.ComputeHash(b,60,identityLength)).Replace("-","");
      }
      c.Online = c.Synced && c.Pin==2 && c.Resident==0;
      return c;
    }
    public static Cloud Query(string path, long root) {
      using(var h=Open(path,7)) return ReadCloud(h,root);
    }
    public static Cloud QueryMatching(string path,long root,string id,long ticks,long size) {
      using(var h=Open(path,7)) {
        var m=Meta(h);
        if(m.Id!=id || m.Ticks!=ticks || m.Size!=size) throw new IOException("File changed before provider metadata read");
        return ReadCloud(h,root);
      }
    }
    public static SafeFileHandle GuardSync(string path, long root, string id, long ticks, long size) {
      // Keep writers and renames out while dispatching a file-specific request.
      var h=Open(path,1);
      try {
        var m=Meta(h);
        if(m.Id!=id || m.Ticks!=ticks || m.Size!=size || m.Links!=1) throw new IOException("File changed before unpin");
        var c=ReadCloud(h,root);
        if(!c.Synced) throw new IOException("Provider has not confirmed in-sync");
        return h;
      } catch { h.Dispose(); throw; }
    }
    public static void Unpin(string path, long root, string id, long ticks, long size) {
      using(var h=GuardSync(path,root,id,ticks,size)) {
        Marshal.ThrowExceptionForHR(CfSetPinState(h,2,0,IntPtr.Zero));
      }
    }
  }
}
'@ -ErrorAction Stop
}

function Normalize([string]$path) {
    if ($path -notmatch '^[a-z]:[\\/]' -or $path.Substring(2).Contains(':')) { throw "Expected an absolute local drive path: $path" }
    $p = [IO.Path]::GetFullPath($path).TrimEnd('\')
    if ($p.Length -le 2) { throw "Select a folder below the drive root: $path" }
    return $p
}
function InTree($child,$parent) { return ($child+'\').StartsWith($parent+'\',[StringComparison]::OrdinalIgnoreCase) }
function X($p) { return '\\?\'+$p }
function Stat($p) { return [ODDB2.Native]::Stat((X $p)) }
function Check-Entry($m,$p) {
    if ($null -eq $m) { return }
    # Allow only the IO_REPARSE_TAG_CLOUD family, never name-surrogate links.
    if (($m.Attributes -band 1024) -and (($m.Tag -band 4294905855L) -ne 2415919130L)) {
        throw "UNSUPPORTED reparse tag $($m.Tag) at $p"
    }
    if (($m.Attributes -band 16) -eq 0 -and $m.Links -ne 1) { throw "UNSUPPORTED hard-linked file: $p" }
}
function Safe-Path($p) {
    $cursor = $p
    while ($cursor.Length -gt 3) {
        Check-Entry (Stat $cursor) $cursor
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}
function Make-Directory($p) { Safe-Path $p; [void][IO.Directory]::CreateDirectory((X $p)) }
function Issue($kind,$rel,$message) {
    $problems.Add([pscustomobject]@{Kind=$kind;Path=$rel;Details=$message})
    if ($rel -and $kind -in @('FAILED','CONFLICT','UNSUPPORTED','CHANGED','MISSING','UNRESOLVED','LOW_DISK','LIMIT')) {
        $issues[$rel] = "$kind - $message"
        $view.Failed = $issues.Count
    }
}
function Inventory($root,$label) {
    $files = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $dirs = [Collections.Generic.Dictionary[string,long]]::new([StringComparer]::OrdinalIgnoreCase)
    $stack = [Collections.Generic.Stack[string]]::new()
    $rootMeta=Stat $root
    $stack.Push('')
    $view.Op = "Inventory $label"
    while ($stack.Count) {
        $relDir = $stack.Pop()
        $folder = if ($relDir) { "$root\$relDir" } else { $root }
        $view.Path = $folder
        try {
            Safe-Path $folder
            foreach ($item in [IO.DirectoryInfo]::new((X $folder)).EnumerateFileSystemInfos()) {
                $rel = if ($relDir) { "$relDir\$($item.Name)" } else { $item.Name }
                try {
                    if (([long]$item.Attributes -band 1024) -ne 0) { Check-Entry (Stat "$root\$rel") "$root\$rel" }
                    if (([long]$item.Attributes -band 16) -ne 0) {
                        $dirs.Add($rel,(Stat "$root\$rel").Ticks)
                        $stack.Push($rel)
                    } else {
                        $files.Add($rel,[pscustomobject]@{Rel=$rel;Bytes=$item.Length;Ticks=$item.LastWriteTimeUtc.Ticks})
                    }
                } catch { Issue "$($label)_ENTRY" $rel $_.Exception.Message }
            }
        } catch { Issue "$($label)_ENUMERATION" $relDir $_.Exception.Message }
    }
    return @{Files=$files;Dirs=$dirs;RootTicks=$rootMeta.Ticks}
}
function Provider($path,$expected) {
    $r = [ODDB2.Native]::RegisterInfo((X $path))
    if ($r.Name -notmatch [regex]::Escape($expected)) { throw "Expected $expected at $path. Registered provider: $($r.Name)" }
    return $r.Id
}
function Cloud($p,$rootId,$id=$null,$ticks=0L,$size=0L) {
    if ($id) { return [ODDB2.Native]::QueryMatching((X $p),$rootId,$id,$ticks,$size) }
    return [ODDB2.Native]::Query((X $p),$rootId)
}
function Unpin($p,$rootId,$id,$ticks,$bytes) { [ODDB2.Native]::Unpin((X $p),$rootId,$id,$ticks,$bytes) }
function Request-DropboxAction($path,$r) {
    if (!(InTree $path $dest)) { throw 'Path outside Dropbox destination' }
    if (!$shellCache.App) { $shellCache.App=New-Object -ComObject Shell.Application }
    $folder=$shellCache.App.Namespace([IO.Path]::GetDirectoryName($path))
    if (!$folder) { return $false }
    $entry=$folder.ParseName([IO.Path]::GetFileName($path))
    if (!$entry -or ![string]::Equals($entry.Path,$path,[StringComparison]::OrdinalIgnoreCase)) { return $false }
    $verbs=@($entry.Verbs())
    $actions=@($verbs | Where-Object { ([string]$_.Name).Replace('&','').Trim() -ceq 'Make online-only' })
    $vendor=@($verbs | Where-Object { ([string]$_.Name).Replace('&','').Trim() -ceq 'View on Dropbox.com' })
    if ($actions.Count -ne 1 -or $vendor.Count -ne 1) { return $false }
    $guard=[ODDB2.Native]::GuardSync((X $path),$dropboxId,$r.DestId,$r.DestTicks,$r.Bytes)
    try { [void]$actions[0].DoIt() } finally { $guard.Dispose() }
    return $true
}
function Check-Space([long]$bytes) {
    $reserve = [long]$MinimumFreeGB * 1GB
    $shared = $sourceDrive.Name -eq $destDrive.Name
    $destNeed = if ($shared) { 2L*$bytes } else { $bytes }
    if ($destDrive.AvailableFreeSpace -lt ($reserve+$destNeed) -or
        $sourceDrive.AvailableFreeSpace -lt ($reserve+$bytes)) { throw "LOW_DISK reserve $MinimumFreeGB GiB, file $bytes bytes" }
}
function Read-Journal($path,$v2) {
    Safe-Path $path
    if (-not [IO.File]::Exists($path)) { return }
    $fs = [IO.File]::OpenRead($path)
    try {
        if ($fs.Length -eq 0) { return }
        $fs.Position = $fs.Length-1
        $terminated = $fs.ReadByte() -eq 10
        $fs.Position = 0
        $reader = [IO.StreamReader]::new($fs,[Text.Encoding]::UTF8,$true)
        while ($null -ne ($line=$reader.ReadLine())) {
            if (-not $terminated -and $reader.EndOfStream) {
                # A new segment is opened for every run, so a torn tail is never appended to.
                Issue 'JOURNAL_TAIL' '' "Interrupted final record ignored in $path"
                break
            }
            if (-not $line.Trim()) { continue }
            $r = ConvertFrom-Json -InputObject $line -ErrorAction Stop
            if (-not $r.Path) { throw "Invalid journal row in $path" }
            if ($v2) {
                if ($r.Version -ne 2 -or $r.Status -notin @('Admitted','LocalVerified','DropboxSynced','OnlineOnlyRequested','Confirmed') -or
                    ($r.Status -ne 'Admitted' -and ($r.SHA256 -notmatch '^[A-Fa-f0-9]{64}$' -or !$r.SourceId -or !$r.DestId))) {
                    throw "Invalid v2 checkpoint in $path"
                }
                $records[$r.Path] = $r
            } else { $legacy[$r.Path] = $r }
            $view.Last="Restored $($r.Status) $($r.Path)"
        }
    } finally { if ($null -ne (Get-Variable reader -ValueOnly -ErrorAction SilentlyContinue)) { $reader.Dispose() }; $fs.Dispose() }
}
function Save($r,$status) {
    $r.Status = $status
    $r.When = [datetime]::UtcNow.ToString('o')
    try {
        $journal.WriteLine(($r | ConvertTo-Json -Compress))
        $journal.Flush()
        $journal.BaseStream.Flush($true)
    } catch { throw "JOURNAL persistence failed: $($_.Exception.Message)" }
    $records[$r.Path] = $r
    $view.Last = "$status $($r.Path)"
}
function Valid-Proof($r,$s,$d) {
    if ($r -and $r.Status -eq 'Confirmed' -and (!$s -or !$d -or !$r.PSObject.Properties['SourceChange'] -or
        $r.SourceChange -ne $s.Change -or $r.DestChange -ne $d.Change)) { return $false }
    return ($null -ne $r -and $r.Status -ne 'Admitted' -and $null -ne $s -and $null -ne $d -and
        $r.Bytes -eq $s.Size -and $r.Bytes -eq $d.Size -and $r.SourceTicks -eq $s.Ticks -and
        $r.DestTicks -eq $d.Ticks -and $r.SourceId -eq $s.Id -and $r.DestId -eq $d.Id)
}
function Check-Streams($path,[bool]$existingDropbox=$false) {
    # Inspect NTFS stream names only. Never discard an alternate data stream silently.
    $streams = @(Get-Item -LiteralPath (X $path) -Force -Stream * -ErrorAction Stop)
    if (!$streams.Count) { throw "UNSUPPORTED cannot enumerate streams at $path" }
    foreach ($stream in $streams) {
        if ($existingDropbox -and $stream.Stream -eq 'com.dropbox.attrs') { continue }
        if ($stream.Stream -ne ':$DATA') { throw "UNSUPPORTED named stream $($stream.Stream) at $path" }
    }
}
function Digest($stream,$out,$operation,$length) {
    $view.Op=$operation; $view.Position=0L; $view.Length=$length
    $sha=[Security.Cryptography.SHA256]::Create()
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $checkAt=0L
    try {
        while (($n=$stream.Read($buffer,0,$buffer.Length)) -gt 0) {
            if ($clock.ElapsedMilliseconds -ge $checkAt) { Check-Space 0; $checkAt=$clock.ElapsedMilliseconds+500 }
            if ($out) { $out.Write($buffer,0,$n) }
            [void]$sha.TransformBlock($buffer,0,$n,$buffer,0)
            $view.Position += $n
        }
        if ($view.Position -ne $length) { throw 'CHANGED byte count during read' }
        [void]$sha.TransformFinalBlock([byte[]]@(),0,0)
        if ($out) { $out.Flush($true) }
        return [BitConverter]::ToString($sha.Hash).Replace('-','')
    } finally { $sha.Dispose() }
}
function Open-Read($path) {
    return [IO.FileStream]::new((X $path),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read,1048576,[IO.FileOptions]::SequentialScan)
}
function Stage-Path($r) {
    if ([string]$r.Stage -notmatch '^[0-9a-f]{32}$') { throw 'Invalid private staging name in journal' }
    return "$job\staging-v2\$($r.Stage).part"
}
function Clean-Stage($r) {
    $stage=Stage-Path $r
    Safe-Path $stage
    if ([IO.File]::Exists((X $stage))) { [IO.File]::Delete((X $stage)) }
}
function New-Record($f,$s) {
    return [pscustomobject]@{Version=2;Path=$f.Rel;Bytes=[long]$f.Bytes;SourceTicks=[long]$f.Ticks;
        DestTicks=0L;SourceChange=0L;DestChange=0L;SourceId=$s.Id;DestId='';SHA256='';Status='';When='';
        Stage=[guid]::NewGuid().ToString('N')}
}
function Verify-Content($f,$s,$d,$r) {
    $src="$SourceRoot\$($f.Rel)"; $dst="$dest\$($f.Rel)"
    $stage=Stage-Path $r
    $inputFile=$null; $compare=$null; $outputFile=$null
    try {
        $view.Op='Open source (possible hydration)'
        $inputFile=Open-Read $src
        if (!$d) {
            $outputFile=[IO.FileStream]::new((X $stage),'CreateNew','Write','None',1048576)
            $hash=Digest $inputFile $outputFile 'Local copy and SHA-256' $f.Bytes
            $outputFile.Dispose(); $outputFile=$null
            $compare=Open-Read $stage
            $other=Digest $compare $null 'Verify staged SHA-256' $f.Bytes
        } else {
            $hash=Digest $inputFile $null 'Hash existing source' $f.Bytes
            $view.Op='Open existing destination (possible hydration)'
            $compare=Open-Read $dst
            $other=Digest $compare $null 'Hash existing destination' $f.Bytes
            # The locked handle identifies the bytes actually read, including a
            # provider-created entry that appeared during initial hydration.
            $d=[ODDB2.Native]::StreamMeta($compare.SafeFileHandle)
            if ($d.Links -ne 1 -or $d.Ticks -ne $f.Ticks) { throw 'CHANGED existing file at verification' }
        }
        if ($hash -ne $other) { throw 'CONFLICT SHA-256 differs' }
        $old=$legacy[$f.Rel]
        if ($old -and $old.Bytes -eq $f.Bytes -and $old.SourceTicks -eq $f.Ticks -and
            $old.SHA256 -match '^[A-Fa-f0-9]{64}$' -and $old.SHA256 -ne $hash) { throw 'CHANGED content differs from legacy SHA-256 at identical source metadata' }
        $post=Stat $src
        if (!$post -or $post.Id -ne $s.Id -or $post.Ticks -ne $f.Ticks -or $post.Size -ne $f.Bytes) { throw 'CHANGED source during verification' }
        if (!$d) {
            $compare.Dispose(); $compare=$null
            [IO.File]::SetLastWriteTimeUtc((X $stage),[datetime]::new($f.Ticks,[DateTimeKind]::Utc))
            $displayAttributes=$s.Attributes -band 6 # Hidden and System; provider flags belong to each sync root.
            if ($displayAttributes) { [IO.File]::SetAttributes((X $stage),[IO.FileAttributes]($displayAttributes -bor 32)) }
            $staged=Stat $stage
            Safe-Path $dst
            [IO.File]::Move((X $stage),(X $dst)) # Same-volume rename, never replaces.
            $d=$staged
        }
        $post=Stat $dst
        if (!$post -or $post.Id -ne $d.Id -or $post.Size -ne $f.Bytes -or $post.Ticks -ne $f.Ticks) { throw 'CHANGED destination identity, size or timestamp' }
        $r.DestTicks=$post.Ticks; $r.DestId=$post.Id; $r.SHA256=$hash
        Save $r 'LocalVerified'
    } finally {
        if ($outputFile) { $outputFile.Dispose() }
        if ($compare) { $compare.Dispose() }
        if ($inputFile) { $inputFile.Dispose() }
        Clean-Stage $r
    }
}

function Update-QueueDisplay {
    $view.Pending=$pending.Count
    $view.PendingBytes=$queueStats.Bytes
    $view.PeakFiles=[math]::Max($view.PeakFiles,$pending.Count)
    $view.PeakBytes=[math]::Max([long]$view.PeakBytes,[long]$queueStats.Bytes)
    $sync=0
    foreach ($item in $pending) { if ($item.Record.Status -eq 'LocalVerified') { $sync++ } }
    $view.AwaitingSync=$sync
}
function Add-Pending($r) {
    $pending.Add([pscustomobject]@{Record=$r;Deadline=[datetime]::UtcNow.AddMinutes($SyncTimeoutMinutes);Reason='Awaiting provider metadata';
        SourceRequested=$false;DropboxRequested=$false;ShellAfter=[datetime]::MaxValue;ShellTried=$false;ShellNote='';BeforeToken=''})
    $queueStats.Bytes += $r.Bytes
    Update-QueueDisplay
}
function Advance($item) {
    $r=$item.Record; $src="$SourceRoot\$($r.Path)"; $dst="$dest\$($r.Path)"
    $view.Path=$r.Path; $view.Position=0L; $view.Length=0L
    $view.Op='Check verified identities'
    Safe-Path $src; Safe-Path $dst
    $sm=Stat $src; $dm=Stat $dst
    if (!(Valid-Proof $r $sm $dm)) {
        # Dropbox may atomically replace the local entry when its Explorer action
        # completes. Only accept an observed transition within this live request.
        if (!$item.BeforeToken -or !$sm -or $sm.Id -ne $r.SourceId -or $sm.Size -ne $r.Bytes -or
            $sm.Ticks -ne $r.SourceTicks -or ($dm -and $dm.Id -eq $r.DestId)) {
            throw 'CHANGED since SHA-256 checkpoint'
        }
        if (!$dm) { $item.Reason='Waiting for Dropbox placeholder replacement'; return $false }
        if ($dm.Size -ne $r.Bytes -or $dm.Ticks -ne $r.DestTicks) { throw 'CHANGED Dropbox replacement size or timestamp' }
        $replacement=Cloud $dst $dropboxId $dm.Id $dm.Ticks $dm.Size
        if ($replacement.Token -cne $item.BeforeToken -or !$replacement.Token) { throw 'CHANGED Dropbox provider identity across online-only request' }
        if (!$replacement.Online) { $item.Reason='Waiting for replacement placeholder sync and dehydration'; return $false }
        $r | Add-Member NoteProperty PreviousDestId $r.DestId -Force
        $r | Add-Member NoteProperty DropboxIdentitySHA256 $replacement.Token -Force
        $r.DestId=$dm.Id
        Save $r 'OnlineOnlyRequested'
    }
    $view.Op='Read Dropbox sync state'
    $dc=Cloud $dst $dropboxId $r.DestId $r.DestTicks $r.Bytes
    if ($dc.Token) {
        if ($tokenOwner.ContainsKey($dc.Token) -and $tokenOwner[$dc.Token] -cne $r.Path) {
            throw 'CHANGED Dropbox provider identity shared by multiple paths'
        }
        $tokenOwner[$dc.Token]=$r.Path
    }
    if (!$dc.Synced) { $item.Reason='Dropbox has not confirmed in-sync'; return $false }
    if ($r.Status -eq 'LocalVerified') { Save $r 'DropboxSynced' }
    $view.Op='Read OneDrive sync state'
    $sc=Cloud $src $oneDriveId
    if (!$sc.Synced) { $item.Reason='OneDrive has not confirmed in-sync'; return $false }
    if ($dc.Online -and $sc.Online) {
        $sm=Stat $src; $dm=Stat $dst
        if (!(Valid-Proof $r $sm $dm)) { throw 'CHANGED during provider confirmation' }
        $r.SourceChange=$sm.Change; $r.DestChange=$dm.Change
        Save $r 'Confirmed'
        $view.Done++; $view.DoneBytes+=$r.Bytes
        return $true
    }
    if ($sc.Pin -ne 2 -and !$item.SourceRequested) {
        $view.Op='Request OneDrive online-only'
        Unpin $src $oneDriveId $r.SourceId $r.SourceTicks $r.Bytes
        $item.SourceRequested=$true
    }
    if (!$dc.Online -and !$item.DropboxRequested) {
        $view.Op='Request Dropbox online-only'
        if ($dc.Pin -ne 2) {
            Unpin $dst $dropboxId $r.DestId $r.DestTicks $r.Bytes
            $item.BeforeToken=$dc.Token
        }
        $item.DropboxRequested=$true
        $item.ShellAfter=[datetime]::UtcNow.AddSeconds($DropboxActionDelaySeconds)
    } elseif (!$dc.Online -and !$item.ShellTried -and [datetime]::UtcNow -ge $item.ShellAfter) {
        $view.Op='Request Dropbox Make online-only'
        $item.ShellTried=$true
        try {
            if (Request-DropboxAction $dst $r) {
                $item.BeforeToken=$dc.Token
                $item.ShellNote='Dropbox Explorer action dispatched'
                $r | Add-Member NoteProperty DropboxRequest $item.ShellNote -Force
                Save $r 'OnlineOnlyRequested'
            } else { $item.ShellNote='Dropbox Explorer action unavailable' }
        } catch {
            if ($_.Exception.Message -match '^JOURNAL') { throw }
            $item.ShellNote=$_.Exception.GetBaseException().Message
        }
    }
    if ($r.Status -ne 'OnlineOnlyRequested') { Save $r 'OnlineOnlyRequested' }
    $item.Reason="OneDrive resident $($sc.Resident) B pin $($sc.Pin), Dropbox resident $($dc.Resident) B pin $($dc.Pin) $($item.ShellNote)"
    return $false
}
function Poll-Queue {
    foreach ($item in $pending.ToArray()) {
        try {
            if (Advance $item) {
                [void]$pending.Remove($item)
                $queueStats.Bytes -= $item.Record.Bytes
                continue
            }
        } catch {
            if ($_.Exception.Message -match '^(CHANGED|JOURNAL|UNSUPPORTED)') { throw }
            $item.Reason="$($view.Op): $($_.Exception.GetBaseException().Message)"
        }
        if ([datetime]::UtcNow -ge $item.Deadline) {
            throw "UNRESOLVED $($item.Record.Path) - $($item.Reason)"
        }
    }
    Update-QueueDisplay
    $queueStats.Next=[datetime]::UtcNow.AddSeconds($PollSeconds)
}
function Wait-Queue([long]$nextBytes,[bool]$drain) {
    while ($pending.Count -and ($drain -or $pending.Count -ge $MaxPendingFiles -or
        $queueStats.Bytes+$nextBytes -gt $MaxPendingBytes)) {
        if ([datetime]::UtcNow -ge $queueStats.Next) { Poll-Queue; continue }
        $first=$pending[0]
        $view.Path=$first.Record.Path
        $view.Op="Waiting - $($first.Reason)"
        Start-Sleep -Milliseconds 250
    }
}
function Csv($rows,$path,$header) {
    if ($rows.Count) { $rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 }
    else { [IO.File]::WriteAllText($path,$header+[Environment]::NewLine,[Text.Encoding]::UTF8) }
}
function Audit-Visible($initial,$tree,$dt) {
    $rows=[Collections.Generic.List[object]]::new()
    $confirmed=0; $verified=0; $pilotConfirmed=0
    $view.Op='Audit visible inventory and current provider state'
    foreach ($f in $tree.Files.Values) {
        $rel=$f.Rel; $view.Path=$rel
        $status='MISSING_DESTINATION'; $details=''; $sha=''; $sr=$null; $dr=$null
        $r=$records[$rel]
        if ($dt.Files.ContainsKey($rel)) {
            $df=$dt.Files[$rel]
            $status=if ($df.Bytes -ne $f.Bytes) { 'SIZE_MISMATCH' }
                elseif ($df.Ticks -ne $f.Ticks) { 'TIMESTAMP_MISMATCH' } else { 'PRESENT_METADATA_ONLY' }
            if ($r -and $r.Status -ne 'Admitted') {
                try {
                    $sp="$SourceRoot\$rel"; $dp="$dest\$rel"
                    Safe-Path $sp; Safe-Path $dp
                    if (Valid-Proof $r (Stat $sp) (Stat $dp)) {
                        $verified++; if ($Mode -eq 'Audit') { $view.VerifiedBytes+=$f.Bytes }; $sha=$r.SHA256; $status='VERIFIED_PROVIDER_UNRESOLVED'
                        $sc=Cloud $sp $oneDriveId; $sr=$sc.Resident
                        $dc=Cloud $dp $dropboxId; $dr=$dc.Resident
                        if ($sc.Online -and $dc.Online) { $status='CONFIRMED'; $confirmed++ }
                        else { $details="OneDrive sync=$($sc.Synced) pin=$($sc.Pin), Dropbox sync=$($dc.Synced) pin=$($dc.Pin)" }
                    } else { $status='CHANGED_SINCE_VERIFICATION' }
                } catch { $details=$_.Exception.GetBaseException().Message }
            } elseif ($legacy.ContainsKey($rel)) {
                $old=$legacy[$rel]
                if ($status -eq 'PRESENT_METADATA_ONLY' -and $old.Bytes -eq $f.Bytes -and
                    $old.SourceTicks -eq $f.Ticks -and $old.SHA256 -match '^[A-Fa-f0-9]{64}$') { $status='LEGACY_SHA256_RECHECK' }
                $details="Legacy $($old.Status) checkpoint requires identity-bound verification"
            }
        }
        if ($initial -and (!$initial.Files.ContainsKey($rel) -or $initial.Files[$rel].Ticks -ne $f.Ticks -or $initial.Files[$rel].Bytes -ne $f.Bytes)) {
            Issue 'CHANGED' $rel 'New or changed after initial inventory'
        }
        if ($issues.ContainsKey($rel)) { $details=($issues[$rel]+' '+$details).Trim(); $status=($issues[$rel] -split ' - ',2)[0] }
        if ($status -eq 'CONFIRMED' -and $pilotTargets.Contains($rel)) { $pilotConfirmed++ }
        if ($Mode -eq 'Audit') {
            $view.Verified=$verified; $view.Done=$confirmed
            if ($status -eq 'CONFIRMED') { $view.DoneBytes+=$f.Bytes }
        }
        $rows.Add([pscustomobject]@{Path=$rel;SourceBytes=$f.Bytes;Status=$status;SHA256=$sha;SourceResidentBytes=$sr;DropboxResidentBytes=$dr;Details=$details})
    }
    foreach ($f in $dt.Files.Keys) { if (!$tree.Files.ContainsKey($f)) { Issue 'EXTRA_IN_DROPBOX' $f 'Destination-only file retained' } }
    foreach ($dir in $tree.Dirs.Keys) {
        if (!$dt.Dirs.ContainsKey($dir)) { Issue 'MISSING_DIRECTORY' $dir 'Folder absent in destination' }
        elseif ($tree.Dirs[$dir] -ne $dt.Dirs[$dir]) { Issue 'DIRECTORY_TIMESTAMP' $dir 'Folder modification time differs' }
    }
    if ($dt.RootTicks -and $tree.RootTicks -ne $dt.RootTicks) { Issue 'DIRECTORY_TIMESTAMP' '.' 'Destination root modification time differs' }
    $priorProblems="$job\problems.csv"
    if ([IO.File]::Exists($priorProblems)) {
        Safe-Path $priorProblems
        Import-Csv -LiteralPath $priorProblems -Encoding UTF8 | Where-Object Kind -eq 'EXTRA_IN_DROPBOX' | ForEach-Object {
            if (!$tree.Files.ContainsKey($_.Path) -and !$dt.Files.ContainsKey($_.Path)) {
                Issue 'HISTORICAL_EXTRA_MISSING' $_.Path 'Previously visible only in Dropbox, now absent from both visible inventories. Reconcile externally.'
            }
        }
    }
    foreach ($dir in $dt.Dirs.Keys) { if (!$tree.Dirs.ContainsKey($dir)) { Issue 'EXTRA_DIRECTORY' $dir 'Destination-only directory retained' } }
    $seenMissing=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($index in @($records,$legacy)) {
        foreach ($rel in $index.Keys) { if (!$tree.Files.ContainsKey($rel) -and $seenMissing.Add($rel)) { Issue 'SOURCE_MISSING' $rel 'Journaled file absent from visible source' } }
    }
    if ($initial) {
        foreach ($rel in $initial.Files.Keys) { if (!$tree.Files.ContainsKey($rel) -and $seenMissing.Add($rel)) { Issue 'SOURCE_MISSING' $rel 'Disappeared during migration' } }
        foreach ($rel in $initial.Dirs.Keys) { if (!$tree.Dirs.ContainsKey($rel)) { Issue 'SOURCE_DIRECTORY_MISSING' $rel 'Disappeared during migration' } }
    }
    foreach ($prior in @("$job\file-audit.csv","$job\inventory-baseline.csv")) {
        if ([IO.File]::Exists($prior)) {
            Safe-Path $prior
            Import-Csv -LiteralPath $prior -Encoding UTF8 | ForEach-Object {
                if ($_.PSObject.Properties['Kind'] -and $_.Kind -eq 'Folder') {
                    if (!$tree.Dirs.ContainsKey($_.Path)) { Issue 'SOURCE_DIRECTORY_MISSING' $_.Path 'In baseline but absent from source' }
                } elseif (!$tree.Files.ContainsKey($_.Path) -and $seenMissing.Add($_.Path)) { Issue 'SOURCE_MISSING' $_.Path 'In previous inventory but absent from visible source' }
            }
        }
    }
    Csv $rows "$report\file-audit.csv" '"Path","SourceBytes","Status","SHA256","SourceResidentBytes","DropboxResidentBytes","Details"'
    Csv $problems "$report\problems.csv" '"Kind","Path","Details"'
    $blocking=@($problems | Where-Object Kind -ne 'JOURNAL_TAIL').Count
    $ok=($tree.Files.Count -gt 0 -and $confirmed -eq $tree.Files.Count -and !$blocking -and !$PilotFiles)
    $summary=[ordered]@{Mode=$Mode;PilotLimit=$PilotFiles;Attempted=$view.Attempted;SourceFiles=$tree.Files.Count;
        SourceFolders=$tree.Dirs.Count;Verified=$verified;Confirmed=$confirmed;Problems=$problems.Count;BlockingProblems=$blocking;
        PilotConfirmed=$pilotConfirmed;PilotPassed=($PilotFiles -gt 0 -and $pilotConfirmed -eq $PilotFiles -and !$issues.Count -and $ready -and !$stopReason);StopReason=$stopReason;
        PeakPendingFiles=$view.PeakFiles;PeakPendingBytes=$view.PeakBytes;LocalAuditPassed=$ok;FinishedUtc=[datetime]::UtcNow.ToString('o')}
    [IO.File]::WriteAllText("$report\summary.json",($summary|ConvertTo-Json),[Text.Encoding]::UTF8)
    return [pscustomobject]@{Code=$(if ($ok) {0} else {2});Text="Visible files $($tree.Files.Count), verified $verified, confirmed $confirmed, issues $($problems.Count). Reports: $report"}
}

$SourceRoot=Normalize $SourceRoot; $DropboxRoot=Normalize $DropboxRoot; $StateRoot=Normalize $StateRoot
if (!$DestinationRoot -and (!$DestinationFolderName -or $DestinationFolderName -ne [IO.Path]::GetFileName($DestinationFolderName) -or
    $DestinationFolderName.TrimEnd(' ','.') -ne $DestinationFolderName)) { throw 'Invalid destination folder name' }
$dest=if ($DestinationRoot) { Normalize $DestinationRoot } else { Normalize "$DropboxRoot\$DestinationFolderName" }
if (!(InTree $dest $DropboxRoot) -or $dest -eq $DropboxRoot -or (InTree $SourceRoot $DropboxRoot) -or (InTree $DropboxRoot $SourceRoot)) { throw 'Unsafe sync root overlap or destination' }
foreach ($root in @($SourceRoot,$DropboxRoot)) {
    if ((InTree $StateRoot $root) -or (InTree $root $StateRoot)) { throw 'State and sync trees overlap' }
    Safe-Path $root
    if (![IO.Directory]::Exists((X $root))) { throw "Missing sync folder $root" }
}
Safe-Path $dest; Safe-Path $StateRoot
$sourceDrive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($SourceRoot))
$destDrive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($dest))
if ($destDrive.Name -ne [IO.Path]::GetPathRoot($StateRoot) -or $destDrive.DriveFormat -ne 'NTFS' -or $sourceDrive.DriveFormat -ne 'NTFS') { throw 'Use local NTFS. Staging and Dropbox must share the same drive.' }
$h=[Security.Cryptography.SHA256]::Create()
try { $key=[BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes(($SourceRoot+'|'+$dest).ToLowerInvariant()))).Replace('-','').Substring(0,16) }
finally { $h.Dispose() }
$job="$StateRoot\$key"
Make-Directory $job
Safe-Path "$job\migration.lock"
$lock=[IO.File]::Open("$job\migration.lock",'OpenOrCreate','ReadWrite','None')
$journal=$null
try {
    $report="$job\reports\$([datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))-$([guid]::NewGuid().ToString('N'))"
    Make-Directory $report
    $view.Report=$report
    $problems=[Collections.Generic.List[object]]::new()
    $issues=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pilotTargets=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $stopReason=''; $shellCache=@{App=$null}
    $records=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $legacy=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $oneDriveId=0L; $dropboxId=0L; $ready=$true
    try { $oneDriveId=Provider $SourceRoot 'OneDrive'; $dropboxId=Provider $DropboxRoot 'Dropbox' }
    catch { $ready=$false; Issue 'PROVIDER_REGISTRATION' '' $_.Exception.GetBaseException().Message }
    if ([IO.Directory]::Exists("$job\staging")) {
        Safe-Path "$job\staging"
        foreach ($part in @(Get-ChildItem -LiteralPath "$job\staging" -Filter '*.part' -Force -File)) {
            Issue 'LEGACY_STAGE' '' "Inspect retained legacy staging file $($part.FullName)"
        }
    }
    Read-Journal "$job\checkpoints.jsonl" $false
    $segments=@(Get-ChildItem -LiteralPath $job -Force -File -Filter 'checkpoints-v2-*.jsonl' | Sort-Object Name)
    foreach ($seg in $segments) {
        if ($seg.Name -notmatch '^checkpoints-v2-[0-9]{8}\.jsonl$') { throw "Unexpected journal name $($seg.Name)" }
        Read-Journal $seg.FullName $true
    }
    $tree=Inventory $SourceRoot 'SOURCE'
    $total=0L; foreach ($f in $tree.Files.Values) { $total+=$f.Bytes }
    $view.Total=$tree.Files.Count; $view.Bytes=$total
    $initial=$null
    if ($Mode -eq 'Migrate' -and $ready -and $tree.Files.Count) {
        $initial=$tree
        $num=if ($segments.Count) { 1+[int]($segments[-1].BaseName.Substring(15)) } else { 1 }
        $jpath=Join-Path $job ('checkpoints-v2-{0:D8}.jsonl' -f $num)
        $journal=[IO.StreamWriter]::new([IO.File]::Open($jpath,'CreateNew','Write','Read'),[Text.UTF8Encoding]::new($false))
        $pending=[Collections.Generic.List[object]]::new()
        $queueStats=@{Bytes=0L;Next=[datetime]::MinValue}
        $tokenOwner=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
        $buffer=[byte[]]::new(4MB)
        $resuming=$false; $rel=''; $r=$null
        try {
            Check-Space 0
            if ($problems | Where-Object Kind -like 'SOURCE_ENUMERATION') { throw 'FAILED source inventory is incomplete' }
            if (![IO.File]::Exists("$job\inventory-baseline.csv")) {
                $tmp="$report\baseline.tmp"
                & {
                    foreach ($f in $tree.Files.Values) { [pscustomobject]@{Kind='File';Path=$f.Rel} }
                    foreach ($dir in $tree.Dirs.Keys) { [pscustomobject]@{Kind='Folder';Path=$dir} }
                } | Export-Csv -LiteralPath $tmp -NoTypeInformation -Encoding UTF8
                [IO.File]::Move($tmp,"$job\inventory-baseline.csv")
            }
            Make-Directory "$job\staging-v2"
            $open=@($records.Values | Where-Object Status -ne 'Confirmed' | Sort-Object Path)
            $oldPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($row in $open) {
                [void]$oldPaths.Add($row.Path)
                if (!$tree.Files.ContainsKey($row.Path)) { throw "MISSING previously admitted source $($row.Path)" }
            }
            if ($PilotPath.Count) {
                $selected=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($p in $PilotPath) {
                    if (!$tree.Files.ContainsKey($p) -or !$selected.Add($p)) { throw "Invalid or duplicate PilotPath $p" }
                }
                foreach ($p in $oldPaths) { if (!$selected.Contains($p)) { throw "UNRESOLVED earlier pending file outside pilot scope: $p" } }
                $work=@($PilotPath | Where-Object { !$oldPaths.Contains($_) })
            } else { $work=@($tree.Files.Keys | Where-Object { !$oldPaths.Contains($_) } | Sort-Object) }
            # Recover outstanding admissions before new work, including a crash during hydration.
            foreach ($phase in @(0,1)) {
                $resuming=$phase -eq 0
                if ($resuming -and $open.Count) {
                    $reserved=0L; foreach ($prior in $open) { $reserved+=$prior.Bytes }
                    if ($open.Count -gt $MaxPendingFiles -or $reserved -gt $MaxPendingBytes) {
                        throw "LIMIT prior admissions exceed the current bounds: $($open.Count) files, $reserved bytes. Restore the previous limits to drain them."
                    }
                }
                $paths=if ($resuming) { $open | ForEach-Object Path } else { $work }
                foreach ($rel in $paths) {
                    if ($PilotFiles -and $view.Attempted -ge $PilotFiles) { break }
                    $f=$tree.Files[$rel]; $src="$SourceRoot\$rel"; $dst="$dest\$rel"; $r=$records[$rel]
                    $view.Path=$rel; $view.Op='Preflight'; $view.Length=0L; $view.Position=0L
                    $admitted=$false; $counted=$false
                    try {
                        Safe-Path $src; Safe-Path $dst
                        $s=Stat $src; $d=Stat $dst
                        if (!$s) { throw 'MISSING source after inventory' }
                        if (($s.Attributes -band 16384) -or ($d -and ($d.Attributes -band 16384))) { throw 'UNSUPPORTED EFS-encrypted file' }
                        if ($s.Size -ne $f.Bytes -or $s.Ticks -ne $f.Ticks) { throw 'CHANGED source after inventory' }
                        $proof=Valid-Proof $r $s $d
                        if ($proof -and $r.Status -eq 'Confirmed') {
                            $sc=Cloud $src $oneDriveId; $dc=Cloud $dst $dropboxId
                            if ($sc.Online -and $dc.Online) {
                                $view.Done++; $view.DoneBytes+=$f.Bytes; $view.ReusedBytes+=$f.Bytes; $view.Verified++; $view.VerifiedBytes+=$f.Bytes
                                if ($PilotPath.Count) { $view.Attempted++; [void]$pilotTargets.Add($rel) }
                                continue
                            }
                        }
                        $view.Attempted++; $counted=$true
                        if ($PilotFiles) { [void]$pilotTargets.Add($rel) }
                        if ($f.Bytes -gt $MaxPendingBytes) { throw "LIMIT file size $($f.Bytes) exceeds MaxPendingBytes $MaxPendingBytes" }
                        Wait-Queue $f.Bytes $false
                        $view.Op='Check source placeholder'; $view.Path=$rel
                        try { $sc=Cloud $src $oneDriveId } catch { throw "UNRESOLVED OneDrive placeholder: $($_.Exception.GetBaseException().Message)" }
                        if (!$sc.Synced) { throw 'UNRESOLVED OneDrive has not confirmed in-sync' }
                        if (!$proof) {
                            if ($d -and (($d.Attributes -band 16) -or $d.Size -ne $f.Bytes -or $d.Ticks -ne $f.Ticks)) { throw 'CONFLICT destination type, size or timestamp differs' }
                            $leaf=[IO.Path]::GetFileName($rel)
                            if ($leaf -match '^(\.~|~\$)|^(desktop\.ini|thumbs\.db|\.ds_store|\.dropbox|\.dropbox\.attr)$') {
                                try { if (!$d -or !(Cloud $dst $dropboxId).Synced) { throw 'Unconfirmed' } }
                                catch { throw 'UNSUPPORTED Dropbox temporary or reserved name without a confirmed synced destination' }
                            }
                            Check-Streams $src
                            if ($d) { Check-Streams $dst $true }
                            try { Check-Space $f.Bytes } catch {
                                if (!$pending.Count) { throw }
                                Wait-Queue 0 $true
                                Check-Space $f.Bytes
                            }
                            Make-Directory ([IO.Path]::GetDirectoryName($dst))
                            if ($resuming -and $r.Status -eq 'Admitted') { Clean-Stage $r }
                            $r=New-Record $f $s
                            Save $r 'Admitted'
                            $admitted=$true
                            Verify-Content $f $s $d $r
                        } elseif ($r.Status -eq 'Confirmed') { Save $r 'LocalVerified' }
                        $view.Verified++; $view.VerifiedBytes+=$f.Bytes
                        Add-Pending $r
                    } catch {
                        $msg=$_.Exception.Message
                        if (!$counted) { $view.Attempted++ }
                        if ($admitted -or $resuming -or $msg -match '^(LOW_DISK|JOURNAL|UNRESOLVED .* - |CHANGED since SHA)') { throw }
                        $kind=if ($msg -match '^(CHANGED|UNSUPPORTED|UNRESOLVED|MISSING|CONFLICT|LIMIT)\b') { $matches[1] } else { 'FAILED' }
                        Issue $kind $rel $msg
                    }
                    if ($pending.Count -and [datetime]::UtcNow -ge $queueStats.Next) { Poll-Queue }
                }
                Wait-Queue 0 $true
            }
            if (!$PilotFiles) {
                # Apply directory mtimes after all child renames, deepest directories first.
                $view.Op='Preserve directory timestamps'
                $dirPaths=@($tree.Dirs.Keys | Sort-Object Length -Descending)
                foreach ($dir in $dirPaths) {
                    $view.Path=$dir
                    $path="$dest\$dir"
                    try {
                        Make-Directory $path
                        $sm=Stat "$SourceRoot\$dir"; $dm=Stat $path
                        if (!$sm -or $sm.Ticks -ne $tree.Dirs[$dir]) { throw 'Source directory changed during migration' }
                        if ($dm.Ticks -ne $sm.Ticks) { [IO.Directory]::SetLastWriteTimeUtc((X $path),[datetime]::new($sm.Ticks,[DateTimeKind]::Utc)) }
                    } catch { Issue 'DIRECTORY' $dir $_.Exception.Message }
                }
                Make-Directory $dest
                $sm=Stat $SourceRoot; $dm=Stat $dest
                if ($sm.Ticks -ne $tree.RootTicks) { Issue 'DIRECTORY' '.' 'Source root changed during migration' }
                elseif ($dm.Ticks -ne $sm.Ticks) { [IO.Directory]::SetLastWriteTimeUtc((X $dest),[datetime]::new($sm.Ticks,[DateTimeKind]::Utc)) }
            }
        } catch {
            $msg=$_.Exception.Message
            $kind=if ($msg -match '^(CHANGED|UNSUPPORTED|UNRESOLVED|MISSING|CONFLICT|LIMIT|LOW_DISK)\b') { $matches[1] } else { 'FAILED' }
            $stopReason=$msg
            $problemPath=if ($msg -match '^(UNRESOLVED .* - |CHANGED since SHA)') { $view.Path } else { $rel }
            Issue $kind $problemPath $msg
            foreach ($item in $pending) { Issue 'PENDING' $item.Record.Path $item.Reason }
        }
        $tree=Inventory $SourceRoot 'SOURCE_FINAL'
    }
    $dt=if ([IO.Directory]::Exists((X $dest))) { Inventory $dest 'DESTINATION' } else { @{Files=@{};Dirs=@{};RootTicks=0L} }
    Audit-Visible $initial $tree $dt
} finally {
    if ($journal) { $journal.Dispose() }
    $lock.Dispose()
}
}

$view=[hashtable]::Synchronized(@{Total=0;Bytes=0L;Done=0;DoneBytes=0L;ReusedBytes=0L;Verified=0;VerifiedBytes=0L;Failed=0;
    Pending=0;PendingBytes=0L;AwaitingSync=0;PeakFiles=0;PeakBytes=0L;Attempted=0;Op='Starting';Path='';
    Position=0L;Length=0L;Last='None this run';Report=''})
$ps=[PowerShell]::Create()
$timer=[Diagnostics.Stopwatch]::StartNew()
$previousAt=0.0; $previousPos=0L; $previousFile=''; $nextLog=0.0
$exitCode=1
try {
    [void]$ps.AddScript($worker.ToString()).AddArgument($options).AddArgument($view)
    $run=$ps.BeginInvoke()
    do {
        $secs=$timer.Elapsed.TotalSeconds
        $op=$view.Op; $path=$view.Path; $pos=$view.Position
        $pct=if ($op -in @('Local copy and SHA-256','Verify staged SHA-256','Hash existing source','Hash existing destination') -and $view.Length -gt 0) { '{0:N1}%' -f (100*$pos/$view.Length) } else { '-' }
        $speed='-'
        if ($op -eq 'Local copy and SHA-256' -and $path -eq $previousFile -and $pos -ge $previousPos -and $secs -gt $previousAt) {
            $speed='{0:N2} MiB/s' -f (($pos-$previousPos)/1MB/($secs-$previousAt))
        }
        $previousAt=$secs; $previousPos=$pos; $previousFile=$path
        $eta='-'
        $newBytes=$view.DoneBytes-$view.ReusedBytes
        if (!$PilotFiles -and $Mode -eq 'Migrate' -and $newBytes -gt 0 -and $secs -gt 5) {
            $remaining=($view.Bytes-$view.DoneBytes)*$secs/$newBytes
            if ($remaining -ge 0 -and $remaining -lt 315360000) { $eta=[TimeSpan]::FromSeconds($remaining).ToString('d\.hh\:mm\:ss') }
        }
        $free=foreach ($volume in @([IO.Path]::GetPathRoot($SourceRoot),[IO.Path]::GetPathRoot($DropboxRoot)) | Select-Object -Unique) {
            try { '{0} {1:N1} GiB free' -f $volume,([IO.DriveInfo]::new($volume).AvailableFreeSpace/1GB) } catch { "$volume free unknown" }
        }
        $status=('{0}/{1} confirmed ({2:N2}/{3:N2} GiB), {4} verified, {5} issues | elapsed {6:d\.hh\:mm\:ss}, ETA {7}' -f
            $view.Done,$view.Total,($view.DoneBytes/1GB),($view.Bytes/1GB),$view.Verified,$view.Failed,$timer.Elapsed,$eta)
        $status+=' | {0:N2} GiB SHA-256 verified' -f ($view.VerifiedBytes/1GB)
        if ($PilotFiles) { $status+=" | pilot attempts $($view.Attempted)/$PilotFiles" }
        $queue=('Pending {0} files / {1:N2} GiB, {2} awaiting Dropbox sync | {3}' -f
            $view.Pending,($view.PendingBytes/1GB),$view.AwaitingSync,($free -join ', '))
        $current="$op $pct | local copy $speed | $path"
        Write-Progress -Id 1 -Activity $status -Status $queue -CurrentOperation "Last checkpoint: $($view.Last)"
        Write-Progress -Id 2 -ParentId 1 -Activity $op -Status $current
        if ($secs -ge $nextLog) {
            Write-Host "$status | $queue | $current | Last: $($view.Last)"
            $nextLog=$secs+15
        }
    } while (!$run.AsyncWaitHandle.WaitOne(1000))
    $results=$ps.EndInvoke($run)
    if ($ps.Streams.Error.Count) { throw ($ps.Streams.Error -join [Environment]::NewLine) }
    $result=$results | Select-Object -Last 1
    Write-Host $result.Text
    $exitCode=$result.Code
} finally {
    Write-Progress -Id 2 -Activity 'File' -Completed
    Write-Progress -Id 1 -Activity 'Migration' -Completed
    $ps.Dispose()
}
exit $exitCode
