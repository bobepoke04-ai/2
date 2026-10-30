#requires -Version 5.1
<#
Windows directory migration: Copy / Pending / Verify.
Never deletes source or destination entries. Existing destination files MAY be
OVERWRITTEN by Copy. Use a dedicated destination and keep source until acceptance.
Verify requires an operator-confirmed write freeze on BOTH trees, not just files
currently being hashed. This script does not create snapshots or stop writers.
Verification scope: ordinary file MAIN DATA STREAMS + relative paths + directory
presence. ACLs, ownership, auditing, ADS, EFS state, hardlink topology, sparse/
compression state and other filesystem metadata are NOT verified.
Reparse points are not traversed by Verify; each is an issue that prevents PASS.
Long-path/permission/enumeration/read errors also prevent PASS.
Copy can resume via Robocopy /Z. Hash verification restarts from scratch.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Copy','Pending','Verify')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$Destination,
    [string]$LogRoot = 'C:\MigrationLogs',
    [ValidateRange(1,128)][int]$Threads = 8,
    [switch]$FileProgress,
    [switch]$PreserveAcl,
    [switch]$WritesStopped
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Normalize-DirectoryPath([string]$Path) {
    if ($Path -notmatch '^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+(?:\\|$))') {
        throw "Use an absolute drive path or UNC share path: $Path"
    }
    $p = [IO.Path]::GetFullPath($Path).TrimEnd([char]'\')
    if ($p -match '^[A-Za-z]:$') { $p += '\' }
    return $p
}
function Same-OrBelow([string]$Child, [string]$Parent) {
    $c = $Child.TrimEnd([char]'\'); $p = $Parent.TrimEnd([char]'\')
    return ($c.Equals($p,[StringComparison]::OrdinalIgnoreCase) -or
            $c.StartsWith($p+'\',[StringComparison]::OrdinalIgnoreCase))
}
function Get-Entry([string]$Path) {
    try {
        $a = [IO.File]::GetAttributes($Path)
        if (($a -band [IO.FileAttributes]::Directory) -ne 0) {
            return [IO.DirectoryInfo]::new($Path)
        }
        return [IO.FileInfo]::new($Path)
    } catch [IO.FileNotFoundException] { return $null
    } catch [IO.DirectoryNotFoundException] { return $null }
}
function Is-Link($Entry) {
    return (($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}
function Assert-PlainAncestors([string]$Path) {
    $p = [IO.DirectoryInfo]::new($Path)
    while ($null -ne $p) {
        $entry = Get-Entry $p.FullName
        if ($null -ne $entry) {
            if (-not ($entry -is [IO.DirectoryInfo])) { throw "Not a directory: $($p.FullName)" }
            if (Is-Link $entry) { throw "Reparse-point root/ancestor is not supported: $($p.FullName)" }
        }
        $p = $p.Parent
    }
}

try {
    if ($env:OS -ne 'Windows_NT') { throw 'This entry point is for Windows.' }
    if ($Mode -eq 'Verify' -and -not $WritesStopped) {
        throw 'Stop all writes to BOTH trees, finish copying, then rerun Verify with -WritesStopped. The switch is an assertion, not a lock.'
    }
    $script:Src = Normalize-DirectoryPath $Source
    $script:Dst = Normalize-DirectoryPath $Destination
    $logs = Normalize-DirectoryPath $LogRoot
    if ((Same-OrBelow $Src $Dst) -or (Same-OrBelow $Dst $Src)) {
        throw 'Source and destination must be distinct, non-nested directories.'
    }
    if ((Same-OrBelow $logs $Src) -or (Same-OrBelow $logs $Dst)) {
        throw 'LogRoot must be outside source and destination.'
    }
    Assert-PlainAncestors $Src
    Assert-PlainAncestors $Dst
    Assert-PlainAncestors $logs
    $s = Get-Entry $Src
    if ($null -eq $s -or -not ($s -is [IO.DirectoryInfo])) { throw "Source not accessible as a directory: $Src" }
    $d = Get-Entry $Dst
    if ($null -ne $d -and -not ($d -is [IO.DirectoryInfo])) { throw "Destination is not a directory: $Dst" }
    if ($Mode -eq 'Verify' -and $null -eq $d) { throw "Destination does not exist: $Dst" }
    $runId = (Get-Date -Format 'yyyyMMdd_HHmmss_fff') + '_' + $PID
    $script:RunDir = [IO.Path]::Combine($logs, $Mode + '_' + $runId)
    [void][IO.Directory]::CreateDirectory($RunDir)
    Write-Host "MODE   : $Mode"
    Write-Host "SOURCE : $Src"
    Write-Host "TARGET : $Dst"
    Write-Host "REPORT : $RunDir"
    Write-Host 'Do not use alternate drive/share aliases that resolve to the same physical tree.'

    if ($Mode -ne 'Verify') {
        $robocopy = (Get-Command robocopy.exe -ErrorAction Stop).Source
        $logFile = [IO.Path]::Combine($RunDir, $Mode.ToLowerInvariant() + '.log')
        # Trailing \. avoids native-command quoting problems with quoted roots.
        $rcArgs = @(($Src.TrimEnd([char]'\')+'\.'), ($Dst.TrimEnd([char]'\')+'\.'),
            '/E', '/DCOPY:DAT', '/IT', '/XJ', '/SL', '/R:2', '/W:5',
            '/FP', '/TS', '/BYTES', '/TEE', ('/UNILOG:'+$logFile))
        if ($PreserveAcl) { $rcArgs += @('/COPY:DATS','/SECFIX') }
        else { $rcArgs += '/COPY:DAT' }
        if ($Mode -eq 'Copy') {
            Write-Host 'COPY may overwrite destination files; it does not delete entries.'
            $rcArgs += @('/Z', ('/MT:'+$Threads))
            if ($FileProgress) { $rcArgs += '/ETA' } else { $rcArgs += '/NP' }
        } else {
            Write-Host 'READ-ONLY comparison. New/changed entries are candidates, not hash results.'
            Write-Host 'EXTRA entries exist only at destination; they are not pending copies.'
            $rcArgs += @('/L','/NP')
        }
        & $robocopy @rcArgs
        $rc = $LASTEXITCODE
        @("Mode=$Mode", "Source=$Src", "Destination=$Dst", "RobocopyExitCode=$rc",
          'RobocopyExitCode>=8 means a failure; 0..7 is NOT a content-verification pass.',
          "Log=$logFile") | Set-Content -LiteralPath ([IO.Path]::Combine($RunDir,'summary.txt')) -Encoding UTF8
        Write-Host "Robocopy exit code: $rc | Log: $logFile"
        if ($rc -ge 8) { Write-Warning 'Copy/scan failures occurred. Inspect the log; do not accept the migration.' }
        else { Write-Host 'Inspect differences/extras, then run final SHA-256 verification under a write freeze.' }
        exit $rc
    }
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 20
}

# Verification writes streaming CSVs, not an in-memory file list.
$script:Counts = [ordered]@{SourceFiles=[long]0;SourceBytes=[long]0;OKFiles=[long]0;OKBytes=[long]0;Issues=[long]0}
$script:Buffer = New-Object byte[] (4MB)
$script:AllWriter = $null
$script:IssueWriter = $null
$script:SummaryFile = [IO.Path]::Combine($RunDir,'verify-summary.json')
$started = (Get-Date).ToString('o')
$script:FinishedScan = $false

function Write-VerifySummary([string]$State, [string]$ErrorText='') {
    [ordered]@{
        State=$State; Started=$started; Updated=(Get-Date).ToString('o'); Source=$Src; Destination=$Dst
        Algorithm='SHA256'; Counts=$Counts; OperatorAssertedWritesStopped=[bool]$WritesStopped
        Scope='Main file data streams, relative paths and directory presence only; NOT ACL/ADS/all metadata.'
        HashVerificationResumable=$false; ScanFinished=$FinishedScan; Error=$ErrorText
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $SummaryFile -Encoding UTF8
}
function Add-Result([string]$Status,[string]$Side,[string]$Relative,[string]$Path,
                    [string]$Bytes='',[string]$SourceHash='',[string]$TargetHash='',[string]$Message='') {
    $values = @((Get-Date).ToString('o'),$Status,$Side,$Relative,$Path,$Bytes,$SourceHash,$TargetHash,$Message)
    $line = ($values | ForEach-Object { '"' + ([string]$_).Replace('"','""') + '"' }) -join ','
    $AllWriter.WriteLine($line)
    if ($Status -ne 'OK' -and $Status -ne 'OK_DIR') {
        $Counts.Issues++
        $IssueWriter.WriteLine($line)
        Write-Host "[$Status] $Path | $Message"
    } elseif ($Status -eq 'OK') {
        Write-Host "[OK] verified=$($Counts.OKFiles) | $Relative"
    }
}
function Hash-StableFile([IO.FileInfo]$File,[string]$Side) {
    $File.Refresh()
    $beforeLength = $File.Length; $beforeTicks = $File.LastWriteTimeUtc.Ticks
    $stream = $null; $algorithm = $null
    Write-Host "[HASH-$Side] $($File.FullName) | $beforeLength bytes"
    try {
        # Deny writing/deletion of THIS file during its read. A tree-wide write
        # freeze is still required; per-file locks are not a snapshot.
        $stream = [IO.FileStream]::new($File.FullName,[IO.FileMode]::Open,
                   [IO.FileAccess]::Read,[IO.FileShare]::Read,1MB,[IO.FileOptions]::SequentialScan)
        if ($stream.Length -ne $beforeLength) { throw 'File changed before hashing started.' }
        $algorithm = [Security.Cryptography.SHA256]::Create()
        [long]$done = 0
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while (($n = $stream.Read($Buffer,0,$Buffer.Length)) -gt 0) {
            [void]$algorithm.TransformBlock($Buffer,0,$n,$Buffer,0)
            $done += $n
            if ($timer.Elapsed.TotalSeconds -ge 3) {
                $percent = if ($beforeLength -gt 0) { [Math]::Min(100,[int](100.0*$done/$beforeLength)) } else { 100 }
                Write-Progress -Id 1 -Activity "SHA256 $Side" -Status "$($File.FullName) | $done / $beforeLength bytes" -PercentComplete $percent
                $timer.Restart()
            }
        }
        [void]$algorithm.TransformFinalBlock([byte[]]@(),0,0)
        $File.Refresh()
        if (-not $File.Exists -or $done -ne $beforeLength -or
            $File.Length -ne $beforeLength -or $File.LastWriteTimeUtc.Ticks -ne $beforeTicks) {
            throw 'File changed during hashing; result is not accepted.'
        }
        return [pscustomobject]@{Hash=([BitConverter]::ToString($algorithm.Hash)).Replace('-','');Length=$beforeLength;Ticks=$beforeTicks}
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $algorithm) { $algorithm.Dispose() }
        Write-Progress -Id 1 -Activity "SHA256 $Side" -Completed
    }
}
function Compare-File([IO.FileInfo]$SourceFile,[IO.FileInfo]$TargetFile,[string]$Relative) {
    try {
        $SourceFile.Refresh(); $TargetFile.Refresh()
        if ($SourceFile.Length -ne $TargetFile.Length) {
            Add-Result 'SIZE_DIFF' 'SOURCE' $Relative $SourceFile.FullName ([string]$SourceFile.Length) '' '' "Target bytes=$($TargetFile.Length)"
            return
        }
        $a = Hash-StableFile $SourceFile 'SOURCE'
        $b = Hash-StableFile $TargetFile 'TARGET'
        $SourceFile.Refresh(); $TargetFile.Refresh()
        if (-not $SourceFile.Exists -or -not $TargetFile.Exists -or
            $SourceFile.Length -ne $a.Length -or $TargetFile.Length -ne $b.Length -or
            $SourceFile.LastWriteTimeUtc.Ticks -ne $a.Ticks -or $TargetFile.LastWriteTimeUtc.Ticks -ne $b.Ticks) {
            Add-Result 'CHANGED_DURING_VERIFY' 'SOURCE' $Relative $SourceFile.FullName '' $a.Hash $b.Hash 'Tree must remain unchanged for the entire verification.'
        } elseif ($a.Hash -cne $b.Hash) {
            Add-Result 'HASH_DIFF' 'SOURCE' $Relative $SourceFile.FullName ([string]$a.Length) $a.Hash $b.Hash 'Main stream content differs.'
        } else {
            $Counts.OKFiles++; $Counts.OKBytes += $a.Length
            Add-Result 'OK' 'SOURCE' $Relative $SourceFile.FullName ([string]$a.Length) $a.Hash $b.Hash ''
        }
    } catch {
        Add-Result 'READ_ERROR' 'SOURCE' $Relative $SourceFile.FullName '' '' '' $_.Exception.Message
    }
}
function Walk-Directory([string]$Directory,[string]$Prefix,[string]$Side) {
    try {
        # Lazy .NET enumeration; includes hidden/system entries. It deliberately
        # does not suppress access/long-path/network enumeration errors.
        foreach ($entry in ([IO.DirectoryInfo]::new($Directory)).EnumerateFileSystemInfos()) {
            $relative = if ($Prefix) { $Prefix + '\' + $entry.Name } else { $entry.Name }
            $isDirectory = ($entry -is [IO.DirectoryInfo])
            $descend = $isDirectory
            try {
                if (Is-Link $entry) {
                    Add-Result 'REPARSE_UNVERIFIED' $Side $relative $entry.FullName '' '' '' 'Not traversed; separate review is required.'
                    continue
                }
                if ($Side -eq 'SOURCE' -and -not $isDirectory) {
                    $Counts.SourceFiles++; $Counts.SourceBytes += $entry.Length
                }
                $otherRoot = if ($Side -eq 'SOURCE') { $Dst } else { $Src }
                $otherPath = [IO.Path]::Combine($otherRoot,$relative)
                $other = Get-Entry $otherPath
                if ($null -ne $other -and (Is-Link $other)) {
                    Add-Result 'REPARSE_COUNTERPART' $Side $relative $otherPath '' '' '' 'Counterpart is a link; this branch is not traversed.'
                    $descend = $false
                } elseif ($Side -eq 'SOURCE') {
                    if ($isDirectory) {
                        if ($null -eq $other) { Add-Result 'MISSING_DIR' $Side $relative $otherPath }
                        elseif (-not ($other -is [IO.DirectoryInfo])) { Add-Result 'TYPE_DIFF' $Side $relative $otherPath '' '' '' 'Expected directory.' }
                        else { Add-Result 'OK_DIR' $Side $relative $entry.FullName }
                    } else {
                        if ($null -eq $other) { Add-Result 'MISSING' $Side $relative $otherPath ([string]$entry.Length) }
                        elseif ($other -is [IO.DirectoryInfo]) { Add-Result 'TYPE_DIFF' $Side $relative $otherPath '' '' '' 'Expected file.' }
                        else { Compare-File $entry $other $relative }
                    }
                } else {
                    if ($null -eq $other) {
                        $status = if ($isDirectory) { 'EXTRA_DIR' } else { 'EXTRA' }
                        Add-Result $status $Side $relative $entry.FullName '' '' '' 'Destination-only entry. NOT deleted.'
                    } elseif ($isDirectory -ne ($other -is [IO.DirectoryInfo])) {
                        Add-Result 'TYPE_DIFF' $Side $relative $entry.FullName '' '' '' 'Source/destination entry types differ.'
                    }
                }
            } catch {
                Add-Result 'ENTRY_ERROR' $Side $relative $entry.FullName '' '' '' $_.Exception.Message
                # After a lookup/access error, do not traverse a potentially
                # unsafe corresponding branch. The issue prevents a PASS.
                $descend = $false
            }
            if ($descend) { Walk-Directory $entry.FullName $relative $Side }
        }
    } catch {
        Add-Result 'SCAN_ERROR' $Side $Prefix $Directory '' '' '' $_.Exception.Message
    }
}

$exitCode = 20
try {
    Write-VerifySummary 'RUNNING'
    $utf8 = [Text.UTF8Encoding]::new($true)
    $script:AllWriter = [IO.StreamWriter]::new([IO.Path]::Combine($RunDir,'verification.csv'),$false,$utf8)
    $script:IssueWriter = [IO.StreamWriter]::new([IO.Path]::Combine($RunDir,'issues.csv'),$false,$utf8)
    $AllWriter.AutoFlush = $true; $IssueWriter.AutoFlush = $true
    $header = 'Time,Status,Side,RelativePath,Path,SourceBytes,SourceSHA256,TargetSHA256,Message'
    $AllWriter.WriteLine($header); $IssueWriter.WriteLine($header)
    Write-Host 'VERIFY is read-only for file data. It does NOT create a snapshot.'
    Write-Host 'Keep BOTH trees unchanged. No automatic repair or deletion is performed.'
    Walk-Directory $Src '' 'SOURCE'
    Write-Host '[SCAN] Checking destination-only entries and directories...'
    Walk-Directory $Dst '' 'TARGET'
    $script:FinishedScan = $true
    if ($Counts.Issues -gt 0) { $state = 'NOT_PASS'; $exitCode = 10 }
    elseif ($Counts.SourceFiles -eq 0) { $state = 'EMPTY_SCOPE_REVIEW'; $exitCode = 10 }
    else { $state = 'PASS_MAIN_STREAMS_AND_TREE'; $exitCode = 0 }
    Write-VerifySummary $state
    Write-Host "RESULT=$state | SourceFiles=$($Counts.SourceFiles) | OK=$($Counts.OKFiles) | Issues=$($Counts.Issues)"
    Write-Host "Reports: $RunDir"
    Write-Host 'PASS is conditional on the asserted full-duration write freeze; metadata/ADS are out of scope.'
} catch {
    try { Write-VerifySummary 'ABORTED' $_.Exception.Message } catch { }
    Write-Error $_ -ErrorAction Continue
    $exitCode = 20
} finally {
    if ($null -ne $AllWriter) { $AllWriter.Dispose() }
    if ($null -ne $IssueWriter) { $IssueWriter.Dispose() }
}
exit $exitCode
