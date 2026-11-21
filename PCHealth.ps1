<#
.SYNOPSIS
  PCHealth - keep a Windows laptop healthy, tidy and safe. Read-only unless you pass -Apply.

.DESCRIPTION
  Commands:
    health     CPU/RAM/disk/battery/uptime/startup checks
    storage    Where is space going? Junk, big files, old downloads (-Duplicates for duplicate scan)
    security   Windows Defender + firewall status (-Scan runs a signature update + quick scan)
    report     Everything above -> score + HTML report in .\reports (-Open to view, -Scan to scan)
    clean      Dry-run of safe junk cleanup. Add -Apply to actually delete.

  Safety rules baked in:
    * Nothing is deleted without -Apply.
    * Only a fixed list of junk folders is ever touched (temp, crash dumps, update cache, browser cache).
    * Only files older than 2 days are deleted (so nothing in use is hit).
    * Big files, old downloads and duplicates are REPORTED only, never auto-deleted.
    * OneDrive cloud-only files are skipped (never downloaded or hashed).
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('health', 'storage', 'security', 'report', 'clean', 'help')]
    [string]$Command = 'help',
    [switch]$Apply,
    [switch]$Scan,
    [switch]$Open,
    [switch]$Duplicates,
    [switch]$EmptyRecycleBin,
    [switch]$IncludeAppData,
    [switch]$Ask,
    [switch]$Notify,
    [int]$TopN = 15,
    [int]$LargeMB = 200,
    [int]$OldDays = 90
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$script:ReportDir = Join-Path $PSScriptRoot 'reports'

# ---------------------------------------------------------------- helpers
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Format-Size([double]$b) {
    if ($b -ge 1GB) { return ('{0:N1} GB' -f ($b / 1GB)) }
    if ($b -ge 1MB) { return ('{0:N0} MB' -f ($b / 1MB)) }
    if ($b -ge 1KB) { return ('{0:N0} KB' -f ($b / 1KB)) }
    return ('{0:N0} B' -f $b)
}

function New-Finding($Area, $Level, $Message, [int]$Penalty = 0) {
    [pscustomobject]@{ Area = $Area; Level = $Level; Message = $Message; Penalty = $Penalty }
}

function Test-CloudOnly($f) {
    # ReparsePoint (0x400), Offline (0x1000), RecallOnOpen (0x40000), RecallOnDataAccess (0x400000)
    $a = [int]$f.Attributes
    return (($a -band 0x400) -ne 0) -or (($a -band 0x1000) -ne 0) -or (($a -band 0x40000) -ne 0) -or (($a -band 0x400000) -ne 0)
}

function Get-FolderSize([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return 0 }
    $s = (Get-ChildItem -LiteralPath $path -Recurse -Force -File -ErrorAction SilentlyContinue |
        Measure-Object Length -Sum).Sum
    if ($s) { return [int64]$s } else { return 0 }
}

function Esc([string]$s) { [System.Net.WebUtility]::HtmlEncode($s) }

# ---------------------------------------------------------------- HEALTH
function Get-HealthInfo {
    $f = New-Object System.Collections.Generic.List[object]
    $os = Get-CimInstance Win32_OperatingSystem
    $cpuLoad = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average, 0)
    $totalGB = $os.TotalVisibleMemorySize / 1MB
    $freeGB = $os.FreePhysicalMemory / 1MB
    $usedPct = [math]::Round((1 - $freeGB / $totalGB) * 100, 0)
    $uptime = (Get-Date) - $os.LastBootUpTime

    # RAM
    if ($usedPct -ge 92) { $f.Add((New-Finding 'Memory' 'BAD' "RAM is $usedPct% used - close heavy apps or restart." 10)) }
    elseif ($usedPct -ge 85) { $f.Add((New-Finding 'Memory' 'WARN' "RAM is $usedPct% used." 5)) }
    else { $f.Add((New-Finding 'Memory' 'OK' "RAM is $usedPct% used." 0)) }

    # Volumes
    $vols = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.Size -gt 0 } |
        ForEach-Object {
            [pscustomobject]@{
                Drive = "$($_.DriveLetter):"; SizeBytes = $_.Size; FreeBytes = $_.SizeRemaining
                FreePct = [math]::Round($_.SizeRemaining / $_.Size * 100, 0)
            }
        })
    foreach ($v in $vols) {
        if ($v.FreePct -lt 8) { $f.Add((New-Finding 'Storage' 'BAD' "$($v.Drive) only $($v.FreePct)% free ($(Format-Size $v.FreeBytes))." 15)) }
        elseif ($v.FreePct -lt 15) { $f.Add((New-Finding 'Storage' 'WARN' "$($v.Drive) is getting full: $($v.FreePct)% free ($(Format-Size $v.FreeBytes))." 8)) }
        else { $f.Add((New-Finding 'Storage' 'OK' "$($v.Drive) has $($v.FreePct)% free ($(Format-Size $v.FreeBytes))." 0)) }
    }

    # Physical disk health (SMART-style summary from Windows)
    $disks = @()
    try {
        $disks = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Name = $_.FriendlyName; Type = "$($_.MediaType)"; Health = "$($_.HealthStatus)"; Status = "$($_.OperationalStatus)" }
            })
        foreach ($d in $disks) {
            if ($d.Health -ne 'Healthy') { $f.Add((New-Finding 'Disk' 'BAD' "Disk '$($d.Name)' reports $($d.Health). Back up your data now." 25)) }
            else { $f.Add((New-Finding 'Disk' 'OK' "Disk '$($d.Name)' ($($d.Type)) is Healthy." 0)) }
        }
    }
    catch { }

    # Battery wear
    $battery = $null
    try {
        $design = (Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction Stop | Select-Object -First 1).DesignedCapacity
        $full = (Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop | Select-Object -First 1).FullChargedCapacity
        if ($design -and $full) {
            $wear = [math]::Max(0, [math]::Round((1 - $full / $design) * 100, 0))
            $battery = [pscustomobject]@{ DesignMWh = $design; FullMWh = $full; WearPct = $wear }
            if ($wear -ge 60) { $f.Add((New-Finding 'Battery' 'BAD' "Battery has lost $wear% of its capacity - consider replacement." 8)) }
            elseif ($wear -ge 40) { $f.Add((New-Finding 'Battery' 'WARN' "Battery has lost $wear% of its capacity." 5)) }
            else { $f.Add((New-Finding 'Battery' 'OK' "Battery wear is $wear%." 0)) }
        }
    }
    catch { }

    # Uptime / restart
    $days = [math]::Round($uptime.TotalDays, 1)
    if ($days -ge 14) { $f.Add((New-Finding 'System' 'WARN' "Last restart was $days days ago. Use Restart (not Shut down - Fast Startup keeps the session alive)." 3)) }
    else { $f.Add((New-Finding 'System' 'OK' "Uptime $days days." 0)) }

    # Pending reboot
    $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    if ($pending) { $f.Add((New-Finding 'System' 'WARN' 'A restart is pending to finish Windows updates.' 4)) }

    # Startup apps
    $startup = @(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue)
    if ($startup.Count -gt 15) { $f.Add((New-Finding 'Startup' 'WARN' "$($startup.Count) apps launch at login - trim them in Task Manager > Startup apps." 4)) }
    else { $f.Add((New-Finding 'Startup' 'OK' "$($startup.Count) startup entries." 0)) }

    # Last Windows update
    $lastHotfix = $null
    try {
        $lastHotfix = Get-HotFix -ErrorAction Stop | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($lastHotfix) {
            $age = [int]((Get-Date) - $lastHotfix.InstalledOn).TotalDays
            if ($age -gt 60) { $f.Add((New-Finding 'Updates' 'WARN' "Last Windows update installed $age days ago ($($lastHotfix.HotFixID))." 4)) }
            else { $f.Add((New-Finding 'Updates' 'OK' "Last Windows update installed $age days ago." 0)) }
        }
    }
    catch { }

    # Top memory consumers (grouped by app name)
    $top = @(Get-Process -ErrorAction SilentlyContinue | Group-Object Name |
        ForEach-Object { [pscustomobject]@{ Name = $_.Name; Count = $_.Count; MemBytes = ($_.Group | Measure-Object WorkingSet64 -Sum).Sum } } |
        Sort-Object MemBytes -Descending | Select-Object -First 6)

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME; OS = $os.Caption; Build = $os.BuildNumber
        CpuPct = $cpuLoad; RamUsedPct = $usedPct; RamTotalGB = [math]::Round($totalGB, 1)
        UptimeDays = $days; Volumes = $vols; Disks = $disks; Battery = $battery
        StartupCount = $startup.Count; TopProcesses = $top; Findings = $f
    }
}

# ---------------------------------------------------------------- SECURITY
function Get-SecurityInfo([switch]$RunScan) {
    $f = New-Object System.Collections.Generic.List[object]
    $info = [ordered]@{}
    $mp = $null
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }

    if (-not $mp) {
        $f.Add((New-Finding 'Antivirus' 'WARN' 'Could not read Microsoft Defender status (a third-party antivirus may be managing protection).' 10))
    }
    else {
        if ($RunScan) {
            Write-Host '  Updating Defender signatures...' -ForegroundColor DarkGray
            try { Update-MpSignature -ErrorAction Stop } catch { Write-Host "  (signature update skipped: $($_.Exception.Message))" -ForegroundColor DarkYellow }
            Write-Host '  Running Defender quick scan (this can take a few minutes)...' -ForegroundColor DarkGray
            try { Start-MpScan -ScanType QuickScan -ErrorAction Stop } catch { Write-Host "  (scan failed: $($_.Exception.Message))" -ForegroundColor DarkYellow }
            $mp = Get-MpComputerStatus
        }
        $sigAge = [int]$mp.AntivirusSignatureAge
        $quickAge = if ($mp.QuickScanAge -ge 4294967295) { -1 } else { [int]$mp.QuickScanAge }
        $fullAge = if ($mp.FullScanAge -ge 4294967295) { -1 } else { [int]$mp.FullScanAge }
        $info.AntivirusEnabled = $mp.AntivirusEnabled
        $info.RealTimeProtection = $mp.RealTimeProtectionEnabled
        $info.TamperProtection = $mp.IsTamperProtected
        $info.SignatureAgeDays = $sigAge
        $info.QuickScanAgeDays = $quickAge
        $info.FullScanAgeDays = $fullAge

        if (-not $mp.AntivirusEnabled) { $f.Add((New-Finding 'Antivirus' 'BAD' 'Microsoft Defender antivirus is OFF.' 30)) }
        if (-not $mp.RealTimeProtectionEnabled) { $f.Add((New-Finding 'Antivirus' 'BAD' 'Real-time protection is OFF.' 25)) }
        elseif ($mp.AntivirusEnabled) { $f.Add((New-Finding 'Antivirus' 'OK' 'Defender and real-time protection are ON.' 0)) }

        if ($sigAge -gt 7) { $f.Add((New-Finding 'Antivirus' 'BAD' "Virus definitions are $sigAge days old." 12)) }
        elseif ($sigAge -gt 3) { $f.Add((New-Finding 'Antivirus' 'WARN' "Virus definitions are $sigAge days old." 8)) }
        else { $f.Add((New-Finding 'Antivirus' 'OK' "Virus definitions are current ($sigAge days old)." 0)) }

        if ($quickAge -lt 0 -and $fullAge -lt 0) { $f.Add((New-Finding 'Scans' 'WARN' 'No Defender scan on record. Run: pchealth security -Scan' 6)) }
        else {
            $latest = @($quickAge, $fullAge | Where-Object { $_ -ge 0 } | Sort-Object)[0]
            if ($latest -gt 7) { $f.Add((New-Finding 'Scans' 'WARN' "Last scan was $latest days ago. Run: pchealth security -Scan" 5)) }
            else { $f.Add((New-Finding 'Scans' 'OK' "Last scan was $latest day(s) ago." 0)) }
        }
        if ($mp.IsTamperProtected -eq $false) { $f.Add((New-Finding 'Antivirus' 'WARN' 'Tamper Protection is off (Windows Security > Virus & threat protection settings).' 4)) }
    }

    # Firewall
    $fw = @()
    try {
        $fw = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Profile = "$($_.Name)"; Enabled = [bool]$_.Enabled } })
        $off = @($fw | Where-Object { -not $_.Enabled })
        if ($off.Count) { $f.Add((New-Finding 'Firewall' 'BAD' ("Firewall is OFF for: " + (($off | ForEach-Object Profile) -join ', ')) 10)) }
        else { $f.Add((New-Finding 'Firewall' 'OK' 'Windows Firewall is ON for all profiles.' 0)) }
    }
    catch { }

    # Active threats
    $threats = @()
    try {
        $threats = @(Get-MpThreat -ErrorAction Stop)
        if ($threats.Count) { $f.Add((New-Finding 'Threats' 'BAD' "$($threats.Count) threat(s) detected by Defender - open Windows Security > Protection history." 20)) }
        else { $f.Add((New-Finding 'Threats' 'OK' 'No active threats.' 0)) }
    }
    catch { }

    [pscustomobject]@{ Status = [pscustomobject]$info; Firewall = $fw; Threats = $threats; Findings = $f }
}

# ---------------------------------------------------------------- STORAGE
function Get-JunkCategories {
    $la = $env:LOCALAPPDATA
    @(
        [pscustomobject]@{ Name = 'User temp files'; Admin = $false; Paths = @($env:TEMP) }
        [pscustomobject]@{ Name = 'Windows temp files'; Admin = $true; Paths = @((Join-Path $env:WINDIR 'Temp')) }
        [pscustomobject]@{ Name = 'Crash dumps & error reports'; Admin = $false; Paths = @("$la\CrashDumps", "$la\Microsoft\Windows\WER\ReportArchive", "$la\Microsoft\Windows\WER\ReportQueue") }
        [pscustomobject]@{ Name = 'Windows Update download cache'; Admin = $true; Paths = @((Join-Path $env:WINDIR 'SoftwareDistribution\Download')) }
        [pscustomobject]@{ Name = 'Browser caches (Chrome/Edge)'; Admin = $false; Paths = @(
                "$la\Google\Chrome\User Data\Default\Cache", "$la\Google\Chrome\User Data\Default\Code Cache",
                "$la\Microsoft\Edge\User Data\Default\Cache", "$la\Microsoft\Edge\User Data\Default\Code Cache") }
    )
}

function Get-RecycleBinSize {
    # Read the current user's bin folder directly (no COM, works from any thread)
    try {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $total = [int64]0
        foreach ($d in ([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady })) {
            $bin = Join-Path $d.RootDirectory.FullName "`$Recycle.Bin\$sid"
            if (Test-Path -LiteralPath $bin) {
                foreach ($it in (Get-ChildItem -LiteralPath $bin -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '$R*' })) {
                    if ($it.PSIsContainer) { $total += [int64](Get-ChildItem -LiteralPath $it.FullName -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum }
                    else { $total += [int64]$it.Length }
                }
            }
        }
        return $total
    }
    catch { return [int64]0 }
}

function Get-StorageInfo([int]$LargeMB, [int]$OldDays, [int]$TopN, [switch]$FindDuplicates, [switch]$IncludeAppData) {
    $f = New-Object System.Collections.Generic.List[object]
    $cutoff = (Get-Date).AddDays(-2)
    $isAdmin = Test-IsAdmin

    $junk = foreach ($c in Get-JunkCategories) {
        $files = foreach ($p in $c.Paths) {
            if (Test-Path -LiteralPath $p) {
                Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff }
            }
        }
        $files = @($files)
        $size = ($files | Measure-Object Length -Sum).Sum
        [pscustomobject]@{ Name = $c.Name; Bytes = [int64]$size; Count = $files.Count; NeedsAdmin = ($c.Admin -and -not $isAdmin) }
    }
    $junk = @($junk)
    $recycle = Get-RecycleBinSize
    $junkTotal = ($junk | Measure-Object Bytes -Sum).Sum
    if (-not $junkTotal) { $junkTotal = 0 }

    if ($junkTotal -gt 5GB) { $f.Add((New-Finding 'Cleanup' 'WARN' "$(Format-Size $junkTotal) of safe-to-remove junk. Run: pchealth clean" 5)) }
    elseif ($junkTotal -gt 1GB) { $f.Add((New-Finding 'Cleanup' 'WARN' "$(Format-Size $junkTotal) of safe-to-remove junk. Run: pchealth clean" 2)) }
    else { $f.Add((New-Finding 'Cleanup' 'OK' "Only $(Format-Size $junkTotal) of junk found." 0)) }
    if ($recycle -gt 2GB) { $f.Add((New-Finding 'Cleanup' 'WARN' "Recycle Bin holds $(Format-Size $recycle)." 2)) }

    # Old downloads
    $dl = Join-Path $env:USERPROFILE 'Downloads'
    $oldDl = @()
    if (Test-Path $dl) {
        $limit = (Get-Date).AddDays(-$OldDays)
        $oldDl = @(Get-ChildItem -LiteralPath $dl -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $limit -and -not (Test-CloudOnly $_) })
    }
    $oldDlBytes = ($oldDl | Measure-Object Length -Sum).Sum; if (-not $oldDlBytes) { $oldDlBytes = 0 }
    $oldDlTop = @($oldDl | Sort-Object Length -Descending | Select-Object -First $TopN |
        ForEach-Object { [pscustomobject]@{ Path = $_.FullName; Bytes = $_.Length; Modified = $_.LastWriteTime.ToString('yyyy-MM-dd') } })
    if ($oldDlBytes -gt 2GB) { $f.Add((New-Finding 'Cleanup' 'WARN' "Downloads has $(Format-Size $oldDlBytes) of files untouched for $OldDays+ days (review them)." 3)) }

    # Large local files across the user profile
    # Walk user folders only (skip AppData and junction points: that is ~90% of the files and not yours to clean)
    $topLevel = @(Get-ChildItem -LiteralPath $env:USERPROFILE -Force -ErrorAction SilentlyContinue |
        Where-Object { ($IncludeAppData -or $_.Name -ne 'AppData') -and -not ($_.PSIsContainer -and (([int]$_.Attributes -band 0x400) -ne 0)) })
    $large = @(& {
            foreach ($t in $topLevel) {
                if ($t.PSIsContainer) { Get-ChildItem -LiteralPath $t.FullName -Recurse -Force -File -ErrorAction SilentlyContinue } else { $t }
            }
        } |
        Where-Object { $_.Length -ge ($LargeMB * 1MB) -and -not (Test-CloudOnly $_) -and ($IncludeAppData -or $_.FullName -notlike '*\AppData\*') } |
        Sort-Object Length -Descending | Select-Object -First $TopN |
        ForEach-Object { [pscustomobject]@{ Path = $_.FullName; Bytes = $_.Length; Modified = $_.LastWriteTime.ToString('yyyy-MM-dd') } })

    # Duplicates (opt-in: hashing is slow)
    $dups = @()
    if ($FindDuplicates) {
        $roots = 'Downloads', 'Documents', 'Desktop', 'Pictures', 'Videos' | ForEach-Object { Join-Path $env:USERPROFILE $_ } | Where-Object { Test-Path $_ }
        $cand = foreach ($r in $roots) {
            Get-ChildItem -LiteralPath $r -Recurse -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -ge 5MB -and -not (Test-CloudOnly $_) }
        }
        $dups = @($cand | Group-Object Length | Where-Object Count -gt 1 | ForEach-Object {
                $_.Group | ForEach-Object {
                    $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    if ($h) { [pscustomobject]@{ Hash = $h; Path = $_.FullName; Length = $_.Length } }
                }
            } | Group-Object Hash | Where-Object Count -gt 1 | ForEach-Object {
                [pscustomobject]@{ Copies = $_.Count; Each = $_.Group[0].Length; Wasted = ($_.Count - 1) * $_.Group[0].Length; Paths = @($_.Group.Path) }
            } | Sort-Object Wasted -Descending | Select-Object -First $TopN)
    }

    [pscustomobject]@{
        Junk = $junk; JunkTotal = [int64]$junkTotal; RecycleBytes = [int64]$recycle
        OldDownloadsBytes = [int64]$oldDlBytes; OldDownloadsCount = $oldDl.Count; OldDownloadsTop = $oldDlTop
        Large = $large; Duplicates = $dups; DuplicatesScanned = [bool]$FindDuplicates; Findings = $f
    }
}

# ---------------------------------------------------------------- CLEAN
function Invoke-Clean([switch]$Apply, [switch]$EmptyBin) {
    $cutoff = (Get-Date).AddDays(-2)
    $isAdmin = Test-IsAdmin
    $total = 0
    Write-Host ''
    if ($Apply) { Write-Host 'CLEANING (deleting safe junk older than 2 days)' -ForegroundColor Yellow }
    else { Write-Host 'DRY RUN - nothing will be deleted. Add -Apply to clean.' -ForegroundColor Cyan }

    foreach ($c in Get-JunkCategories) {
        if ($c.Admin -and -not $isAdmin) {
            Write-Host ('  {0,-34} skipped (needs an Administrator PowerShell)' -f $c.Name) -ForegroundColor DarkYellow
            continue
        }
        $files = foreach ($p in $c.Paths) {
            if (Test-Path -LiteralPath $p) {
                Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff }
            }
        }
        $files = @($files)
        $bytes = 0; $deleted = 0
        foreach ($file in $files) {
            if ($Apply) {
                try { $len = $file.Length; Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop; $bytes += $len; $deleted++ } catch { }
            }
            else { $bytes += $file.Length; $deleted++ }
        }
        $total += $bytes
        $verb = if ($Apply) { 'freed' } else { 'would free' }
        Write-Host ('  {0,-34} {1} {2} ({3} files)' -f $c.Name, $verb, (Format-Size $bytes), $deleted)
    }

    $bin = Get-RecycleBinSize
    if ($EmptyBin) {
        if ($Apply) {
            try { Clear-RecycleBin -Force -ErrorAction Stop; Write-Host ('  {0,-34} freed {1}' -f 'Recycle Bin', (Format-Size $bin)); $total += $bin }
            catch { Write-Host "  Recycle Bin: $($_.Exception.Message)" -ForegroundColor DarkYellow }
        }
        else { Write-Host ('  {0,-34} would free {1}' -f 'Recycle Bin', (Format-Size $bin)); $total += $bin }
    }
    else { Write-Host ('  {0,-34} {1} (not touched; add -EmptyRecycleBin)' -f 'Recycle Bin', (Format-Size $bin)) -ForegroundColor DarkGray }

    Write-Host ''
    $label = if ($Apply) { 'Total freed' } else { 'Total reclaimable' }
    Write-Host ('{0}: {1}' -f $label, (Format-Size $total)) -ForegroundColor Green
    Write-Host 'Big files, old downloads and duplicates are never auto-deleted - see: pchealth storage' -ForegroundColor DarkGray
}

# ---------------------------------------------------------------- OUTPUT
function Write-Section($t) { Write-Host ''; Write-Host "== $t ==" -ForegroundColor Cyan }

function Write-Findings($list) {
    foreach ($x in $list) {
        $color = switch ($x.Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } default { 'Red' } }
        Write-Host ('  [{0,-4}] {1,-9} {2}' -f $x.Level, $x.Area, $x.Message) -ForegroundColor $color
    }
}

function Get-Score($findings) {
    $pen = ($findings | Measure-Object Penalty -Sum).Sum
    $s = [math]::Max(0, 100 - [int]$pen)
    $grade = if ($s -ge 90) { 'Excellent' } elseif ($s -ge 75) { 'Good' } elseif ($s -ge 55) { 'Needs attention' } else { 'At risk' }
    [pscustomobject]@{ Score = $s; Grade = $grade }
}

function Get-Advice($x) {
    switch ($x.Area) {
        'Memory' { 'Your laptop is juggling too much at once. Close browser tabs and apps you are not using, or restart it.' }
        'Storage' { 'Your drive is filling up. Delete old downloads and junk (see the lists below).' }
        'Disk' { 'Your storage drive is reporting a problem. Back up your important files today and ask the manufacturer or IT for help.' }
        'Battery' { 'The battery holds less charge than when it was new. This is normal over time; consider replacing it if battery life bothers you.' }
        'System' { 'Restart your laptop: Start > Power > Restart. ("Shut down" does not fully restart Windows 11.)' }
        'Startup' { 'Too many apps launch when you sign in, which slows things down. Press Ctrl+Shift+Esc > Startup apps, and Disable the ones you do not need.' }
        'Updates' { 'Open Settings > Windows Update and click "Check for updates".' }
        'Antivirus' { 'Open Windows Security > Virus & threat protection and fix what it flags (turn protection on, click "Check for updates").' }
        'Scans' { 'Run a virus scan: double-click "PC Health Check + Virus Scan" on your desktop.' }
        'Firewall' { 'Open Windows Security > Firewall & network protection and turn the firewall on.' }
        'Threats' { 'Open Windows Security > Virus & threat protection > Protection history, then remove or quarantine what was found.' }
        'Cleanup' {
            if ($x.Message -like '*Downloads*') { 'Open your Downloads folder and delete old installers and files you no longer need (the biggest are listed below).' }
            elseif ($x.Message -like '*Recycle*') { 'Right-click the Recycle Bin on your desktop > Empty Recycle Bin (only if you are sure nothing in it is needed).' }
            else { 'Double-click "Clean Junk" on your desktop. It shows what it will remove and asks before deleting anything.' }
        }
        default { '' }
    }
}

function Show-Notification($title, $text, $openPath) {
    try {
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing
        $n = New-Object System.Windows.Forms.NotifyIcon
        $n.Icon = [System.Drawing.SystemIcons]::Shield
        $n.Visible = $true
        $p = $openPath
        $n.add_BalloonTipClicked({ Start-Process $p }.GetNewClosure())
        $n.ShowBalloonTip(10000, $title, $text, [System.Windows.Forms.ToolTipIcon]::Info)
        $end = (Get-Date).AddSeconds(30)
        while ((Get-Date) -lt $end) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 200 }
        $n.Visible = $false; $n.Dispose()
    }
    catch { }
}

function Show-Health($h) {
    Write-Section "Health - $($h.ComputerName) ($($h.OS), build $($h.Build))"
    Write-Host ("  CPU {0}%   RAM {1}% of {2} GB   Uptime {3} days   Startup entries {4}" -f $h.CpuPct, $h.RamUsedPct, $h.RamTotalGB, $h.UptimeDays, $h.StartupCount)
    Write-Host '  Top memory users: ' -NoNewline
    Write-Host (($h.TopProcesses | ForEach-Object { "$($_.Name) $(Format-Size $_.MemBytes)" }) -join ', ') -ForegroundColor DarkGray
    Write-Findings $h.Findings
}

function Show-Security($s) {
    Write-Section 'Security'
    Write-Findings $s.Findings
}

function Show-Storage($st, $LargeMB, $OldDays) {
    Write-Section 'Storage'
    Write-Host '  Safe-to-remove junk (older than 2 days):'
    foreach ($j in $st.Junk) {
        $note = if ($j.NeedsAdmin) { '  (partial - run as Administrator for full total)' } else { '' }
        Write-Host ('    {0,-34} {1,10}  {2,6} files{3}' -f $j.Name, (Format-Size $j.Bytes), $j.Count, $note)
    }
    Write-Host ('    {0,-34} {1,10}' -f 'Recycle Bin (not auto-cleaned)', (Format-Size $st.RecycleBytes))
    Write-Host ('  Downloads untouched for {0}+ days: {1} in {2} files' -f $OldDays, (Format-Size $st.OldDownloadsBytes), $st.OldDownloadsCount)
    foreach ($x in $st.OldDownloadsTop | Select-Object -First 5) { Write-Host ('    {0,10}  {1}  {2}' -f (Format-Size $x.Bytes), $x.Modified, $x.Path) -ForegroundColor DarkGray }
    Write-Host ("  Largest local files (>= $LargeMB MB, cloud-only OneDrive files excluded):")
    foreach ($x in $st.Large) { Write-Host ('    {0,10}  {1}  {2}' -f (Format-Size $x.Bytes), $x.Modified, $x.Path) -ForegroundColor DarkGray }
    if ($st.DuplicatesScanned) {
        Write-Host '  Duplicate files (same content, >= 5 MB) - keep one, review the rest yourself:'
        foreach ($d in $st.Duplicates) {
            Write-Host ('    {0} copies x {1} = {2} wasted' -f $d.Copies, (Format-Size $d.Each), (Format-Size $d.Wasted)) -ForegroundColor Yellow
            foreach ($p in $d.Paths) { Write-Host "       $p" -ForegroundColor DarkGray }
        }
        if (-not $st.Duplicates.Count) { Write-Host '    none found' -ForegroundColor Green }
    }
    Write-Findings $st.Findings
}

# ---------------------------------------------------------------- HTML REPORT
function New-HtmlReport($h, $sec, $st, $score, $all) {
    $color = if ($score.Score -ge 90) { '#1a9b5b' } elseif ($score.Score -ge 75) { '#4a9b1a' } elseif ($score.Score -ge 55) { '#d98b0a' } else { '#d1342f' }
    $nBad = @($all | Where-Object Level -eq 'BAD').Count
    $nWarn = @($all | Where-Object Level -eq 'WARN').Count
    $verdict = if ($nBad) { "$nBad important issue(s) need action" } elseif ($nWarn) { "$nWarn small thing(s) worth a look" } else { 'Everything looks healthy' }
    $attn = ($all | Where-Object Level -ne 'OK' | ForEach-Object {
            $c = if ($_.Level -eq 'BAD') { '#d1342f' } else { '#d98b0a' }
            $lbl = if ($_.Level -eq 'BAD') { 'Important' } else { 'Worth a look' }
            "<div class='item' style='border-left-color:$c'><div class='t'><span class='pill' style='background:$c'>$lbl</span> $(Esc $_.Message)</div><div class='do'><b>What to do:</b> $(Esc (Get-Advice $_))</div></div>"
        }) -join "`n"
    if (-not $attn) { $attn = "<div class='card'>Nothing needs your attention right now.</div>" }
    $okRows = ($all | Where-Object Level -eq 'OK' | ForEach-Object { "<li>$(Esc $_.Message)</li>" }) -join "`n"
    $vol = ($h.Volumes | ForEach-Object {
            "<div class='bar'><div class='lbl'>$($_.Drive) &mdash; $(Format-Size $_.FreeBytes) free of $(Format-Size $_.SizeBytes)</div><div class='track'><div class='fill' style='width:$(100 - $_.FreePct)%'></div></div></div>"
        }) -join "`n"
    $junk = ($st.Junk | ForEach-Object { "<tr><td>$(Esc $_.Name)</td><td class='r'>$(Format-Size $_.Bytes)</td><td class='r'>$($_.Count)</td></tr>" }) -join "`n"
    $large = ($st.Large | ForEach-Object { "<tr><td class='r'>$(Format-Size $_.Bytes)</td><td>$($_.Modified)</td><td class='path'>$(Esc $_.Path)</td></tr>" }) -join "`n"
    $oldDl = ($st.OldDownloadsTop | Select-Object -First 8 | ForEach-Object { "<tr><td class='r'>$(Format-Size $_.Bytes)</td><td>$($_.Modified)</td><td class='path'>$(Esc $_.Path)</td></tr>" }) -join "`n"
    $topProc = ($h.TopProcesses | ForEach-Object { "<tr><td>$(Esc $_.Name)</td><td class='r'>$($_.Count)</td><td class='r'>$(Format-Size $_.MemBytes)</td></tr>" }) -join "`n"
    $dupHtml = ''
    if ($st.DuplicatesScanned) {
        $d = ($st.Duplicates | ForEach-Object { "<tr><td class='r'>$($_.Copies) x $(Format-Size $_.Each)</td><td class='r'>$(Format-Size $_.Wasted)</td><td class='path'>$((($_.Paths | ForEach-Object { Esc $_ }) -join '<br>'))</td></tr>" }) -join "`n"
        $dupHtml = "<h2>Duplicate files</h2><table><tr><th>Copies</th><th>Wasted</th><th>Locations</th></tr>$d</table>"
    }
    $when = Get-Date -Format 'dddd, d MMMM yyyy HH:mm'
@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PC Health Report</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1b1f24;--mut:#6a737d;--line:#e3e6ea}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--card:#1d2125;--fg:#e8eaed;--mut:#9aa3ad;--line:#2d333a}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:900px;margin:0 auto;padding:24px 16px 48px}
h1{margin:0 0 4px;font-size:22px}h2{font-size:16px;margin:28px 0 8px}
.sub{color:var(--mut);margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px}
.hero{display:flex;align-items:center;gap:20px}
.score{font-size:56px;font-weight:700;color:$color;line-height:1}
.grade{font-size:18px;font-weight:600}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}.r{text-align:right;white-space:nowrap}
.path{word-break:break-all;color:var(--mut);font-size:13px}
.pill{color:#fff;border-radius:99px;padding:1px 9px;font-size:12px;font-weight:600}
.bar{margin:10px 0}.lbl{font-size:13px;color:var(--mut);margin-bottom:4px}
.track{background:var(--line);border-radius:6px;height:10px;overflow:hidden}.fill{background:#3b82f6;height:100%}
.note{color:var(--mut);font-size:13px;margin-top:24px}
.item{background:var(--card);border:1px solid var(--line);border-left:5px solid;border-radius:10px;padding:12px 16px;margin:8px 0}
.item .t{font-weight:600}.item .do{margin-top:6px;color:var(--fg)}
ul.ok{margin:0;padding-left:20px;color:var(--mut)}.gl{line-height:1.9;font-size:14px}
</style></head><body><main>
<h1>PC Health Report</h1><div class="sub">$(Esc $h.ComputerName) &middot; $(Esc $h.OS) &middot; $when</div>
<div class="card hero"><div class="score">$($score.Score)</div><div><div class="grade">$($score.Grade)</div><div class="sub" style="margin:0">out of 100 &middot; $verdict</div></div></div>
<p class="sub" style="margin-top:8px">How to read the score: 90+ excellent &middot; 75&ndash;89 good &middot; 55&ndash;74 needs attention &middot; below 55 at risk.</p>
<h2>What needs your attention</h2>$attn
<h2>What looks good</h2><div class="card"><ul class="ok">$okRows</ul></div>
<h2>Disk space</h2><div class="card">$vol</div>
<h2>Safe-to-remove junk</h2><p class="sub">Temporary files that apps leave behind. Removing them is safe. Use the "Clean Junk" shortcut.</p><table><tr><th>Category</th><th class="r">Size</th><th class="r">Files</th></tr>$junk</table>
<h2>Largest files on your laptop</h2><p class="sub">Your call: nothing here is deleted automatically. To remove one, open its folder, right-click the file and choose Delete.</p><table><tr><th class="r">Size</th><th>Modified</th><th>Path</th></tr>$large</table>
<h2>Old downloads ($($st.OldDownloadsCount) files, $(Format-Size $st.OldDownloadsBytes))</h2><table><tr><th class="r">Size</th><th>Modified</th><th>Path</th></tr>$oldDl</table>
$dupHtml
<h2>Top memory users</h2><table><tr><th>App</th><th class="r">Processes</th><th class="r">Memory</th></tr>$topProc</table>
<h2>Plain-English glossary</h2><div class="card gl"><b>RAM</b> &ndash; your laptop's short-term memory; when it is full, everything slows down.<br><b>Virus definitions</b> &ndash; the list of known viruses Windows checks against; it should be updated every few days.<br><b>Real-time protection</b> &ndash; Windows watching for viruses all the time, not just during scans.<br><b>Firewall</b> &ndash; a gatekeeper that blocks unwanted connections from the internet.<br><b>Startup apps</b> &ndash; programs that start by themselves when you turn the laptop on.<br><b>Cache / temp files</b> &ndash; leftovers apps keep to run faster; safe to delete, they rebuild themselves.<br><b>Disk health</b> &ndash; whether the drive that stores your files reports any failure signs.</div>
<p class="note">Generated by PCHealth. Nothing is deleted automatically; big files, old downloads and duplicates are for you to review.</p>
</main></body></html>
"@
}

# Structured cleanup for the dashboard (same safety rules as Invoke-Clean, returns data instead of printing)
function Invoke-CleanCore([switch]$Apply, [switch]$EmptyBin) {
    $cutoff = (Get-Date).AddDays(-2)
    $isAdmin = Test-IsAdmin
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($c in Get-JunkCategories) {
        if ($c.Admin -and -not $isAdmin) { $items.Add([pscustomobject]@{ Name = $c.Name; Bytes = [int64]0; Count = 0; Skipped = $true }); continue }
        $files = @(foreach ($p in $c.Paths) {
                if (Test-Path -LiteralPath $p) {
                    Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $cutoff }
                }
            })
        $bytes = [int64]0; $n = 0
        foreach ($file in $files) {
            if ($Apply) {
                try { $len = $file.Length; Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop; $bytes += $len; $n++ } catch { }
            }
            else { $bytes += $file.Length; $n++ }
        }
        $items.Add([pscustomobject]@{ Name = $c.Name; Bytes = $bytes; Count = $n; Skipped = $false })
    }
    $bin = [int64](Get-RecycleBinSize)
    $binFreed = [int64]0
    if ($EmptyBin -and $Apply) {
        try { Clear-RecycleBin -Force -ErrorAction Stop; $binFreed = $bin } catch { }
    }
    $total = [int64](($items | Measure-Object Bytes -Sum).Sum) + $binFreed
    [pscustomobject]@{ Items = @($items); RecycleBytes = $bin; RecycleFreed = $binFreed; TotalBytes = $total }
}

# ---------------------------------------------------------------- STORAGE MAP + PER-ITEM CLEANUP (used by the dashboard)
$script:ScannerSrc = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
namespace PCH {
  public class Entry { public string Name; public string Path; public long Bytes; public long Files; public bool IsDir; public bool Pending; }
  public class NmItem { public string Path; public long Bytes; public long Files; public DateTime Modified; }
  public static class Scanner {
    // skip junctions/symlinks (dirs) so nothing is counted twice; skip cloud-only (OneDrive) placeholder files
    static bool SkipDir(FileAttributes a) { return (a & FileAttributes.ReparsePoint) != 0; }
    static bool SkipFile(FileAttributes a) { int i = (int)a; return (i & 0x400000) != 0 || (i & 0x40000) != 0 || (a & FileAttributes.Offline) != 0; }

    public static long Walk(string dir, out long files) {
      long total = 0, count = 0;
      try {
        foreach (var fi in new DirectoryInfo(dir).EnumerateFileSystemInfos()) {
          FileAttributes a; try { a = fi.Attributes; } catch { continue; }
          if ((a & FileAttributes.Directory) != 0) {
            if (SkipDir(a)) continue;
            long f2; total += Walk(fi.FullName, out f2); count += f2;
          } else {
            if (SkipFile(a)) continue;
            try { total += ((FileInfo)fi).Length; count++; } catch { }
          }
        }
      } catch { }
      files = count; return total;
    }

    public static List<Entry> Children(string path) {
      var res = new List<Entry>(); var dirs = new List<DirectoryInfo>();
      try {
        foreach (var fi in new DirectoryInfo(path).EnumerateFileSystemInfos()) {
          FileAttributes a; try { a = fi.Attributes; } catch { continue; }
          if ((a & FileAttributes.Directory) != 0) { if (!SkipDir(a)) dirs.Add((DirectoryInfo)fi); }
          else { if (SkipFile(a)) continue; try { res.Add(new Entry { Name = fi.Name, Path = fi.FullName, Bytes = ((FileInfo)fi).Length, Files = 1, IsDir = false }); } catch { } }
        }
      } catch { }
      var arr = new Entry[dirs.Count];
      Parallel.For(0, dirs.Count, new ParallelOptions { MaxDegreeOfParallelism = 8 }, i => {
        long f; long b = Walk(dirs[i].FullName, out f);
        arr[i] = new Entry { Name = dirs[i].Name, Path = dirs[i].FullName, Bytes = b, Files = f, IsDir = true };
      });
      res.AddRange(arr);
      res.Sort((x, y) => y.Bytes.CompareTo(x.Bytes));
      return res;
    }

    // progressive version: folders appear right away as "pending" and fill in as each finishes
    public static void ChildrenInto(string path, List<Entry> sink) {
      var dirs = new List<DirectoryInfo>(); var ents = new List<Entry>();
      try {
        foreach (var fi in new DirectoryInfo(path).EnumerateFileSystemInfos()) {
          FileAttributes a; try { a = fi.Attributes; } catch { continue; }
          if ((a & FileAttributes.Directory) != 0) { if (!SkipDir(a)) { dirs.Add((DirectoryInfo)fi); ents.Add(new Entry { Name = fi.Name, Path = fi.FullName, Bytes = 0, IsDir = true, Pending = true }); } }
          else { if (SkipFile(a)) continue; try { ents.Add(new Entry { Name = fi.Name, Path = fi.FullName, Bytes = ((FileInfo)fi).Length, Files = 1, IsDir = false }); } catch { } }
        }
      } catch { }
      lock (sink) { sink.AddRange(ents); }
      var pend = ents.FindAll(e => e.IsDir);
      Parallel.ForEach(pend, new ParallelOptions { MaxDegreeOfParallelism = 8 }, e => {
        long f; long b = Walk(e.Path, out f);
        lock (sink) { e.Bytes = b; e.Files = f; e.Pending = false; }
      });
    }
    public static Entry[] Snapshot(List<Entry> sink) { lock (sink) { return sink.ToArray(); } }
    public static long[] EntryInfo(Entry e) { lock (e) { return new long[] { e.Bytes, e.Files, e.Pending ? 1 : 0 }; } }

    // size (and optionally delete) files older than a cutoff under fixed folders
    static void Sweep(string dir, DateTime cutoff, bool delete, bool isRoot, ref long bytes, ref long files) {
      try {
        foreach (var fi in new DirectoryInfo(dir).EnumerateFileSystemInfos()) {
          FileAttributes a; try { a = fi.Attributes; } catch { continue; }
          if ((a & FileAttributes.Directory) != 0) {
            if (SkipDir(a)) continue;
            Sweep(fi.FullName, cutoff, delete, false, ref bytes, ref files);
            if (delete) { try { Directory.Delete(fi.FullName, false); } catch { } }
          } else {
            if (SkipFile(a)) continue;
            try {
              if (fi.LastWriteTimeUtc >= cutoff) continue;
              long len = ((FileInfo)fi).Length;
              if (delete) { if ((a & FileAttributes.ReadOnly) != 0) fi.Attributes = FileAttributes.Normal; fi.Delete(); }
              bytes += len; files++;
            } catch { }
          }
        }
      } catch { }
    }
    public static long Older(string[] paths, int minAgeDays, bool delete, out long files) {
      long b = 0, f = 0; var cutoff = DateTime.UtcNow.AddDays(-minAgeDays);
      foreach (var p in paths) { if (Directory.Exists(p)) Sweep(p, cutoff, delete, true, ref b, ref f); }
      files = f; return b;
    }

    // node_modules folders that belong to a project (a package.json next to them)
    static void FindNm(string dir, List<NmItem> found, object gate, int depth) {
      if (depth > 12) return;
      try {
        foreach (var di in new DirectoryInfo(dir).EnumerateDirectories()) {
          FileAttributes a; try { a = di.Attributes; } catch { continue; }
          if (SkipDir(a)) continue;
          string n = di.Name;
          if (n == "node_modules") {
            string pj = System.IO.Path.Combine(dir, "package.json");
            if (File.Exists(pj)) {
              long f; long b = Walk(di.FullName, out f);
              lock (gate) { found.Add(new NmItem { Path = di.FullName, Bytes = b, Files = f, Modified = File.GetLastWriteTime(pj) }); }
            }
            continue;
          }
          if (n == ".git" || n == "AppData" || n.StartsWith("$")) continue;
          FindNm(di.FullName, found, gate, depth + 1);
        }
      } catch { }
    }
    public static List<NmItem> FindNodeModules(string root) {
      var found = new List<NmItem>(); var gate = new object(); var tops = new List<string>();
      try { foreach (var di in new DirectoryInfo(root).EnumerateDirectories()) { if ((di.Attributes & FileAttributes.ReparsePoint) == 0 && di.Name != "AppData") tops.Add(di.FullName); } } catch { }
      Parallel.ForEach(tops, new ParallelOptions { MaxDegreeOfParallelism = 6 }, t => { FindNm(t, found, gate, 0); });
      found.Sort((x, y) => y.Bytes.CompareTo(x.Bytes)); return found;
    }
    public static bool DeleteDir(string path) {
      try { Directory.Delete(path, true); return true; } catch { }
      try {
        foreach (var f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)) { try { File.SetAttributes(f, FileAttributes.Normal); } catch { } }
        Directory.Delete(path, true); return true;
      } catch { return false; }
    }
  }
}
'@
function Initialize-Scanner { if (-not ('PCH.Scanner' -as [type])) { Add-Type -TypeDefinition $script:ScannerSrc -ErrorAction Stop } }

# Each cleanup item: what it is, what happens if it goes, how safe it is. Paths are fixed here - never taken from the browser.
function Get-CleanupDefs {
    $la = $env:LOCALAPPDATA; $ra = $env:APPDATA
    @(
        @{ id = 'usertemp'; name = 'Temporary files'; what = 'Scratch files that apps leave in your temp folder.'; ifGone = 'Nothing. Apps make new ones when they need them.'; risk = 'safe'; paths = @($env:TEMP); age = 2 }
        @{ id = 'crash'; name = 'Crash reports and dumps'; what = 'Memory snapshots and error reports from apps that crashed.'; ifGone = 'Nothing, apart from old crash details being gone.'; risk = 'safe'; paths = @("$la\CrashDumps", "$la\Microsoft\Windows\WER\ReportArchive", "$la\Microsoft\Windows\WER\ReportQueue"); age = 2 }
        @{ id = 'chrome'; name = 'Chrome cache'; what = 'Saved copies of web pages and images so sites load faster.'; ifGone = 'Sites you revisit load a little slower the first time.'; risk = 'safe'; paths = @("$la\Google\Chrome\User Data\Default\Cache", "$la\Google\Chrome\User Data\Default\Code Cache"); age = 0 }
        @{ id = 'edge'; name = 'Edge cache'; what = 'Saved copies of web pages and images so sites load faster.'; ifGone = 'Sites you revisit load a little slower the first time.'; risk = 'safe'; paths = @("$la\Microsoft\Edge\User Data\Default\Cache", "$la\Microsoft\Edge\User Data\Default\Code Cache"); age = 0 }
        @{ id = 'vscode'; name = 'VS Code cache'; what = 'Cached code and editor data VS Code keeps for speed.'; ifGone = 'VS Code rebuilds it the next time you open it.'; risk = 'safe'; paths = @("$ra\Code\Cache", "$ra\Code\CachedData", "$ra\Code\Code Cache"); age = 0 }
        @{ id = 'npm'; name = 'npm download cache'; what = 'Packages npm downloaded before, kept for reuse.'; ifGone = 'npm downloads them again when a project needs them.'; risk = 'recreatable'; paths = @("$la\npm-cache", "$ra\npm-cache"); age = 0 }
        @{ id = 'pip'; name = 'Python (pip) cache'; what = 'Packages pip downloaded before, kept for reuse.'; ifGone = 'pip downloads them again when needed.'; risk = 'recreatable'; paths = @("$la\pip\Cache"); age = 0 }
        @{ id = 'nuget'; name = 'NuGet cache'; what = 'Developer packages downloaded for .NET projects.'; ifGone = 'They are downloaded again when a project is built.'; risk = 'recreatable'; paths = @("$la\NuGet\v3-cache"); age = 0 }
        @{ id = 'arduino'; name = 'Arduino download leftovers'; what = 'Installer archives Arduino kept after installing boards.'; ifGone = 'Nothing. They are only needed during installation.'; risk = 'recreatable'; paths = @("$la\Arduino15\staging"); age = 0 }
        @{ id = 'wu'; name = 'Windows Update downloads'; what = 'Update files Windows already installed.'; ifGone = 'Nothing. Windows re-downloads if it ever needs them.'; risk = 'safe'; paths = @((Join-Path $env:WINDIR 'SoftwareDistribution\Download')); age = 2; admin = $true }
        @{ id = 'wintemp'; name = 'Windows temporary files'; what = 'Scratch files used by Windows itself.'; ifGone = 'Nothing. Windows makes new ones when needed.'; risk = 'safe'; paths = @((Join-Path $env:WINDIR 'Temp')); age = 2; admin = $true }
    )
}

function Get-CleanupItems {
    Initialize-Scanner
    $isAdmin = Test-IsAdmin
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($d in Get-CleanupDefs) {
        $paths = @($d.paths | Where-Object { Test-Path -LiteralPath $_ })
        if (-not $paths.Count) { continue }
        $files = [long]0
        $bytes = [PCH.Scanner]::Older([string[]]$paths, [int]$d.age, $false, [ref]$files)
        $needsAdmin = [bool]($d.admin -and -not $isAdmin)
        if ($bytes -lt 1MB -and -not $needsAdmin) { continue }
        $out.Add(@{ id = $d.id; name = $d.name; what = $d.what; ifGone = $d.ifGone; risk = $d.risk; bytes = [int64]$bytes; files = [int64]$files; needsAdmin = $needsAdmin })
    }
    $bin = [int64](Get-RecycleBinSize)
    if ($bin -gt 0) { $out.Add(@{ id = 'recycle'; name = 'Recycle Bin'; what = 'Files you deleted that can still be restored.'; ifGone = 'They are gone for good and cannot be restored.'; risk = 'permanent'; bytes = $bin; files = 0; needsAdmin = $false }) }
    @($out | Sort-Object { $_.bytes } -Descending)
}

function Invoke-CleanItem([string]$Id) {
    Initialize-Scanner
    if ($Id -eq 'recycle') { $before = [int64](Get-RecycleBinSize); Clear-RecycleBin -Force -ErrorAction Stop; return $before }
    $d = Get-CleanupDefs | Where-Object { $_.id -eq $Id } | Select-Object -First 1
    if (-not $d) { throw "Unknown cleanup item" }
    if ($d.admin -and -not (Test-IsAdmin)) { throw "This one needs PC Health to run as administrator" }
    $files = [long]0
    return [int64][PCH.Scanner]::Older([string[]]@($d.paths | Where-Object { Test-Path -LiteralPath $_ }), [int]$d.age, $true, [ref]$files)
}

function Get-DriveHealthInfo {
    $disks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue)
    $out = foreach ($pd in $disks) {
        $rc = $null; try { $rc = $pd | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }
        @{
            name = $pd.FriendlyName; type = "$($pd.MediaType)"; bus = "$($pd.BusType)"; sizeBytes = [int64]$pd.Size; health = "$($pd.HealthStatus)"; status = "$($pd.OperationalStatus)"
            wear = $(if ($rc -and $null -ne $rc.Wear) { [int]$rc.Wear } else { $null }); tempC = $(if ($rc -and $rc.Temperature) { [int]$rc.Temperature } else { $null })
            hours = $(if ($rc -and $rc.PowerOnHours) { [int]$rc.PowerOnHours } else { $null })
            readErrors = $(if ($rc -and $null -ne $rc.ReadErrorsTotal) { [int64]$rc.ReadErrorsTotal } else { $null }); writeErrors = $(if ($rc -and $null -ne $rc.WriteErrorsTotal) { [int64]$rc.WriteErrorsTotal } else { $null })
        }
    }
    @($out)
}

# Allow other scripts to dot-source this file for its functions without running a command.
if ($MyInvocation.InvocationName -eq '.') { return }

# ---------------------------------------------------------------- MAIN
switch ($Command) {
    'help' {
        Get-Help $PSCommandPath -Detailed | Out-String | Write-Host
        Write-Host 'Examples:  pchealth health | pchealth storage -Duplicates | pchealth security -Scan | pchealth report -Open | pchealth clean -Apply' -ForegroundColor Cyan
    }
    'health' { Show-Health (Get-HealthInfo) }
    'security' { Show-Security (Get-SecurityInfo -RunScan:$Scan) }
    'storage' { Show-Storage (Get-StorageInfo -LargeMB $LargeMB -OldDays $OldDays -TopN $TopN -FindDuplicates:$Duplicates -IncludeAppData:$IncludeAppData) $LargeMB $OldDays }
    'clean' {
        Invoke-Clean -Apply:$Apply -EmptyBin:$EmptyRecycleBin
        if ($Ask -and -not $Apply) {
            Write-Host ''
            $a = Read-Host 'Delete these junk files now? Type Y and press Enter (anything else cancels)'
            if ($a -match '^[Yy]') { Invoke-Clean -Apply } else { Write-Host 'Cancelled - nothing was deleted.' -ForegroundColor Cyan }
            Read-Host 'Press Enter to close'
        }
    }
    'report' {
        Write-Host 'Checking your PC - this takes about a minute. Your report opens when it is done.' -ForegroundColor Cyan
        Write-Host 'Collecting health...' -ForegroundColor DarkGray
        $h = Get-HealthInfo
        Write-Host 'Checking security...' -ForegroundColor DarkGray
        $sec = Get-SecurityInfo -RunScan:$Scan
        Write-Host 'Scanning storage (can take a minute)...' -ForegroundColor DarkGray
        $st = Get-StorageInfo -LargeMB $LargeMB -OldDays $OldDays -TopN $TopN -FindDuplicates:$Duplicates -IncludeAppData:$IncludeAppData
        $order = @{ BAD = 0; WARN = 1; OK = 2 }
        $all = @($sec.Findings.ToArray()) + @($h.Findings.ToArray()) + @($st.Findings.ToArray())
        $all = @($all | Sort-Object { $order[$_.Level] })
        $score = Get-Score $all

        Show-Health $h; Show-Security $sec; Show-Storage $st $LargeMB $OldDays
        Write-Host ''
        Write-Host ("HEALTH SCORE: {0}/100 - {1}" -f $score.Score, $score.Grade) -ForegroundColor Green

        if (-not (Test-Path $script:ReportDir)) { New-Item -ItemType Directory -Path $script:ReportDir | Out-Null }
        $stamp = Get-Date -Format 'yyyyMMdd-HHmm'
        $file = Join-Path $script:ReportDir "PCHealth-$stamp.html"
        New-HtmlReport $h $sec $st $score $all | Set-Content -LiteralPath $file -Encoding UTF8
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm'),$($score.Score),$($st.JunkTotal)" | Add-Content -LiteralPath (Join-Path $script:ReportDir 'history.csv')
        Copy-Item -LiteralPath $file -Destination (Join-Path $script:ReportDir 'latest.html') -Force
        Write-Host "Report saved: $file" -ForegroundColor Cyan
        if ($Open) { Start-Process (Join-Path $script:ReportDir 'latest.html') }
        if ($Notify) {
            $bad = @($all | Where-Object Level -eq 'BAD').Count; $warn = @($all | Where-Object Level -eq 'WARN').Count
            $msg = if ($bad) { "$bad important issue(s) need action. Click to see what to do." } elseif ($warn) { "$warn small thing(s) worth a look. Click to see." } else { 'Everything looks healthy.' }
            Show-Notification "PC Health: $($score.Score)/100 - $($score.Grade)" $msg (Join-Path $script:ReportDir 'latest.html')
        }
    }
}
