<#
.SYNOPSIS
  PC Health live dashboard - a Vitals-style window for Windows.

.DESCRIPTION
  Starts a tiny web server that listens ONLY on this PC (127.0.0.1), then opens the dashboard
  in its own app window (Microsoft Edge app mode). Closing the window stops the server.

  Safety: every request needs a secret token that only the dashboard page knows, the Host header
  is checked (blocks DNS-rebinding), and the only actions it can take are the same safe ones as
  PCHealth.ps1: refresh checks, run a Defender quick scan, clean the fixed junk folders (after you
  confirm in the window) and "show in folder". It never deletes your own files.
#>
[CmdletBinding()]
param(
    [switch]$NoWindow,    # start the server without opening a window
    [switch]$Persistent,  # keep running after the window closes
    [int]$Port = 47821
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$core = Join-Path $PSScriptRoot 'PCHealth.ps1'
$htmlFile = Join-Path $PSScriptRoot 'dashboard.html'
$dataDir = Join-Path $env:LOCALAPPDATA 'PCHealth'
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
$stateFile = Join-Path $dataDir 'dashboard.json'
$logFile = Join-Path $dataDir 'dashboard.log'
try { if ((Get-Item $logFile -ErrorAction SilentlyContinue).Length -gt 200KB) { Remove-Item $logFile -Force } } catch { }
function Write-Log($m) { try { Add-Content -LiteralPath $logFile -Value "$(Get-Date -Format s) $m" } catch { } }

function Open-Window($url) {
    $a = @("--app=$url", '--window-size=1320,900', "--user-data-dir=`"$dataDir\edge`"", '--no-first-run', '--no-default-browser-check')
    foreach ($exe in 'msedge.exe', 'chrome.exe') {
        try { Start-Process -FilePath $exe -ArgumentList $a -ErrorAction Stop; return } catch { }
    }
    Start-Process $url
}

# --- already running? just open another window on it
if (Test-Path $stateFile) {
    try {
        $st = Get-Content $stateFile -Raw | ConvertFrom-Json
        [void](Get-Process -Id $st.pid -ErrorAction Stop)
        $r = Invoke-WebRequest "http://127.0.0.1:$($st.port)/ping" -UseBasicParsing -TimeoutSec 2
        if ($r.Content -eq 'pchealth') {
            if (-not $NoWindow) { Open-Window "http://127.0.0.1:$($st.port)/" }
            return
        }
    }
    catch { }
}

# --- start the local-only listener
$listener = $null
foreach ($p in (@($Port) + (Get-Random -Count 25 -InputObject (49152..65000)))) {
    try {
        $l = New-Object System.Net.HttpListener
        $l.Prefixes.Add("http://127.0.0.1:$p/")
        $l.Start()
        $listener = $l; $Port = $p; break
    }
    catch { Write-Log "port $p unavailable: $($_.Exception.Message)" }
}
if (-not $listener) { Write-Log 'could not start listener'; exit 1 }
$token = [guid]::NewGuid().ToString('N')
@{ pid = $PID; port = $Port } | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding ASCII
Write-Log "listening on 127.0.0.1:$Port"

# --- shared state + background tasks (slow checks never block the live view)
. $core
$S = [hashtable]::Synchronized(@{})
$S.busy = [hashtable]::Synchronized(@{ health = $false; security = $false; storage = $false; scan = $false; clean = $false })
$S.scan = @{ state = 'idle'; msg = '' }
$S.clean = @{ state = 'idle'; msg = '' }
$S.needStorage = $false
$S.needCleanup = $false
$S.maps = [hashtable]::Synchronized(@{})
$S.mapRuns = [hashtable]::Synchronized(@{})
Initialize-Scanner
$tasks = New-Object System.Collections.ArrayList

function Start-Bg([string]$name, [scriptblock]$sb, [object[]]$extra) {
    if ($S.busy[$name]) { return }
    $S.busy[$name] = $true
    # STA thread so COM calls (Recycle Bin size) work
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'; $rs.ThreadOptions = 'ReuseThread'; $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($sb).AddArgument($S).AddArgument($core)
    foreach ($e in $extra) { [void]$ps.AddArgument($e) }
    [void]$tasks.Add([pscustomobject]@{ Ps = $ps; Rs = $rs; Handle = $ps.BeginInvoke(); Name = $name })
}

$bgHealth = { param($S, $core) try { . $core; $S.health = Get-HealthInfo } catch { $S.errHealth = $_.Exception.Message } finally { $S.busy['health'] = $false } }
$bgSecurity = { param($S, $core) try { . $core; $S.security = Get-SecurityInfo } catch { $S.errSecurity = $_.Exception.Message } finally { $S.busy['security'] = $false } }
$bgStorage = { param($S, $core) try { . $core; $S.storage = Get-StorageInfo -LargeMB 200 -OldDays 90 -TopN 10 } catch { $S.errStorage = $_.Exception.Message } finally { $S.busy['storage'] = $false } }
$bgScan = {
    param($S, $core)
    try {
        . $core
        $S.scan = @{ state = 'running'; msg = 'Updating virus definitions...' }
        try { Update-MpSignature -ErrorAction Stop } catch { }
        $S.scan = @{ state = 'running'; msg = 'Scanning your PC - this takes a few minutes' }
        Start-MpScan -ScanType QuickScan -ErrorAction Stop
        $S.scan = @{ state = 'done'; msg = 'Scan finished' }
        $S.security = Get-SecurityInfo
    }
    catch { $S.scan = @{ state = 'error'; msg = "Scan could not run: $($_.Exception.Message)" } }
    finally { $S.busy['scan'] = $false }
}
$bgClean = {
    param($S, $core, $id)
    try {
        . $core
        $S.clean = @{ state = 'running'; msg = 'Cleaning...'; id = $id }
        $freed = [int64]0
        if ($id -like 'nm:*') {
            Initialize-Scanner
            $it = @($S.nm)[[int]$id.Substring(3)]
            if (-not $it) { throw 'That folder is no longer in the list' }
            $p = [string]$it.path
            $okPath = ((Split-Path $p -Leaf) -eq 'node_modules') -and (Test-Path -LiteralPath (Join-Path (Split-Path $p -Parent) 'package.json')) -and $p.StartsWith($env:USERPROFILE + '\', [StringComparison]::OrdinalIgnoreCase) -and ($p -notlike '*\AppData\*')
            if (-not $okPath) { throw 'That is not a project node_modules folder' }
            if (-not [PCH.Scanner]::DeleteDir($p)) { throw 'Some files are in use and could not be removed' }
            $freed = [int64]$it.bytes
        }
        else { $freed = [int64](Invoke-CleanItem $id) }
        $S.clean = @{ state = 'done'; msg = 'Done'; freed = $freed; id = $id; at = (Get-Date).ToString('o') }
        $S.cleanup = $null; $S.maps.Clear()
        $S.needCleanup = $true; $S.needStorage = $true
    }
    catch { $S.clean = @{ state = 'error'; msg = $_.Exception.Message; id = $id } }
    finally { $S.busy['clean'] = $false }
}
$bgMap = {
    param($S, $core, $path, $key)
    try {
        . $core; Initialize-Scanner
        $sink = New-Object 'System.Collections.Generic.List[PCH.Entry]'
        $S.mapRuns[$path] = @{ path = $path; sink = $sink }
        [PCH.Scanner]::ChildrenInto($path, $sink)
        $S.maps[$path] = @{ at = (Get-Date); items = @([PCH.Scanner]::Snapshot($sink) | ForEach-Object { @{ name = $_.Name; path = $_.Path; bytes = $_.Bytes; files = $_.Files; isDir = $_.IsDir } }) }
    }
    catch { $S.mapErr = $_.Exception.Message }
    finally { $S.mapRuns.Remove($path); $S.busy[$key] = $false }
}
$bgCleanup = {
    param($S, $core)
    try {
        . $core
        $items = Get-CleanupItems
        $nm = @([PCH.Scanner]::FindNodeModules($env:USERPROFILE) | ForEach-Object { @{ path = $_.Path; bytes = $_.Bytes; files = $_.Files; modified = $_.Modified.ToString('yyyy-MM-dd'); days = [int]((Get-Date) - $_.Modified).TotalDays } })
        $S.nm = $nm
        $S.cleanup = @{ items = $items; nm = $nm }
    }
    catch { $S.cleanup = @{ items = @(); nm = @(); err = $_.Exception.Message } }
    finally { $S.busy['cleanup'] = $false }
}
$bgDrive = { param($S, $core) try { . $core; $S.driveHealth = Get-DriveHealthInfo } catch { $S.driveHealth = @() } finally { $S.busy['drive'] = $false } }

$bgGpu = {
    param($S, $core)
    try {
        $mem = @(Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory -ErrorAction Stop)
        $main = $mem | Sort-Object SharedUsage -Descending | Select-Object -First 1
        $luid = if ($main) { $main.Name -replace '.*luid_0x00000000_(0x[0-9A-Fa-f]+)_.*', '$1' } else { '' }
        $eng = @(Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -Filter "Name LIKE '%engtype_3D' OR Name LIKE '%engtype_Compute'" -ErrorAction Stop | Where-Object { $luid -and $_.Name -like "*$luid*" })
        $byType = @($eng | Group-Object { $_.Name -replace '.*engtype_', '' } | ForEach-Object { @{ type = $_.Name; util = [int][math]::Min(100, ($_.Group | Measure-Object UtilizationPercentage -Sum).Sum) } })
        $util = ($byType | ForEach-Object { $_.util } | Measure-Object -Maximum).Maximum
        $vc = Get-CimInstance Win32_VideoController | Select-Object -First 1
        $S.gpu = @{ ok = $true; name = $vc.Name; driver = $vc.DriverVersion; util = [int]$util; engines = $byType; memMB = [int][math]::Round(([double]$main.SharedUsage + [double]$main.DedicatedUsage) / 1MB) }
    }
    catch { $S.gpu = @{ ok = $false; msg = $_.Exception.Message } }
    finally { $S.busy['gpu'] = $false }
}
$bgDevices = {
    param($S, $core)
    try {
        $bt = @(Get-PnpDevice -Class Bluetooth -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -and $_.FriendlyName -notmatch 'Enumerator|Transport|RFCOMM|Protocol|Generic|Radio|Adapter|Wireless Bluetooth' } |
                Sort-Object FriendlyName -Unique | ForEach-Object { @{ name = $_.FriendlyName; ok = ($_.Status -eq 'OK') } })
        $radio = [bool](Get-PnpDevice -Class Bluetooth -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match 'Wireless Bluetooth|Radio|Adapter' -and $_.Status -eq 'OK' } | Select-Object -First 1)
        $audio = @(Get-PnpDevice -Class AudioEndpoint -PresentOnly -ErrorAction SilentlyContinue | ForEach-Object { @{ name = $_.FriendlyName; ok = ($_.Status -eq 'OK') } })
        $npu = @(Get-PnpDevice -Class ComputeAccelerator -PresentOnly -ErrorAction SilentlyContinue | ForEach-Object { @{ name = $_.FriendlyName; ok = ($_.Status -eq 'OK') } })
        $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | ForEach-Object { @{ name = $_.Name; desc = $_.InterfaceDescription; speed = $_.LinkSpeed } })
        $wifi = $null
        try {
            $o = netsh wlan show interfaces 2>$null
            $ssid = ($o | Select-String '^\s*SSID\s*:\s*(.+)$' | Select-Object -First 1).Matches.Groups[1].Value.Trim()
            $sig = ($o | Select-String '^\s*Signal\s*:\s*(\d+)%' | Select-Object -First 1).Matches.Groups[1].Value
            if ($ssid) { $wifi = @{ ssid = $ssid; signal = [int]$sig } }
        }
        catch { }
        $fans = @(Get-CimInstance Win32_Fan -ErrorAction SilentlyContinue).Count
        $S.devices = @{ bluetooth = $bt; btRadio = $radio; audio = $audio; npu = $npu; adapters = $adapters; wifi = $wifi; fans = $fans }
    }
    catch { $S.devices = @{ bluetooth = @(); audio = @(); npu = @(); adapters = @(); fans = 0; err = $_.Exception.Message } }
    finally { $S.busy['devices'] = $false }
}
$bgBat = {
    param($S, $core)
    try {
        $out = Join-Path $env:TEMP "pchealth-bat-$([guid]::NewGuid().ToString('N')).xml"
        powercfg /batteryreport /xml /output $out | Out-Null
        if (Test-Path $out) {
            [xml]$x = Get-Content $out
            $b = @($x.BatteryReport.Batteries.Battery)[0]
            if ($b) { $d = [double]$b.DesignCapacity; $f = [double]$b.FullChargeCapacity; $S.batHealth = @{ design = [int]$d; full = [int]$f; cycles = [int]$b.CycleCount; pct = [int][math]::Round($f / $d * 100, 0) } }
            Remove-Item $out -Force -ErrorAction SilentlyContinue
        }
    }
    catch { }
    finally { $S.busy['bat'] = $false }
}

function Start-AllChecks {
    Start-Bg 'security' $bgSecurity
    Start-Bg 'health' $bgHealth
    Start-Bg 'storage' $bgStorage
}

# wallpaper (for the "match my wallpaper" theme) - served only to the dashboard window
$script:wpBytes = $null; $script:wpStamp = $null
function Get-Wallpaper {
    $f = Join-Path $env:APPDATA 'Microsoft\Windows\Themes\TranscodedWallpaper'
    if (-not (Test-Path -LiteralPath $f)) {
        $reg = (Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue).WallPaper
        if ($reg -and (Test-Path -LiteralPath $reg)) { $f = $reg } else { return $null }
    }
    $stamp = (Get-Item -LiteralPath $f).LastWriteTimeUtc.Ticks
    if ($script:wpBytes -and $script:wpStamp -eq $stamp) { return $script:wpBytes }
    try {
        Add-Type -AssemblyName System.Drawing
        $ms = New-Object IO.MemoryStream (, [IO.File]::ReadAllBytes($f))
        $img = [System.Drawing.Image]::FromStream($ms)
        $w = [math]::Min(1600, $img.Width); $h = [int]($img.Height * $w / $img.Width)
        $bmp = New-Object System.Drawing.Bitmap($w, $h)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.InterpolationMode = 'HighQualityBicubic'; $g.DrawImage($img, 0, 0, $w, $h); $g.Dispose()
        $enc = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
        $ep = New-Object System.Drawing.Imaging.EncoderParameters(1)
        $ep.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, [long]78)
        $out = New-Object IO.MemoryStream
        $bmp.Save($out, $enc, $ep)
        $script:wpBytes = $out.ToArray(); $script:wpStamp = $stamp
        $bmp.Dispose(); $img.Dispose(); $ms.Dispose(); $out.Dispose()
        return $script:wpBytes
    }
    catch { Write-Log "wallpaper: $($_.Exception.Message)"; return $null }
}

# --- live metrics (cheap; runs in the server loop)
function New-Counter($cat, $ctr, $inst) {
    try {
        $c = if ($inst) { New-Object System.Diagnostics.PerformanceCounter($cat, $ctr, $inst, $true) } else { New-Object System.Diagnostics.PerformanceCounter($cat, $ctr, '', $true) }
        [void]$c.NextValue(); return $c
    }
    catch { return $null }
}
function Read-Counter($c) { if ($c) { try { return [double]$c.NextValue() } catch { return 0.0 } } else { return 0.0 } }

$cCpu = New-Counter 'Processor Information' '% Processor Utility' '_Total'
$cDiskR = New-Counter 'PhysicalDisk' 'Disk Read Bytes/sec' '_Total'
$cDiskW = New-Counter 'PhysicalDisk' 'Disk Write Bytes/sec' '_Total'
$cDiskT = New-Counter 'PhysicalDisk' '% Disk Time' '_Total'
$cCommit = New-Counter 'Memory' '% Committed Bytes In Use' $null
$netIn = @(); $netOut = @()
try {
    $cat = New-Object System.Diagnostics.PerformanceCounterCategory('Network Interface')
    foreach ($i in $cat.GetInstanceNames()) {
        if ($i -notmatch 'Loopback|isatap|Teredo|Pseudo|vEthernet|Virtual|Bluetooth|WAN Miniport|Kernel Debug') {
            $netIn += New-Counter 'Network Interface' 'Bytes Received/sec' $i
            $netOut += New-Counter 'Network Interface' 'Bytes Sent/sec' $i
        }
    }
}
catch { }
$cpuInfo = Get-CimInstance Win32_Processor | Select-Object -First 1
$cores = [int]$env:NUMBER_OF_PROCESSORS
$cUser = New-Counter 'Processor' '% User Time' '_Total'
$cPriv = New-Counter 'Processor' '% Privileged Time' '_Total'
$cFreq = New-Counter 'Processor Information' '% Processor Performance' '_Total'
$coreC = @(0..($cores - 1) | ForEach-Object { New-Counter 'Processor' '% Processor Time' "$_" })
$memC = @{
    s1 = (New-Counter 'Memory' 'Standby Cache Normal Priority Bytes' $null); s2 = (New-Counter 'Memory' 'Standby Cache Reserve Bytes' $null)
    s3 = (New-Counter 'Memory' 'Standby Cache Core Bytes' $null); free = (New-Counter 'Memory' 'Free & Zero Page List Bytes' $null)
}
$maxMHz = [double]$cpuInfo.MaxClockSpeed
$script:cpuSum = 0.0; $script:cpuN = 0; $script:rSince = 0.0; $script:wSince = 0.0; $script:therm = @()
$pdCtr = @()
try {
    $pcat = New-Object System.Diagnostics.PerformanceCounterCategory('PhysicalDisk')
    foreach ($i in $pcat.GetInstanceNames()) {
        if ($i -ne '_Total') { $pdCtr += @{ name = $i; r = (New-Counter 'PhysicalDisk' 'Disk Read Bytes/sec' $i); w = (New-Counter 'PhysicalDisk' 'Disk Write Bytes/sec' $i); t = (New-Counter 'PhysicalDisk' '% Disk Time' $i) } }
    }
}
catch { }

# one free-space reading per day, for the "disk full in about N days" estimate
$histFile = Join-Path $dataDir 'diskhistory.json'
$script:diskHist = @()
function Update-DiskHistory {
    try {
        $today = (Get-Date).ToString('yyyy-MM-dd')
        $h = @(); if (Test-Path $histFile) { $h = @(Get-Content $histFile -Raw | ConvertFrom-Json) }
        if (-not ($h | Where-Object { $_.d -eq $today })) {
            $di = New-Object System.IO.DriveInfo($sysDrive)
            $h += [pscustomobject]@{ d = $today; free = [int64]$di.AvailableFreeSpace; total = [int64]$di.TotalSize }
            $h = @($h | Select-Object -Last 120)
            ConvertTo-Json -InputObject $h -Compress | Set-Content -LiteralPath $histFile -Encoding ASCII
        }
        $script:diskHist = $h
    }
    catch { Write-Log "history: $($_.Exception.Message)" }
}
function Get-DiskTrend {
    $h = @($script:diskHist)
    if ($h.Count -lt 3) { return @{ ready = $false; samples = $h.Count } }
    $t0 = [datetime]::ParseExact($h[0].d, 'yyyy-MM-dd', $null)
    $xs = @($h | ForEach-Object { ([datetime]::ParseExact($_.d, 'yyyy-MM-dd', $null) - $t0).TotalDays }); $ys = @($h | ForEach-Object { [double]$_.free })
    $n = $xs.Count; $mx = ($xs | Measure-Object -Average).Average; $my = ($ys | Measure-Object -Average).Average
    $num = 0.0; $den = 0.0; for ($i = 0; $i -lt $n; $i++) { $num += ($xs[$i] - $mx) * ($ys[$i] - $my); $den += [math]::Pow($xs[$i] - $mx, 2) }
    if ($den -eq 0) { return @{ ready = $false; samples = $n } }
    $slope = $num / $den    # bytes per day (negative = filling up)
    $free = [double]$h[$n - 1].free
    $days = $null; if ($slope -lt -5MB) { $days = [int][math]::Round($free / -$slope) }
    @{ ready = $true; samples = $n; perDay = [int64]$slope; daysLeft = $days }
}
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$prevT = 0.0; $prevCpu = @{}
$sessRx = 0.0; $sessTx = 0.0
$poll = 0; $hasBattery = $null
$sysDrive = $env:SystemDrive.TrimEnd(':')

function Get-Live {
    $script:poll++
    $now = $sw.Elapsed.TotalSeconds
    $dt = [math]::Max(0.2, $now - $script:prevT)

    $os = Get-CimInstance Win32_OperatingSystem
    $totalKB = [double]$os.TotalVisibleMemorySize; $freeKB = [double]$os.FreePhysicalMemory
    $usedGB = ($totalKB - $freeKB) / 1MB; $totalGB = $totalKB / 1MB

    $cpuPct = if ($cCpu) { [math]::Min(100, [math]::Round((Read-Counter $cCpu), 0)) } else { [double]$cpuInfo.LoadPercentage }
    $rx = 0.0; foreach ($c in $netIn) { $rx += Read-Counter $c }
    $tx = 0.0; foreach ($c in $netOut) { $tx += Read-Counter $c }
    $script:sessRx += $rx * $dt; $script:sessTx += $tx * $dt

    # per-app memory + CPU
    $procs = @(Get-Process -ErrorAction SilentlyContinue | Group-Object Name | ForEach-Object {
            [pscustomobject]@{
                Name = $_.Name; Count = $_.Count
                Mem = [double](($_.Group | Measure-Object WorkingSet64 -Sum).Sum)
                Cpu = [double](($_.Group | Measure-Object CPU -Sum).Sum)
            }
        })
    $apps = foreach ($p in $procs) {
        $prev = $script:prevCpu[$p.Name]
        $pct = 0.0
        if ($null -ne $prev -and $script:prevT -gt 0) { $pct = [math]::Max(0, ($p.Cpu - $prev) / ($dt * $cores) * 100) }
        $script:prevCpu[$p.Name] = $p.Cpu
        [pscustomobject]@{ name = $p.Name; count = $p.Count; mem = [int64]$p.Mem; cpu = [math]::Round($pct, 1) }
    }
    $script:prevT = $now
    $topMem = @($apps | Sort-Object mem -Descending | Select-Object -First 12)
    $topCpu = @($apps | Sort-Object cpu -Descending | Select-Object -First 8)
    $compB = [double](($procs | Where-Object { $_.Name -eq 'Memory Compression' } | Select-Object -First 1).Mem)
    $list = @($topMem) + @($topCpu | Where-Object { $n = $_.name; -not ($topMem | Where-Object { $_.name -eq $n }) })

    # battery (skip repeated lookups on desktops)
    $bat = $null
    if ($script:hasBattery -ne $false -or ($script:poll % 30 -eq 0)) {
        $b = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($b) {
            $script:hasBattery = $true
            $mins = $null; if ($b.EstimatedRunTime -and $b.EstimatedRunTime -lt 100000) { $mins = [int]$b.EstimatedRunTime }
            $bat = @{ pct = [int]$b.EstimatedChargeRemaining; plugged = ($b.BatteryStatus -in 2, 3, 6, 7, 8, 9, 11); minutes = $mins; status = [int]$b.BatteryStatus; health = $S.batHealth }
            $bs = Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($bs) {
                $rate = if ($bs.Charging) { [double]$bs.ChargeRate } else { [double]$bs.DischargeRate }
                $bat.powerW = [math]::Round($rate / 1000, 1); $bat.voltage = [math]::Round([double]$bs.Voltage / 1000, 2)
                $bat.charging = [bool]$bs.Charging; $bat.remainingMWh = [int64]$bs.RemainingCapacity
            }
        }
        else { $script:hasBattery = $false }
    }

    $drive = New-Object System.IO.DriveInfo($sysDrive)

    # extra detail for the per-metric pages
    $user = Read-Counter $cUser; $priv = Read-Counter $cPriv
    $script:cpuSum += $cpuPct; $script:cpuN++
    $perCore = @($coreC | ForEach-Object { [int][math]::Min(100, [math]::Round((Read-Counter $_), 0)) })
    $freq = [int][math]::Round($maxMHz * (Read-Counter $cFreq) / 100)
    $standby = (Read-Counter $memC.s1) + (Read-Counter $memC.s2) + (Read-Counter $memC.s3)
    $freeB = Read-Counter $memC.free
    $totalB = $totalKB * 1KB; $usedB = $totalB - ($freeKB * 1KB)
    $cachedB = [math]::Max(0, $totalB - $usedB - $freeB)
    $rd = Read-Counter $cDiskR; $wr = Read-Counter $cDiskW
    $script:rSince += $rd * $dt; $script:wSince += $wr * $dt
    if ($script:poll % 5 -eq 1) {
        $script:therm = @(Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction SilentlyContinue | ForEach-Object { @{ name = ($_.Name -replace '^\\_TZ\.', ''); c = [math]::Round([double]$_.Temperature - 273.15, 1) } })
    }
    $vols = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { @{ drive = $_.Name.TrimEnd('\'); label = $_.VolumeLabel; total = [int64]$_.TotalSize; free = [int64]$_.AvailableFreeSpace } })

    $live = @{
        t =[int64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
        cpu = @{ pct = $cpuPct; name = ($cpuInfo.Name -replace '\s+', ' ').Trim(); cores = $cores; procs = [int]$os.NumberOfProcesses }
        mem = @{ usedGB = [math]::Round($usedGB, 2); totalGB = [math]::Round($totalGB, 1); pct = [math]::Round($usedGB / $totalGB * 100, 0); commitPct = [math]::Round((Read-Counter $cCommit), 0) }
        disk = @{ readBps = [int64](Read-Counter $cDiskR); writeBps = [int64](Read-Counter $cDiskW); busyPct = [math]::Min(100, [math]::Round((Read-Counter $cDiskT), 0)); drive = "$($sysDrive):"; total = [int64]$drive.TotalSize; free = [int64]$drive.AvailableFreeSpace }
        net = @{ rxBps = [int64]$rx; txBps = [int64]$tx; sessRx = [int64]$script:sessRx; sessTx = [int64]$script:sessTx }
        battery = $bat
        uptimeSec = [int64]((Get-Date) - $os.LastBootUpTime).TotalSeconds
        apps = @($list)
    }
    $live.cpu.user = [math]::Round($user, 0); $live.cpu.system = [math]::Round($priv, 0)
    $live.cpu.avg = [math]::Round($script:cpuSum / [math]::Max(1, $script:cpuN), 0)
    $live.cpu.perCore = $perCore; $live.cpu.freqMHz = $freq; $live.cpu.maxMHz = [int]$maxMHz
    $live.memTypes = @{ appsGB = [math]::Round(($usedB - $compB) / 1GB, 2); compressedGB = [math]::Round($compB / 1GB, 2); cachedGB = [math]::Round($cachedB / 1GB, 2); freeGB = [math]::Round($freeB / 1GB, 2) }
    $live.disk.drives = @($pdCtr | ForEach-Object { @{ name = $_.name; read = [int64](Read-Counter $_.r); write = [int64](Read-Counter $_.w); busy = [int][math]::Min(100, [math]::Round((Read-Counter $_.t), 0)) } })
    $live.disk.readSince = [int64]$script:rSince; $live.disk.writeSince = [int64]$script:wSince; $live.disk.volumes = $vols
    $live.gpu = $S.gpu
    $live.thermal = $script:therm
    return $live
}

# --- status for the dashboard (results of the slow background checks)
function Get-Status {
    $f = New-Object System.Collections.Generic.List[object]
    foreach ($k in 'security', 'health', 'storage') { if ($S[$k]) { foreach ($x in @($S[$k].Findings.ToArray())) { $f.Add($x) } } }
    $ready = [bool]($S.security -and $S.health -and $S.storage)
    $order = @{ BAD = 0; WARN = 1; OK = 2 }
    $findings = @($f | Sort-Object { $order[$_.Level] } | ForEach-Object {
            $adv = Get-Advice $_
            if ($_.Area -eq 'Cleanup' -and $_.Message -like '*junk*') { $adv = 'Open the Storage tab. Each cleanup item explains what it is and asks before removing anything.' }
            elseif ($_.Area -eq 'Cleanup' -and $_.Message -like '*Downloads*') { $adv = 'Open the Storage tab, find "Old downloads", click Show on a file and delete what you do not need.' }
            elseif ($_.Area -eq 'Scans') { $adv = 'Click "Run quick scan" in the Virus protection card.' }
            @{ area = $_.Area; level = $_.Level; message = ($_.Message -replace '\s*Run: pchealth.*$', ''); advice = $adv }
        })
    $score = $null; $grade = ''
    if ($ready) { $sc = Get-Score ([object[]]$f.ToArray()); $score = $sc.Score; $grade = $sc.Grade }

    $sec = $null
    if ($S.security) { $sec = @{ status = $S.security.Status; firewall = @($S.security.Firewall); threatCount = @($S.security.Threats).Count } }
    $hl = $null
    if ($S.health) { $h = $S.health; $hl = @{ computer = $h.ComputerName; os = $h.OS; build = $h.Build; ramTotalGB = $h.RamTotalGB; volumes = @($h.Volumes); disks = @($h.Disks); battery = $h.Battery; startupCount = $h.StartupCount; uptimeDays = $h.UptimeDays } }
    $stg = $null
    if ($S.storage) {
        $so = $S.storage
        $stg = @{ junk = @($so.Junk); junkTotal = $so.JunkTotal; recycleBytes = $so.RecycleBytes; oldBytes = $so.OldDownloadsBytes; oldCount = $so.OldDownloadsCount; oldTop = @($so.OldDownloadsTop); large = @($so.Large) }
    }
    @{
        ready = $ready; score = $score; grade = $grade; findings = $findings
        security = $sec; health = $hl; storage = $stg
        driveHealth = @($S.driveHealth); trend = (Get-DiskTrend)
        busy = @{ health = [bool]$S.busy['health']; security = [bool]$S.busy['security']; storage = [bool]$S.busy['storage'] }
        scan = $S.scan; clean = $S.clean
        errors = @($S.errHealth, $S.errSecurity, $S.errStorage | Where-Object { $_ })
    }
}

# --- http helpers
function Send-Bytes($ctx, [int]$code, [string]$ctype, [byte[]]$bytes, [switch]$Page) {
    $r = $ctx.Response
    $r.StatusCode = $code; $r.ContentType = $ctype
    $r.Headers.Add('Cache-Control', 'no-store')
    $r.Headers.Add('X-Content-Type-Options', 'nosniff')
    $r.Headers.Add('Referrer-Policy', 'no-referrer')
    if ($Page) { $r.Headers.Add('Content-Security-Policy', "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'") }
    $r.ContentLength64 = $bytes.Length
    $r.OutputStream.Write($bytes, 0, $bytes.Length)
    $r.OutputStream.Close()
}
function Send-Text($ctx, [int]$code, [string]$text) { Send-Bytes $ctx $code 'text/plain; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes($text)) }
function Send-Json($ctx, $obj) {
    $json = ConvertTo-Json -InputObject $obj -Depth 8 -Compress
    Send-Bytes $ctx 200 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes($json))
}
function Read-Body($req) {
    try { $sr = New-Object IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8); $t = $sr.ReadToEnd(); if ($t) { return ($t | ConvertFrom-Json) } } catch { }
    return $null
}

$iconCache = @{}
function Get-AppIcon([string]$name) {
    if ($iconCache.ContainsKey($name)) { return $iconCache[$name] }
    $bytes = $null
    try {
        Add-Type -AssemblyName System.Drawing
        $path = (Get-Process -Name $name -ErrorAction Stop | Where-Object { $_.Path } | Select-Object -First 1).Path
        if ($path) {
            $ico = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
            $ms = New-Object IO.MemoryStream
            $ico.ToBitmap().Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
            $bytes = $ms.ToArray(); $ms.Dispose(); $ico.Dispose()
        }
    }
    catch { }
    $iconCache[$name] = $bytes
    return $bytes
}

$script:lastLive = Get-Date
$script:everConnected = $false
$started = Get-Date

function Handle-Request($ctx) {
    $req = $ctx.Request
    $path = $req.Url.AbsolutePath
    $hostHdr = $req.Headers['Host']
    if (@("127.0.0.1:$Port", "localhost:$Port") -notcontains $hostHdr) { Send-Text $ctx 403 'forbidden'; return }

    if ($path -eq '/ping') { Send-Text $ctx 200 'pchealth'; return }
    if ($path -eq '/favicon.ico') {
        $f = Join-Path $PSScriptRoot 'assets\pchealth.ico'
        if (Test-Path $f) { Send-Bytes $ctx 200 'image/x-icon' ([IO.File]::ReadAllBytes($f)) } else { Send-Bytes $ctx 204 'image/x-icon' ([byte[]]@()) }
        return
    }
    if ($path -match '^/assets/icon-(16|32|48|64|96|128|256)\.png$') {
        $f = Join-Path $PSScriptRoot "assets\icon-$($Matches[1]).png"
        if (Test-Path $f) { Send-Bytes $ctx 200 'image/png' ([IO.File]::ReadAllBytes($f)) } else { Send-Text $ctx 404 'none' }
        return
    }
    if ($path -eq '/' -and $req.HttpMethod -eq 'GET') {
        $html = (Get-Content -LiteralPath $htmlFile -Raw -Encoding UTF8).Replace('__TOKEN__', $token)
        Send-Bytes $ctx 200 'text/html; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes($html)) -Page
        return
    }
    if ($path -eq '/wallpaper') {
        if ($req.QueryString['t'] -ne $token) { Send-Text $ctx 403 'forbidden'; return }
        $wb = Get-Wallpaper
        if ($wb) { Send-Bytes $ctx 200 'image/jpeg' $wb } else { Send-Text $ctx 404 'none' }
        return
    }
    if ($path -like '/icon/*') {
        if ($req.QueryString['t'] -ne $token) { Send-Text $ctx 403 'forbidden'; return }
        $n = [Uri]::UnescapeDataString($path.Substring(6))
        $b = $null
        if ($n -match '^[\w\.\- ]{1,64}$') { $b = Get-AppIcon $n }
        if ($b) { Send-Bytes $ctx 200 'image/png' $b } else { Send-Text $ctx 404 'none' }
        return
    }
    if ($path -like '/api/*') {
        if ($req.Headers['X-Token'] -ne $token) { Send-Text $ctx 403 'forbidden'; return }
        switch ($path) {
            '/api/live' { $script:lastLive = Get-Date; $script:everConnected = $true; Send-Json $ctx (Get-Live) }
            '/api/status' { Send-Json $ctx (Get-Status) }
            '/api/devices' { if ($S.devices) { Send-Json $ctx $S.devices } else { Send-Json $ctx @{ pending = $true } } }
            '/api/refresh' { Start-AllChecks; Send-Json $ctx @{ ok = $true } }
            '/api/scan' {
                if (-not $S.busy['scan']) { Start-Bg 'scan' $bgScan }
                Send-Json $ctx @{ ok = $true }
            }
            '/api/clean' {
                $body = Read-Body $req
                $cid = [string]$body.id
                if ($cid -match '^(nm:\d{1,4}|[a-z]{3,12})$' -and -not $S.busy['clean']) { Start-Bg 'clean' $bgClean @($cid); Send-Json $ctx @{ ok = $true } }
                else { Send-Json $ctx @{ ok = $false } }
            }
            '/api/cleanup' {
                if (-not $S.cleanup -and -not $S.busy['cleanup']) { Start-Bg 'cleanup' $bgCleanup }
                if ($S.cleanup) { Send-Json $ctx $S.cleanup } else { Send-Json $ctx @{ pending = $true } }
            }
            '/api/map' {
                $body = Read-Body $req
                $p = [string]$body.path
                if (-not $p) { $p = "$($sysDrive):\" }
                $ok = $false
                try {
                    $full = [IO.Path]::GetFullPath($p)
                    if ($full -match '^[A-Za-z]:\\' -and $full.Substring(0, 1).ToUpper() -eq $sysDrive.ToUpper() -and (Test-Path -LiteralPath $full -PathType Container)) { $ok = $true; $p = $full }
                }
                catch { }
                if (-not $ok) { Send-Json $ctx @{ state = 'error'; msg = 'Folder not found' }; return }
                $cached = $S.maps[$p]
                $run = $S.mapRuns[$p]
                if ($cached -and -not [bool]$body.refresh -and ((Get-Date) - $cached.at).TotalMinutes -lt 10) { Send-Json $ctx @{ state = 'ready'; path = $p; items = $cached.items }; return }
                if ($run) {
                    $snap = [PCH.Scanner]::Snapshot($run.sink)
                    Send-Json $ctx @{ state = 'running'; path = $p; items = @($snap | ForEach-Object { @{ name = $_.Name; path = $_.Path; bytes = $_.Bytes; files = $_.Files; isDir = $_.IsDir; pending = $_.Pending } }) }
                    return
                }
                if ($S.mapRuns.Count -ge 3) { Send-Json $ctx @{ state = 'busy'; path = $p }; return }
                $mkey = 'map-' + [math]::Abs($p.ToLower().GetHashCode())
                Start-Bg $mkey $bgMap @($p, $mkey)
                Send-Json $ctx @{ state = 'running'; path = $p; items = @() }
            }
            '/api/reveal' {
                $body = Read-Body $req
                $p = [string]$body.path
                $allowed = @()
                if ($S.storage) { $allowed = @($S.storage.Large.Path) + @($S.storage.OldDownloadsTop.Path) }
                foreach ($k in @($S.maps.Keys)) { $allowed += @($S.maps[$k].items | ForEach-Object { $_.path }) }
                foreach ($rk in @($S.mapRuns.Keys)) { $rr = $S.mapRuns[$rk]; if ($rr) { $allowed += @([PCH.Scanner]::Snapshot($rr.sink) | ForEach-Object { $_.Path }) } }
                if ($S.nm) { $allowed += @($S.nm | ForEach-Object { $_.path }) }
                if ($p -and ($allowed -contains $p) -and (Test-Path -LiteralPath $p)) {
                    Start-Process explorer.exe -ArgumentList "/select,`"$p`""
                    Send-Json $ctx @{ ok = $true }
                }
                else { Send-Json $ctx @{ ok = $false } }
            }
            default { Send-Text $ctx 404 'not found' }
        }
        return
    }
    Send-Text $ctx 404 'not found'
}

# --- go
$script:lastGpu = [datetime]::MinValue; $script:lastDev = [datetime]::MinValue; $script:lastHist = Get-Date
Update-DiskHistory
Start-AllChecks
Start-Bg 'drive' $bgDrive
Start-Bg 'bat' $bgBat
if (-not $NoWindow) { Open-Window "http://127.0.0.1:$Port/" }

$accept = $listener.GetContextAsync()
$lastTick = Get-Date
try {
    while ($true) {
        if (-not $accept.Wait(1000)) {
            $now = Get-Date
            # finished background tasks
            for ($i = $tasks.Count - 1; $i -ge 0; $i--) {
                $t = $tasks[$i]
                if ($t.Handle.IsCompleted) {
                    try { [void]$t.Ps.EndInvoke($t.Handle) } catch { Write-Log "task $($t.Name): $($_.Exception.Message)" }
                    foreach ($e in $t.Ps.Streams.Error) { Write-Log "task $($t.Name) error: $e" }
                    $t.Ps.Dispose(); try { $t.Rs.Close(); $t.Rs.Dispose() } catch { }; $tasks.RemoveAt($i)
                }
            }
            if ($S.needStorage) { $S.needStorage = $false; Start-Bg 'storage' $bgStorage }
            if ($S.needCleanup) { $S.needCleanup = $false; Start-Bg 'cleanup' $bgCleanup }
            if (($now - $script:lastHist).TotalMinutes -ge 60) { $script:lastHist = $now; Update-DiskHistory }
            if ($script:everConnected) {
                if (($now - $script:lastGpu).TotalSeconds -ge 4) { $script:lastGpu = $now; Start-Bg 'gpu' $bgGpu }
                if (($now - $script:lastDev).TotalSeconds -ge 45) { $script:lastDev = $now; Start-Bg 'devices' $bgDevices }
            }
            # computer slept? don't count that as "window closed"
            if (($now - $lastTick).TotalSeconds -gt 10) { $script:lastLive = $now }
            $lastTick = $now
            if (-not $Persistent) {
                $idle = ($now - $script:lastLive).TotalSeconds
                if (($script:everConnected -and $idle -gt 45) -or (-not $script:everConnected -and ($now - $started).TotalSeconds -gt 120)) { Write-Log 'window closed - exiting'; break }
            }
            continue
        }
        $ctx = $accept.Result
        $accept = $listener.GetContextAsync()
        try { Handle-Request $ctx }
        catch {
            Write-Log "request error: $($_.Exception.Message) @ $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())"
            try { Send-Text $ctx 500 'error' } catch { }
        }
    }
}
finally {
    try { $listener.Stop(); $listener.Close() } catch { }
    foreach ($t in $tasks) { try { $t.Ps.Stop(); $t.Ps.Dispose() } catch { } }
    Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
}
