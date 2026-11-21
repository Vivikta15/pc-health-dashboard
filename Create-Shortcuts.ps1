<#
.SYNOPSIS
  Puts three double-click shortcuts on your Desktop (you can pin the first one to the taskbar).
#>
$desktop = [Environment]::GetFolderPath('Desktop')
$script = Join-Path $PSScriptRoot 'PCHealth.ps1'
$ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$ws = New-Object -ComObject WScript.Shell
$ico = Join-Path $PSScriptRoot 'assets\pchealth.ico'
if (-not (Test-Path $ico)) { & (Join-Path $PSScriptRoot 'Make-Icon.ps1') }

function New-Lnk($name, $cmdArgs, $icon, $desc) {
    $l = $ws.CreateShortcut((Join-Path $desktop "$name.lnk"))
    $l.TargetPath = $ps
    $l.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$script`" $cmdArgs"
    $l.WorkingDirectory = $PSScriptRoot
    $l.IconLocation = $icon
    $l.Description = $desc
    $l.Save()
    Write-Host "Created: $name" -ForegroundColor Green
}

# The live dashboard window (pin THIS one to your taskbar). Runs hidden; the dashboard opens in its own window.
$dash = $ws.CreateShortcut((Join-Path $desktop 'PC Health.lnk'))
$dash.TargetPath = $ps
$dash.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$(Join-Path $PSScriptRoot 'Dashboard.ps1')`""
$dash.WorkingDirectory = $PSScriptRoot
$dash.WindowStyle = 7
$dash.IconLocation = "$ico,0"
$dash.Description = 'Live PC health dashboard'
$dash.Save()
Write-Host 'Created: PC Health (live dashboard)' -ForegroundColor Green

New-Lnk 'PC Health Check' 'report -Open' "$ico,0" 'Check my laptop and open a plain-English report (about 1 minute)'
New-Lnk 'PC Health Check + Virus Scan' 'report -Scan -Open' "$ico,0" 'Same check plus a Windows virus quick scan (a few minutes)'
New-Lnk 'Clean Junk' 'clean -Ask' "$ico,0" 'Shows safe junk files and asks before deleting them'
