<#
.SYNOPSIS
  Sets up (or removes) a weekly automatic health + virus check.
.DESCRIPTION
  Creates a Windows scheduled task "PCHealth Weekly" that runs `PCHealth.ps1 report -Scan`
  every Sunday at 10:00 (or the next time the laptop is on). It only REPORTS and runs a Defender
  quick scan - it never deletes anything. Runs as you, no admin rights needed.
.EXAMPLE
  .\Install-Schedule.ps1            # install
  .\Install-Schedule.ps1 -Remove    # uninstall
#>
param(
    [switch]$Remove,
    [string]$Day = 'Sunday',
    [string]$Time = '10:00'
)

$name = 'PCHealth Weekly'

if ($Remove) {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed scheduled task '$name'." -ForegroundColor Green
    return
}

$script = Join-Path $PSScriptRoot 'PCHealth.ps1'
$arg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`" report -Scan -Notify"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $Day -At $Time
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2)

Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings `
    -Description 'Weekly PC health report + Defender quick scan (report only, never deletes).' -Force | Out-Null

Write-Host "Scheduled '$name': every $Day at $Time (or next time the PC is on)." -ForegroundColor Green
Write-Host "Reports land in: $(Join-Path $PSScriptRoot 'reports')"
