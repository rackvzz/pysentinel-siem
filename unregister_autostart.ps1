# Removes the pysentinel-siem auto-start scheduled task created by
# register_autostart.ps1. Run once: .\unregister_autostart.ps1

$TaskName = "pysentinel-siem"

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'. pysentinel-siem will no longer launch automatically at logon."
} else {
    Write-Host "No scheduled task named '$TaskName' found -- nothing to remove."
}
