# Registers a Windows Scheduled Task that launches pysentinel-siem
# automatically at logon -- running elevated (no UAC click needed at
# logon: Task Scheduler grants that non-interactively for an admin
# account when the task's RunLevel is Highest) and restarting itself if
# the process ever dies unexpectedly. Run this once, from an elevated
# PowerShell prompt:
#
#   .\register_autostart.ps1
#
# To undo: .\unregister_autostart.ps1
# To launch it right now instead of waiting for next logon:
#   Start-ScheduledTask -TaskName "pysentinel-siem"
#
# SECURITY: a task that runs elevated with no UAC prompt must only ever point
# at files normal (non-admin) programs can't change. Otherwise anything
# running as you -- malware included -- could edit those files and get admin
# rights silently at your next sign-in. So this only registers the installed
# app in Program Files, never a source checkout, the portable zip, or a .venv.

param(
    [string]$ExePath = (Join-Path $env:ProgramFiles "pysentinel-siem\pysentinel-siem.exe")
)

$TaskName = "pysentinel-siem"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script from an elevated (Run as Administrator) PowerShell prompt -- registering a task with RunLevel Highest requires it."
    exit 1
}

if (-not (Test-Path $ExePath -PathType Leaf)) {
    Write-Error "pysentinel-siem isn't installed at $ExePath. Install it with the setup .exe from the Releases page first. (Autostart from a source checkout isn't supported -- see the SECURITY note at the top of this script.)"
    exit 1
}

# Refuse any location a non-admin account can write to: check the exe and
# every folder above it for write/modify/full-control grants to anyone
# other than SYSTEM, Administrators, and TrustedInstaller.
$trusted = @("S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
# WriteData/CreateFiles (0x2), DeleteSubdirectoriesAndFiles (0x40), Delete
# (0x10000), ChangePermissions (0x40000), TakeOwnership (0x80000), GenericAll
# (0x10000000), GenericWrite (0x40000000). AppendData/CreateDirectories alone
# is left out on purpose -- every drive root grants that to all users.
$writeMask = 0x2 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
$item = Get-Item -LiteralPath $ExePath
while ($item) {
    $acl = Get-Acl -LiteralPath $item.FullName
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne "Allow") { continue }
        # inherit-only entries don't apply to this object itself
        if ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if (([int64]$rule.FileSystemRights -band $writeMask) -eq 0) { continue }
        try {
            $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            $sid = $rule.IdentityReference.Value
        }
        # CREATOR OWNER only applies to things the owner creates later
        if ($sid -eq "S-1-3-0") { continue }
        if ($trusted -notcontains $sid) {
            Write-Error "$($item.FullName) can be modified by $($rule.IdentityReference). An elevated autostart task pointing there would let that account get admin rights. Refusing."
            exit 1
        }
    }
    $item = if ($item -is [System.IO.FileInfo]) { $item.Directory } else { $item.Parent }
}

$action = New-ScheduledTaskAction -Execute $ExePath -WorkingDirectory (Split-Path -Parent $ExePath)
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "Registered scheduled task '$TaskName' -- pysentinel-siem will now launch automatically at logon."
Write-Host "It runs elevated without a UAC prompt (Task Scheduler grants that non-interactively for an admin account)."
Write-Host "Crash resilience: Windows will restart it up to 3 times, 1 minute apart, if the process dies."
Write-Host ""
Write-Host "To undo:                .\unregister_autostart.ps1"
Write-Host "To launch it right now:  Start-ScheduledTask -TaskName '$TaskName'"
