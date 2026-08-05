<#
.SYNOPSIS
    Install vpnmgr on Windows. The counterpart of packaging/install.sh.

.DESCRIPTION
    Copies the binaries to a stable location, registers the daemon as a service,
    and puts the tray in the Start Menu.

    Run from an elevated prompt, from the repository root:

        powershell -ExecutionPolicy Bypass -File packaging\install.ps1 -Conf path\to\AirVPN.conf

    Re-running without -Conf updates the binaries and leaves the configuration
    and keys alone, the same way install.sh does.

.PARAMETER Conf
    The .conf from AirVPN's Config Generator (WireGuard, UDP 1637). Only needed
    for a first install: its keys are copied out once, and after that the file
    is not referenced again.
#>
[CmdletBinding()]
param(
    [string]$Conf,
    [string]$Prefix = "$env:ProgramFiles\vpnmgr",
    [string]$ConfDir = "$env:ProgramData\vpnmgr"
)

$ErrorActionPreference = 'Stop'

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "must be run from an elevated prompt: registering a service and writing to $Prefix both need it"
    }
}

Assert-Elevated

$root = Split-Path -Parent $PSScriptRoot
# Prefer release binaries, but accept a debug build so the script is usable
# during development without a separate flag.
$bin = if (Test-Path "$root\target\release\vpnmgrd.exe") { "$root\target\release" }
       elseif (Test-Path "$root\target\debug\vpnmgrd.exe") { "$root\target\debug" }
       else { throw "no binaries found; run: cargo build --release" }

Write-Host "==> installing binaries from $bin into $Prefix"
New-Item -ItemType Directory -Force -Path $Prefix | Out-Null

# The service holds vpnmgrd.exe open, so it has to stop before the file can be
# replaced. Stopping it also brings the tunnel down through the normal path.
$existing = Get-Service -Name vpnmgrd -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Write-Host "    stopping the running service first"
    Stop-Service -Name vpnmgrd -Force
    Start-Sleep -Seconds 2
}

# The tray holds its own image open just as the service does, and it is a
# long-lived process most users leave running, so an update fails on a sharing
# violation partway through unless it is stopped first.
$tray = Get-Process -Name vpnmgr-tray -ErrorAction SilentlyContinue
if ($tray) {
    Write-Host "    stopping the running tray first"
    $tray | Stop-Process -Force
    Start-Sleep -Seconds 1
}

foreach ($exe in 'vpnmgrd.exe', 'vpnmgr.exe', 'vpnmgr-tray.exe') {
    Copy-Item -Force "$bin\$exe" "$Prefix\$exe"
}

Write-Host "==> configuration directory $ConfDir"
New-Item -ItemType Directory -Force -Path $ConfDir | Out-Null
# The key files live here. ProgramData is world-readable by default and
# inheriting that would publish the WireGuard private key to every account on
# the machine, so inheritance is stripped and only SYSTEM and the
# administrators are granted access.
& icacls.exe $ConfDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' /grant:r '*S-1-5-32-544:(OI)(CI)F' | Out-Null

$isFirstInstall = -not (Test-Path "$ConfDir\config.toml")
if ($isFirstInstall) {
    if (-not $Conf) {
        throw "first install needs -Conf <path to AirVPN .conf>; download one from AirVPN's Config Generator (WireGuard, port 1637)"
    }
    if (-not (Test-Path $Conf)) { throw "no such file: $Conf" }

    Write-Host "==> extracting key material into $ConfDir"
    # Read the keys directly rather than passing them to anything: a command
    # line is visible to every process on the machine.
    $text = Get-Content -Raw $Conf
    $private = [regex]::Match($text, '(?im)^\s*PrivateKey\s*=\s*([A-Za-z0-9+/=]+)').Groups[1].Value
    $preshared = [regex]::Match($text, '(?im)^\s*PresharedKey\s*=\s*([A-Za-z0-9+/=]+)').Groups[1].Value
    if (-not $private) { throw "no PrivateKey found in $Conf" }

    # -NoNewline: a trailing newline would become part of the key.
    Set-Content -NoNewline -Path "$ConfDir\wg.key" -Value $private
    if ($preshared) { Set-Content -NoNewline -Path "$ConfDir\wg.psk" -Value $preshared }

    Write-Host "==> writing $ConfDir\config.toml"
    # `import` prints shell commands for installing the keys, then the config
    # itself. Only the config is wanted here -- the keys are already written
    # above -- so everything before the first section header is dropped.
    $lines = @(& "$Prefix\vpnmgr.exe" import $Conf --dir $ConfDir)
    $start = ($lines | Select-String -Pattern '^\[provider' | Select-Object -First 1).LineNumber
    if (-not $start) { throw "vpnmgr import produced no configuration" }
    ($lines | Select-Object -Skip ($start - 1)) -join "`r`n" |
        Set-Content -Path "$ConfDir\config.toml"
} else {
    Write-Host "==> keeping the existing $ConfDir\config.toml"
}

Write-Host "==> registering the service"
if ($existing) {
    & "$Prefix\vpnmgrd.exe" --uninstall-service | Out-Null
    Start-Sleep -Seconds 1
}
& "$Prefix\vpnmgrd.exe" --install-service --config "$ConfDir\config.toml"
Start-Service -Name vpnmgrd

# The Start Menu is a folder of shortcuts. Writing to the machine-wide one
# rather than the current user's means the entry survives for every account,
# which matches a service that is also machine-wide.
$programs = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
Write-Host "==> adding the Start Menu entry"
$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut("$programs\VPN Manager.lnk")
# The tray, not the CLI: this is the entry someone clicks expecting a window,
# and the CLI would open a console that immediately exits.
$link.TargetPath = "$Prefix\vpnmgr-tray.exe"
$link.WorkingDirectory = $Prefix
$link.Description = 'Keep this machine on a fast AirVPN WireGuard server'
$link.Save()

# The daemon starts at boot on its own, but nothing would then be watching for
# a pending switch: it runs in Session 0 and cannot raise a notification, so the
# tray is the only thing that can ask. A tray that has to be launched by hand
# after every reboot is a tray that stops getting launched.
#
# The Startup folder rather than the Run registry key: it is visible in Task
# Manager's Startup tab and removable from there, which a registry entry is not.
Write-Host "==> starting the tray at login"
$startup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$autostart = $shell.CreateShortcut("$startup\VPN Manager Tray.lnk")
$autostart.TargetPath = "$Prefix\vpnmgr-tray.exe"
$autostart.WorkingDirectory = $Prefix
$autostart.Description = 'VPN Manager tray icon'
$autostart.Save()

Write-Host ""
Write-Host "Done. 'VPN Manager' is in the Start Menu; it opens the tray icon."
Write-Host "Launching it while it is already running does nothing rather than"
Write-Host "adding a second icon."
Write-Host ""
Write-Host "  vpnmgr status"
Write-Host "  vpnmgr test --country ca"
Write-Host "  vpnmgr connect"
Write-Host ""
Write-Host "Add $Prefix to PATH to run those from anywhere."
