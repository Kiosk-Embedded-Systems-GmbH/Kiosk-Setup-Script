<#
.SYNOPSIS
    Kiosk hardening script for Windows 10 IoT Enterprise LTSC / Windows 11 IoT Enterprise.
    VARIANT: TOUCH KEYBOARD OFF - the touch keyboard is disabled entirely
    (never auto-invokes, TabletInputService disabled). See
    Set-KioskConfig-v* (without "-NoKeyboard") for the counterpart where
    the touch keyboard is configured to appear automatically.

.DESCRIPTION
    Configures in a single run:
      1. Firewall (enable + rules for Lobster/OneConnect + ProV)
      2. Machine-wide Edge base settings (Translate off, kiosk-mode swipe
         gestures off) + domain allowlist ONLY for "Kiosk" (not
         "Maintenance", see 2b/7 below)
      2b. Edge site permissions (camera/mic/location/notifications/
          sensors/clipboard/local network) allowed for ALL sites,
          independent of the navigation domain lock, plus OS-level
          camera/microphone privacy (policy + Consent Store) and a
          best-effort camera driver warm-up.
      3. Desktop and lock screen wallpaper (PersonalizationCSP, applies
         to all users)
      4. Disable Edge UI edge-swipe gestures
      5. Disable notifications/Action Center for all users
      6. Power settings: "High performance" power plan, display and
         standby timeout set to "Never"
      7. Disable touch/swipe gestures (Precision Touchpad multi-finger
         gestures AND real touchscreen 3/4-finger gestures) + Edge domain
         restriction only for the "Kiosk" profile (HKCU instead of HKLM)
         -> applied to ALL existing user profiles AND the Default profile
            (template for new users, incl. Assigned Access accounts like
            "Kiosk") via offline hive loading; the Edge domain restriction
            is applied only to "Kiosk".
      8. Touch keyboard: disabled entirely (never auto-invokes,
         TabletInputService stopped and disabled) - see the VARIANT note
         at the top of this file.
      9. Local users "Maintenance" (administrator) and "Kiosk" (standard),
         created if they don't exist yet, incl. profile picture
         (downloaded from GitHub repo, resized to the account picture
         sizes Windows expects).
     10. Auto-logon for "Kiosk" via the Winlogon registry (no password
         needed, since the account is created without a password).
     11. AutoHotkey installed + scheduled task that blocks kiosk-relevant
         Ctrl+key combinations on every "Kiosk" logon (no registry-based
         way to do this, see note below).
     12. German language pack (de-DE) installed and set as the system/
         default language for new profiles (incl. "Kiosk").

.NOTES
    IMPORTANT - Two-finger pinch-to-zoom on the touchscreen: there is NO
    officially supported, global Windows switch for this (explicitly
    confirmed by Microsoft for Windows 11 IoT Enterprise). The only
    practical way for a pure Edge kiosk is the Chromium startup flag
    "--disable-pinch" wherever you launch Edge in Assigned Access - this
    is NOT part of this script, since it belongs to your kiosk launch
    configuration, not to registry-based hardening.

    IMPORTANT - gpedit.msc shows "Not configured" despite the registry
    values being set: this is EXPECTED behavior, not a bug. gpedit.msc
    reads its status exclusively from the local registry.pol file, not
    from the live registry. Policy values set directly via script/
    PowerShell are still applied correctly by Windows (the same registry
    structure is read at runtime) - only the display in gpedit.msc stays
    "Not configured", because it only reflects settings configured
    through gpedit itself. Verify via regedit or an actual test on the
    device instead of gpedit.msc.
    IMPORTANT - Newly created users:
    - "Maintenance" is created with a fixed password (hardcoded in the
      script - treat the script file confidentially / adjust as needed).
    - "Kiosk" is created WITHOUT a password (-NoPassword). By default,
      Windows only allows logons with a blank password at the local
      console (security policy "Accounts: Limit local account use of
      blank passwords to console logon only" = enabled). This is normally
      fine for Assigned Access auto-logon, since it's a local console
      logon - if you plan to use RDP/remote logon with "Kiosk", this will
      NOT work, you'd need to allow that separately via this policy.
    - Existing "Maintenance"/"Kiosk" accounts are not modified (no
      password reset, no group change).
    - Auto-logon / Assigned Access app assignment for "Kiosk" is NOT part
      of this script - that presumably already runs through your existing
      provisioning.

    IMPORTANT - Reliability of the settings:
    - Firewall, Edge policies, PersonalizationCSP (wallpaper/lock screen),
      TouchGestureSetting, and TipbandDesiredVisibility (both HKCU and
      machine-wide HKLM) are confirmed/documented, or verified via a
      partner script already used in production -> reliable.
    - There is NO confirmed registry-based way to disable the left Ctrl
      key on the touch keyboard - handled via AutoHotkey instead (step 11).
    - Truly disabling two-finger pinch-to-zoom on the touchscreen globally
      is not provided by Windows as a supported switch (apps like Edge
      handle this themselves). What reliably works here is disabling the
      Precision Touchpad multi-finger gestures (trackpad) and the Edge UI
      edge-swipe gestures (charms/corners/swipe-from-edge).

.PARAMETER NoRestart
    Skip the automatic restart at the end of the script (e.g. for testing a
    single change without rebooting). Settings still won't take full effect
    until the device is restarted manually afterward.

.PARAMETER SkipLanguagePack
    Skip installing/configuring the German language pack (step 12). Useful
    to speed up repeated test runs where the language pack is already known
    to be installed and unchanged.

.PARAMETER MaintenancePasswordPlain
    Password to use when creating the "Maintenance" account, if it doesn't
    already exist. Defaults to the standard value; override only if you
    need a different password for a specific deployment.

.PARAMETER Uninstall
    (optional, not implemented) - maintain separately for rollback if needed.

    Run as Administrator! A restart or gpupdate /force + re-logon is
    required for some settings to take effect.
#>

# ============================================================
# FIRST-TIME RUN: if this script won't even start because of the
# "Restricted" execution policy, copy/paste this single line into an
# elevated PowerShell window first, then run the script normally:
#
#   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
#
# ============================================================

#Requires -RunAsAdministrator

param(
    [switch]$NoRestart,
    [switch]$SkipLanguagePack,
    [string]$MaintenancePasswordPlain = "KISEstart82229#"
)

$ErrorActionPreference = 'Stop'

# ============================================================
# EXECUTION POLICY
# ============================================================
# Permanently allows running (unsigned, local) PowerShell scripts on this
# device - necessary if the default "Restricted" policy would otherwise
# prevent this and future kiosk scripts from running. Wrapped in try/catch,
# since a policy enforced centrally via GPO can block this with a
# non-terminable SecurityException - that's not an error in that case (the
# effective policy is usually already "Bypass"/"RemoteSigned" then), the
# script should keep running regardless.
try {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop
} catch {
    Write-Host "Note: Execution Policy is centrally enforced via GPO, local change skipped (currently effective: $(Get-ExecutionPolicy))." -ForegroundColor DarkYellow
}

# ============================================================
# CONFIGURATION
# ============================================================
$AllowedDomains = @(
    "oneux.kiosk.eu",
    "kiosk.eu",
    "app.straiv.io",
    "straiv.io",
    "api.straiv.io",
    "start.straiv.io",
    "app.development.straiv.dev",
    "*.luca.app",
    "*.likemagic.tech",
    "my.demo-apaleo.likemagic.tech",
    "monitoring.demo-apaleo.likemagic.tech",
    "idp.demo-apaleo.likemagic.tech",
    "localhost:8080",
    "localhost:8081",
    "de.webcamtests.com",
    "webcamtests.com",
    "webcam.org"
)

$WallpaperUrl       = "https://raw.githubusercontent.com/Kiosk-Embedded-Systems-GmbH/Kiosk-Setup-Script/main/wallpaper.jpg"
$WallpaperLocalPath = "C:\ProgramData\KioskConfig\background.jpg"

$MaintenancePicUrl = "https://raw.githubusercontent.com/Kiosk-Embedded-Systems-GmbH/Kiosk-Setup-Script/main/maintenance-profile-picture.png"
$KioskPicUrl        = "https://raw.githubusercontent.com/Kiosk-Embedded-Systems-GmbH/Kiosk-Setup-Script/main/kiosk-profile-picture.png"

# ============================================================
# SCRIPT VERSION
# ============================================================
# Bump this (and the filename) on every meaningful change, so it's easy to
# tell from the console output alone which version actually ran on a device.
$ScriptVersion = "3.17"

# ============================================================
# LOGGING
# ============================================================
# Writes a full transcript of the run to disk - valuable for remote
# execution via ProV (RMM), where there's no way to scroll back through the
# console after the fact once the connection closes.
$LogFolder = "C:\ProgramData\KioskConfig\Logs"
if (-not (Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path $LogFolder ("KioskSetup_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
try {
    Start-Transcript -Path $LogFile -Append -ErrorAction Stop | Out-Null
} catch {
    Write-Host "WARNING: Could not start transcript logging: $_" -ForegroundColor DarkYellow
}

Write-Host "=== Kiosk Setup Script v$ScriptVersion (Touch Keyboard OFF) started ===" -ForegroundColor Cyan
Write-Host "Options: NoRestart=$NoRestart, SkipLanguagePack=$SkipLanguagePack" -ForegroundColor DarkCyan
Write-Host "Log file: $LogFile" -ForegroundColor DarkCyan

# ============================================================
# VALIDATED DOWNLOAD HELPERS
# ============================================================
# Catches two classes of silent failure the plain Invoke-WebRequest calls
# used to be exposed to: a URL that accidentally contains HTML markup
# (e.g. pasted from a browser address bar with surrounding <a href=...>
# artifacts) instead of a plain link, and a download that "succeeds"
# (no exception) but produces an empty or missing file.
function Test-KioskPlainUrl {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Url
    )
    if ([string]::IsNullOrWhiteSpace($Url)) {
        throw "$Name is empty."
    }
    if ($Url -match '<|>|&quot;|</a>|href=') {
        throw "$Name contains HTML artifacts. Use a plain URL only. Current value: $Url"
    }
    if ($Url -notmatch '^https?://') {
        throw "$Name is not a valid http/https URL. Current value: $Url"
    }
}

function Invoke-KioskWebDownload {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile,
        [int]$TimeoutSec = 60
    )
    Test-KioskPlainUrl -Name "Download URI" -Url $Uri

    $parent = Split-Path $OutFile -Parent
    if ($parent -and -not (Test-Path $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }

    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop

    if (-not (Test-Path $OutFile)) {
        throw "Download finished without error, but file was not created: $OutFile"
    }
    if ((Get-Item $OutFile).Length -le 0) {
        throw "Downloaded file is empty: $OutFile"
    }
}

function New-KioskRegPath {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

Test-KioskPlainUrl -Name "WallpaperUrl" -Url $WallpaperUrl
Test-KioskPlainUrl -Name "MaintenancePicUrl" -Url $MaintenancePicUrl
Test-KioskPlainUrl -Name "KioskPicUrl" -Url $KioskPicUrl

# ============================================================
# 1. FIREWALL
# ============================================================
function Set-FirewallRules {
    Write-Host "`n[1/13] Configuring firewall..." -ForegroundColor Yellow
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

    Get-NetFirewallRule -DisplayName "Kiosk-Lobster-OneConnect-In" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Get-NetFirewallRule -DisplayName "Kiosk-ProV-Out" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    New-NetFirewallRule -DisplayName "Kiosk-Lobster-OneConnect-In" `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080-8081 `
        -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "Kiosk-ProV-Out" `
        -Direction Outbound -Action Allow -Protocol TCP -RemotePort 5902 `
        -Profile Any | Out-Null

    Write-Host "  Firewall enabled (all profiles), rules for 8080-8081 (in) / 5902 (out) set." -ForegroundColor Green
}

# ============================================================
# 2. EDGE DOMAIN ALLOWLIST
# ============================================================
function Set-EdgePolicies {
    Write-Host "`n[2/13] Configuring Edge base settings (machine-wide)..." -ForegroundColor Yellow
    $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    New-Item -Path $edgePolicyPath -Force | Out-Null

    # NOTE: The domain allow-/blocklist is deliberately NOT here (machine-
    # wide), but implemented further below as its own HKCU policy that only
    # applies to "Kiosk" (Set-KioskEdgeDomainRestriction) - "Maintenance"
    # should be able to browse without restrictions.

    # Cleanup: if an older version of this script already set a machine-wide
    # URLBlocklist/URLAllowlist here, remove it now - otherwise "Maintenance"
    # would remain restricted despite the current script.
    $staleBlockPath = "$edgePolicyPath\URLBlocklist"
    $staleAllowPath = "$edgePolicyPath\URLAllowlist"
    if (Test-Path $staleBlockPath) {
        Remove-Item -Path $staleBlockPath -Recurse -Force
        Write-Host "  Removed stale machine-wide URLBlocklist from an earlier run." -ForegroundColor DarkYellow
    }
    if (Test-Path $staleAllowPath) {
        Remove-Item -Path $staleAllowPath -Recurse -Force
        Write-Host "  Removed stale machine-wide URLAllowlist from an earlier run." -ForegroundColor DarkYellow
    }

    # Disable the automatic translate popup ("Translate this page from English?")
    New-ItemProperty -Path $edgePolicyPath -Name "TranslateEnabled" -PropertyType DWord -Value 0 -Force | Out-Null

    # Officially documented Edge policy, applies specifically to Edge kiosk
    # mode: disables swipe gestures for back/forward navigation and page
    # refresh. This is the confirmed fix for the "back gesture" still being
    # active in Edge kiosk mode - unlike OverscrollHistoryNavigation, this
    # is a real registry policy, not just a command-line flag.
    New-ItemProperty -Path $edgePolicyPath -Name "KioskSwipeGesturesEnabled" -PropertyType DWord -Value 0 -Force | Out-Null

    Write-Host "  Translate suggestion disabled (TranslateEnabled=0, applies to all users)." -ForegroundColor Green
    Write-Host "  Kiosk-mode swipe gestures (back/forward, refresh) disabled (KioskSwipeGesturesEnabled=0)." -ForegroundColor Green
}

# ============================================================
# 2b. EDGE SITE PERMISSIONS (camera/mic/location/etc. for ALL sites)
# ============================================================
function Set-EdgeSitePermissions {
    Write-Host "`n[2b/13] Granting site permissions for all sites (independent of the navigation domain lock)..." -ForegroundColor Yellow

    $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (-not (Test-Path $edgePolicyPath)) { New-Item -Path $edgePolicyPath -Force | Out-Null }

    # Explicitly set to Disabled (0) rather than leaving unconfigured -
    # combined with the "https://*" AllowedUrls entries below, this means
    # every HTTPS site gets silent access, no prompt.
    New-ItemProperty -Path $edgePolicyPath -Name "VideoCaptureAllowed" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $edgePolicyPath -Name "AudioCaptureAllowed" -PropertyType DWord -Value 0 -Force | Out-Null

    # DELIBERATE DESIGN CHOICE: these site-permission policies are set for
    # ALL sites (https://*), NOT scoped to $AllowedDomains. Only page
    # NAVIGATION is restricted to specific domains (via
    # $KIOSK_EDGE_DOMAIN_ACTION further below, applied only to "Kiosk") -
    # site permissions like camera/mic/etc. are intentionally kept separate
    # and unrestricted, since in practice the domain-restricted patterns
    # were prone to mismatches (subdomains, embedded third-party widgets)
    # that caused permission prompts/failures even for legitimately
    # allowed pages.
    $permissionPolicies = @(
        "NotificationsAllowedForUrls",
        "GeolocationAllowedForUrls",
        "VideoCaptureAllowedUrls",
        "AudioCaptureAllowedUrls",
        "SensorsAllowedForUrls",
        "ClipboardAllowedForUrls",
        "LocalNetworkAccessAllowedForUrls"
    )

    foreach ($policyName in $permissionPolicies) {
        $policyPath = "$edgePolicyPath\$policyName"
        New-Item -Path $policyPath -Force | Out-Null

        # Clear existing entries (idempotent on repeated runs)
        Get-Item $policyPath | Select-Object -ExpandProperty Property | ForEach-Object {
            Remove-ItemProperty -Path $policyPath -Name $_ -ErrorAction SilentlyContinue
        }

        New-ItemProperty -Path $policyPath -Name "1" -PropertyType String -Value "https://*" -Force | Out-Null
    }

    Write-Host "  Camera, microphone, location, notifications, sensors, clipboard," -ForegroundColor Green
    Write-Host "  and local network access set to 'Allow' by default for ALL HTTPS sites (navigation stays domain-restricted separately)." -ForegroundColor Green
}

# ============================================================
# 2c. OS-LEVEL CAMERA/MICROPHONE PRIVACY (separate from Edge's own site permissions above)
# ============================================================
# IMPORTANT: Set-EdgeSitePermissions above only pre-authorizes camera/mic
# access WITHIN Edge's own permission model. Windows has its own, separate
# global privacy gate (Settings > Privacy & security > Camera/Microphone)
# that sits ABOVE that and blocks every app - Edge included - regardless of
# what Edge itself allows, if it's off. In Assigned Access there's no way
# for anyone to interactively click through a privacy consent prompt, so
# this needs to be pre-authorized here instead.
function Set-KioskCameraMicPrivacy {
    Write-Host "`n[2c/13] Enabling OS-level camera/microphone access (machine-wide)..." -ForegroundColor Yellow

    # Most authoritative: the actual "App Privacy" Group Policy. Values:
    # 0 = user is in control, 1 = force allow, 2 = force deny. This
    # overrides the per-user Consent Store entirely, including any stale
    # "Deny" left over in a user's own profile.
    $appPrivacyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    if (-not (Test-Path $appPrivacyPath)) { New-Item -Path $appPrivacyPath -Force | Out-Null }
    New-ItemProperty -Path $appPrivacyPath -Name "LetAppsAccessCamera" -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $appPrivacyPath -Name "LetAppsAccessMicrophone" -PropertyType DWord -Value 1 -Force | Out-Null

    # Also set the underlying Consent Store directly at the machine level -
    # belt-and-suspenders alongside the policy above, and what the Settings
    # app itself reads/displays.
    foreach ($capability in @("webcam", "microphone")) {
        $consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$capability"
        if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
        New-ItemProperty -Path $consentPath -Name "Value" -PropertyType String -Value "Allow" -Force | Out-Null

        # "NonPackaged" = the "Let desktop apps access your camera/mic"
        # sub-toggle, specifically relevant for classic Win32 apps.
        $nonPackagedPath = "$consentPath\NonPackaged"
        if (-not (Test-Path $nonPackagedPath)) { New-Item -Path $nonPackagedPath -Force | Out-Null }
        New-ItemProperty -Path $nonPackagedPath -Name "Value" -PropertyType String -Value "Allow" -Force | Out-Null
    }

    Write-Host "  Camera and microphone access allowed at the OS level (policy + Consent Store, incl. desktop apps)." -ForegroundColor Green

    # Ensure the Windows Camera Frame Server (and its monitor companion
    # service) are set to Automatic and actually running. This is a
    # well-documented single point of failure: on some hardware/driver
    # combinations, the Frame Server doesn't bind properly to the camera on
    # a cold boot until SOME app has successfully opened the camera once -
    # after that, it works for every app, including Edge. Forcing the
    # service to Automatic/Started here reduces (though may not eliminate)
    # the chance of this "first open fails" behavior on first boot.
    foreach ($svcName in @("FrameServer", "FrameServerMonitor")) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            try {
                Set-Service -Name $svcName -StartupType Automatic -ErrorAction Stop
                if ($svc.Status -ne "Running") {
                    Start-Service -Name $svcName -ErrorAction SilentlyContinue
                }
                Write-Host "  $svcName set to Automatic and running." -ForegroundColor Green
            } catch {
                Write-Host "  WARNING: Could not configure ${svcName}: $_" -ForegroundColor Red
            }
        }
    }

    # Best-effort "warm up" of the camera driver via the WinRT MediaCapture
    # API - automates what was found to reliably fix camera access in the
    # field: opening the camera once in VIDEO streaming mode (not just a
    # still-photo capture) properly initializes the driver/Frame Server
    # pipeline on some hardware. This briefly initializes a video capture
    # session and disposes it immediately - no UI, no visible window.
    # Wrapped so any failure here is non-fatal; this is a best-effort
    # mitigation for a driver quirk, not something the script depends on.
    try {
        Write-Host "  Warming up the camera driver via a brief video capture session..." -ForegroundColor Yellow

        Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop

        Function Await($WinRtTask) {
            $asTaskMethod = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
                $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction'
            })[0]
            $netTask = $asTaskMethod.Invoke($null, @($WinRtTask))
            $netTask.Wait(5000) | Out-Null
        }

        [Windows.Media.Capture.MediaCapture, Windows.Media.Capture, ContentType = WindowsRuntime] | Out-Null
        $mediaCapture = New-Object Windows.Media.Capture.MediaCapture
        Await ($mediaCapture.InitializeAsync())
        Start-Sleep -Milliseconds 1500
        $mediaCapture.Dispose()

        Write-Host "  Camera warm-up completed." -ForegroundColor Green
    } catch {
        Write-Host "  NOTE: Camera warm-up via MediaCapture did not succeed (non-fatal): $_" -ForegroundColor DarkYellow
        Write-Host "  If the camera still doesn't work in Edge after this, opening the native Camera app once" -ForegroundColor DarkYellow
        Write-Host "  manually (and switching it to video mode) is the confirmed fallback." -ForegroundColor DarkYellow
    }
}

$CAMERA_MIC_USER_ACTION = {
    param($Root)
    # A stale per-user "Deny" can override even a machine-wide "Allow" -
    # explicitly clear/set the per-user Consent Store too instead of
    # relying on the machine-wide policy alone.
    foreach ($capability in @("webcam", "microphone")) {
        $consentPath = "$Root\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$capability"
        if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
        New-ItemProperty -Path $consentPath -Name "Value" -PropertyType String -Value "Allow" -Force | Out-Null

        $nonPackagedPath = "$consentPath\NonPackaged"
        if (-not (Test-Path $nonPackagedPath)) { New-Item -Path $nonPackagedPath -Force | Out-Null }
        New-ItemProperty -Path $nonPackagedPath -Name "Value" -PropertyType String -Value "Allow" -Force | Out-Null
    }
}

# ============================================================
# 3. WALLPAPER / LOCK SCREEN
# ============================================================
function Set-KioskWallpaper {
    Write-Host "`n[3/13] Setting desktop and lock screen wallpaper..." -ForegroundColor Yellow

    try {
        Invoke-KioskWebDownload -Uri $WallpaperUrl -OutFile $WallpaperLocalPath
    } catch {
        Write-Host "  ERROR: Wallpaper could not be downloaded: $_" -ForegroundColor Red
        return
    }

    # NOTE: HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization is the
    # classic domain-GPO path and is not reliably enforced for all users
    # outside an AD domain. The path actually used (and confirmed working)
    # by Intune/MDM/local scripts is PersonalizationCSP under CurrentVersion
    # (not under Policies).
    $persPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
    New-Item -Path $persPath -Force | Out-Null

    New-ItemProperty -Path $persPath -Name "DesktopImagePath"   -PropertyType String -Value $WallpaperLocalPath -Force | Out-Null
    New-ItemProperty -Path $persPath -Name "DesktopImageUrl"    -PropertyType String -Value $WallpaperLocalPath -Force | Out-Null
    New-ItemProperty -Path $persPath -Name "DesktopImageStatus" -PropertyType DWord  -Value 1 -Force | Out-Null

    New-ItemProperty -Path $persPath -Name "LockScreenImagePath"   -PropertyType String -Value $WallpaperLocalPath -Force | Out-Null
    New-ItemProperty -Path $persPath -Name "LockScreenImageUrl"    -PropertyType String -Value $WallpaperLocalPath -Force | Out-Null
    New-ItemProperty -Path $persPath -Name "LockScreenImageStatus" -PropertyType DWord  -Value 1 -Force | Out-Null

    # Tell Windows to re-read the changed system parameters immediately for
    # all active sessions instead of waiting for the next restart (still
    # reliably takes full effect only after a re-logon).
    try {
        rundll32.exe user32.dll,UpdatePerUserSystemParameters 1, $true
    } catch {
        Write-Host "  Note: Immediate refresh via rundll32 not possible, re-logon/restart required." -ForegroundColor DarkYellow
    }

    Write-Host "  Image stored locally at $WallpaperLocalPath and set via PersonalizationCSP (applies to all users)." -ForegroundColor Green
    Write-Host "  Note: Full effect usually only after re-logon/restart." -ForegroundColor DarkYellow
}

# ============================================================
# 4. HELPER FUNCTION: run an action against all user hives (incl. Default)
# ============================================================
function Invoke-ForAllUserHives {
    param(
        [ScriptBlock]$Action,
        # Optional: only these usernames (e.g. "Kiosk") instead of all
        # profiles. IMPORTANT: when this is specified, the Default profile
        # is deliberately NOT touched (see below) - a targeted call like
        # this is meant to affect exactly the named account(s), nothing
        # else, now or in the future.
        [string[]]$OnlyUserNames = $null
    )

    $ProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $profileKeys = Get-ChildItem $ProfileListPath | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

    $hiveTargets = @()
    foreach ($p in $profileKeys) {
        $sid = $p.PSChildName
        $profilePath = (Get-ItemProperty $p.PSPath).ProfileImagePath
        $profileUserName = Split-Path $profilePath -Leaf
        if ($OnlyUserNames -and ($OnlyUserNames -notcontains $profileUserName)) { continue }
        $ntUserPath = Join-Path $profilePath "NTUSER.DAT"
        if (Test-Path $ntUserPath) {
            $hiveTargets += [PSCustomObject]@{ SID = $sid; Path = $ntUserPath }
        }
    }
    # Default profile = template for future/new users (incl. newly created
    # Assigned Access users) - only added for the "apply to everyone" mode
    # (no -OnlyUserNames given). Previously this was added unconditionally,
    # which was a bug: a targeted call like the Kiosk-only Edge domain
    # restriction ended up also writing into the Default profile, meaning
    # ANY future/recreated account (e.g. "Maintenance" if its profile ever
    # got reset) would silently inherit a restriction that was only ever
    # meant for "Kiosk".
    if (-not $OnlyUserNames) {
        $hiveTargets += [PSCustomObject]@{ SID = "DefaultUser"; Path = "C:\Users\Default\NTUSER.DAT" }
    }

    foreach ($target in $hiveTargets) {
        $safeName = ($target.SID -replace '[^a-zA-Z0-9]', '_')
        $mountKey = "TempHive_$safeName"
        $alreadyLoaded = Test-Path "Registry::HKEY_USERS\$($target.SID)"

        if ($alreadyLoaded) {
            $regRoot = "Registry::HKEY_USERS\$($target.SID)"
        } else {
            $loadResult = reg load "HKU\$mountKey" "$($target.Path)" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  WARNING: Could not load hive: $($target.Path) ($loadResult)" -ForegroundColor Red
                continue
            }
            $regRoot = "Registry::HKEY_USERS\$mountKey"
        }

        try {
            & $Action $regRoot
            Write-Host "  OK: $($target.SID)" -ForegroundColor Green
        } catch {
            Write-Host "  ERROR for $($target.SID): $_" -ForegroundColor Red
        } finally {
            if (-not $alreadyLoaded) {
                [gc]::Collect()
                [gc]::WaitForPendingFinalizers()
                Start-Sleep -Milliseconds 300
                reg unload "HKU\$mountKey" 2>&1 | Out-Null
            }
        }
    }
}

# ============================================================
# 4a. EDGE DOMAIN RESTRICTION - ONLY FOR "Kiosk" (not "Maintenance")
# ============================================================
# HKCU variant of the Edge policies instead of HKLM: applies only to the
# respective user profile. This keeps "Maintenance" free to browse without
# restrictions for support/updates; only "Kiosk" gets the domain
# restriction. Deliberately NOT applied to the Default profile (see the fix
# note on Invoke-ForAllUserHives) - the restriction should only ever affect
# an account literally named "Kiosk", not silently propagate to any other
# future or recreated account on this device.
$KIOSK_EDGE_DOMAIN_ACTION = {
    param($Root)

    $edgePolicyPath = "$Root\Software\Policies\Microsoft\Edge"
    if (-not (Test-Path $edgePolicyPath)) { New-Item -Path $edgePolicyPath -Force | Out-Null }

    # Block everything...
    $blockPath = "$edgePolicyPath\URLBlocklist"
    if (-not (Test-Path $blockPath)) { New-Item -Path $blockPath -Force | Out-Null }
    New-ItemProperty -Path $blockPath -Name "1" -PropertyType String -Value "*" -Force | Out-Null

    # ...except the allowed domains (Chromium syntax: an entry without a
    # leading dot/wildcard automatically also allows all subdomains)
    $allowPath = "$edgePolicyPath\URLAllowlist"
    if (-not (Test-Path $allowPath)) { New-Item -Path $allowPath -Force | Out-Null }
    Get-Item $allowPath | Select-Object -ExpandProperty Property | ForEach-Object {
        Remove-ItemProperty -Path $allowPath -Name $_ -ErrorAction SilentlyContinue
    }

    $i = 1
    foreach ($domain in $AllowedDomains) {
        New-ItemProperty -Path $allowPath -Name "$i" -PropertyType String -Value $domain -Force | Out-Null
        $i++
    }
}

# Cleanup companion: removes the per-user Edge domain restriction from a
# profile, in case an earlier buggy script run applied it somewhere it
# shouldn't have (e.g. "Maintenance" or the Default profile - see the fix
# note on Invoke-ForAllUserHives above). Run broadly (no -OnlyUserNames)
# BEFORE re-applying $KIOSK_EDGE_DOMAIN_ACTION to "Kiosk" only, so any
# previously leaked restriction gets undone first.
$CLEANUP_STRAY_EDGE_DOMAIN_ACTION = {
    param($Root)
    $edgePolicyPath = "$Root\Software\Policies\Microsoft\Edge"
    Remove-Item -Path "$edgePolicyPath\URLBlocklist" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$edgePolicyPath\URLAllowlist" -Recurse -Force -ErrorAction SilentlyContinue
}

# ============================================================
# 4b. EDGE-SWIPE GESTURES (correctly ADMX-bound "Edge UI" policy, Windows 10/11)
# ============================================================
function Set-EdgeUiSwipePolicy {
    Write-Host "`n[4/13] Disabling edge-swipe gestures via the Group Policy path..." -ForegroundColor Yellow

    # Computer Configuration > Administrative Templates > Windows Components > Edge UI
    $euiPathHKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI"
    New-Item -Path $euiPathHKLM -Force | Out-Null
    # "Disable swiping from screen edges" = Enabled
    New-ItemProperty -Path $euiPathHKLM -Name "AllowEdgeSwipe" -PropertyType DWord -Value 0 -Force | Out-Null
    # "Disable help tips" = Enabled
    New-ItemProperty -Path $euiPathHKLM -Name "DisableHelpSticker" -PropertyType DWord -Value 1 -Force | Out-Null

    # Also set as a user policy (the same ADMX path also exists under User
    # Configuration) - here for HKCU of the currently executing context;
    # applied to other/future profiles via Invoke-ForAllUserHives below.
    $euiPathHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI"
    New-Item -Path $euiPathHKCU -Force | Out-Null
    New-ItemProperty -Path $euiPathHKCU -Name "AllowEdgeSwipe" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $euiPathHKCU -Name "DisableHelpSticker" -PropertyType DWord -Value 1 -Force | Out-Null

    Write-Host "  AllowEdgeSwipe=0 / DisableHelpSticker=1 set under Policies\Microsoft\Windows\EdgeUI." -ForegroundColor Green
    Write-Host "  Verify via gpedit.msc: Computer/User Config > Admin Templates > Windows Components > Edge UI." -ForegroundColor DarkYellow
}

$EDGEUI_USER_ACTION = {
    param($Root)
    $euiPath = "$Root\Software\Policies\Microsoft\Windows\EdgeUI"
    New-Item -Path $euiPath -Force | Out-Null
    New-ItemProperty -Path $euiPath -Name "AllowEdgeSwipe" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $euiPath -Name "DisableHelpSticker" -PropertyType DWord -Value 1 -Force | Out-Null
}

# ============================================================
# 5a. TOUCH/SWIPE GESTURES (Precision Touchpad multi-finger)
# ============================================================
$GESTURE_ACTION = {
    param($Root)

    # NOTE: "ImmersiveShell\EdgeUi" (Charms bar era, Windows 8.1) removed -
    # this mechanism no longer exists since Windows 10 and is NOT bound to
    # the GPO template. The correct, ADMX-bound path for Windows 10/11
    # ("Edge UI" under Windows Components) is instead set below as its own
    # machine policy in Set-EdgeUiSwipePolicy.

    # Precision Touchpad multi-finger gestures (2/3/4 finger, pan/zoom/rotate) - affects trackpads
    $ptpPath = "$Root\Software\Microsoft\Windows\CurrentVersion\PrecisionTouchPad"
    New-Item -Path $ptpPath -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "ThreeFingerSlideEnabled" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "FourFingerSlideEnabled"  -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "ThreeFingerTapEnabled"   -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "FourFingerTapEnabled"    -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "PanningEnabled"          -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "ZoomEnabled"             -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "RotationEnabled"         -PropertyType DWord -Value 0 -Force | Out-Null

    # REAL touchscreen 3/4-finger gestures (not trackpad!) - corresponds to
    # the toggle under Settings > Bluetooth & devices > Touch > "Three- and
    # four-finger touch gestures". PrecisionTouchPad above ONLY affects
    # trackpads, not a touchscreen kiosk like yours - this key is the
    # confirmed counterpart responsible for touchscreens.
    $desktopPath = "$Root\Control Panel\Desktop"
    if (-not (Test-Path $desktopPath)) { New-Item -Path $desktopPath -Force | Out-Null }
    New-ItemProperty -Path $desktopPath -Name "TouchGestureSetting" -PropertyType DWord -Value 0 -Force | Out-Null

    # NOTE on two-finger pinch-to-zoom on the touchscreen: there is NO
    # officially supported, global Windows switch for this (explicitly
    # confirmed by Microsoft for Windows 11 IoT Enterprise - see
    # https://learn.microsoft.com/answers/questions/5809027). The only
    # practical way for a pure Edge kiosk is the Chromium startup flag
    # "--disable-pinch" when launching Edge in Assigned Access - that
    # belongs in your kiosk launch configuration, not in this
    # registry-based hardening script.
}

# ============================================================
# 5b. TOUCH KEYBOARD (TabletTip)
# ============================================================
$TOUCH_KEYBOARD_ACTION = {
    param($Root)

    $tipPath = "$Root\Software\Microsoft\TabletTip\1.7"
    New-Item -Path $tipPath -Force | Out-Null

    # NO-KEYBOARD VARIANT: touch keyboard should never appear, so
    # auto-invoke is explicitly disabled here (0), not enabled.
    New-ItemProperty -Path $tipPath -Name "EnableDesktopModeAutoInvoke" -PropertyType DWord -Value 0 -Force | Out-Null

    # NO-KEYBOARD VARIANT: 0 = "Never" for the three-way setting (Never /
    # When no keyboard attached / Always) introduced in Windows 11 build
    # 22621.1926+. Ensures the touch keyboard is suppressed even by the
    # newer tap-to-invoke mechanism, not just the older auto-invoke setting.
    New-ItemProperty -Path $tipPath -Name "TouchKeyboardTapInvoke" -PropertyType DWord -Value 0 -Force | Out-Null

    # TipbandDesiredVisibility is irrelevant if the keyboard never invokes
    # in the first place, but left at 0 for consistency/no ambiguity.
    New-ItemProperty -Path $tipPath -Name "TipbandDesiredVisibility" -PropertyType DWord -Value 0 -Force | Out-Null

    # Left Ctrl key: NO registry key for this (see research note) - handled
    # reliably via AutoHotkey instead, see Install-KioskAutoHotkey further
    # below.
}

# ============================================================
# 5c. TOUCH KEYBOARD - MACHINE-WIDE DEFAULT (HKLM)
# ============================================================
# NO-KEYBOARD VARIANT: same settings as the per-user action above, also
# applied machine-wide for consistency (mirrors the "keyboard shows" variant's
# structure, just with the values inverted to suppress the keyboard).
function Set-KioskTouchKeyboardMachineDefaults {
    Write-Host "`n[8b/13] Setting machine-wide touch keyboard defaults (HKLM)..." -ForegroundColor Yellow
    $tipPathHKLM = "HKLM:\SOFTWARE\Microsoft\TabletTip\1.7"
    if (-not (Test-Path $tipPathHKLM)) { New-Item -Path $tipPathHKLM -Force | Out-Null }
    New-ItemProperty -Path $tipPathHKLM -Name "EnableDesktopModeAutoInvoke" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $tipPathHKLM -Name "TouchKeyboardTapInvoke" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $tipPathHKLM -Name "TipbandDesiredVisibility" -PropertyType DWord -Value 0 -Force | Out-Null
    Write-Host "  Machine-wide touch keyboard defaults set (keyboard suppressed)." -ForegroundColor Green
}

# ============================================================
# 5d. TOUCH KEYBOARD SERVICE (TabletInputService)
# ============================================================
# NO-KEYBOARD VARIANT: disable the service instead of enabling it, as an
# extra layer of assurance on top of the registry settings above (belt and
# suspenders - some builds still rely on this service under the hood even
# where Microsoft has deprecated it in favor of TextInputHost.exe).
function Enable-KioskTouchKeyboardService {
    Write-Host "`n[8c/13] Disabling TabletInputService (touch keyboard service)..." -ForegroundColor Yellow

    $svc = Get-Service -Name TabletInputService -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "  NOTE: TabletInputService is not present on this device/image - nothing to disable, which is fine for this variant." -ForegroundColor DarkYellow
        return
    }

    try {
        Stop-Service -Name TabletInputService -Force -ErrorAction SilentlyContinue
        Set-Service -Name TabletInputService -StartupType Disabled -ErrorAction Stop
        Write-Host "  TabletInputService stopped and set to Disabled." -ForegroundColor Green
    } catch {
        Write-Host "  WARNING: TabletInputService could not be configured: $_" -ForegroundColor Red
    }
}

# ============================================================
# 6. LOCAL USERS "Maintenance" (admin) and "Kiosk" (standard) + profile pictures
# ============================================================
$Global:CreatedUserCredentials = @()

function Set-KioskFolderFullControl {
    param([Parameter(Mandatory)][string]$FolderPath)
    # Explicitly grant Administrators and SYSTEM Full Control instead of
    # relying on inherited ACLs from the parent folder - some Windows 11
    # images/baselines apply a more restrictive default ACL to
    # C:\Users\Public than Windows 10 does, which causes plain "access
    # denied" (not Controlled Folder Access) on newly created subfolders.
    try {
        icacls $FolderPath /grant "*S-1-5-32-544:(OI)(CI)F" /grant "*S-1-5-18:(OI)(CI)F" /T /C *>$null
    } catch {
        # Non-fatal - the write test right after this call will catch it if
        # permissions are still insufficient.
    }
}

function Enable-KioskTakeOwnershipPrivilege {
    # Enables SeTakeOwnershipPrivilege/SeRestorePrivilege/SeBackupPrivilege
    # on the current process token via P/Invoke. Required to take ownership
    # of a registry key that Administrators don't already own (e.g. a key
    # owned by TrustedInstaller on a hardened Windows 11 baseline) - without
    # this, ChangePermissions/SetAccessControl silently has no effect even
    # when run elevated.
    if (-not ("KioskTokenPriv.TokenPriv" -as [type])) {
        Add-Type -Name TokenPriv -Namespace KioskTokenPriv -MemberDefinition @"
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
[StructLayout(LayoutKind.Sequential)]
public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public long Luid; public uint Attributes; }
public static bool EnablePrivilege(string privilege) {
    IntPtr hToken;
    if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out hToken)) return false;
    long luid;
    if (!LookupPrivilegeValue(null, privilege, out luid)) return false;
    TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
    tp.PrivilegeCount = 1;
    tp.Luid = luid;
    tp.Attributes = 0x00000002;
    return AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
}
"@ -ErrorAction Stop
    }
    [void][KioskTokenPriv.TokenPriv]::EnablePrivilege("SeTakeOwnershipPrivilege")
    [void][KioskTokenPriv.TokenPriv]::EnablePrivilege("SeRestorePrivilege")
    [void][KioskTokenPriv.TokenPriv]::EnablePrivilege("SeBackupPrivilege")
}

function Set-KioskRegistryKeyFullControl {
    param([Parameter(Mandatory)][string]$RegistryPath)
    # Same idea as Set-KioskFolderFullControl, but for a registry key.
    # Some hardened Windows 11 baselines restrict
    # HKLM\...\AccountPicture\Users to read-only, even for Administrators -
    # "Create Subkey" can succeed while "Set Value" on that subkey is still
    # denied, which is exactly what produces this error.

    # Step 1: take ownership first. If Administrators don't own the key
    # (e.g. it's owned by TrustedInstaller), granting ACL rules as
    # Administrator has no effect even when run elevated - ownership must
    # change before permissions can be changed.
    try {
        Enable-KioskTakeOwnershipPrivilege
        $subKeyPath = $RegistryPath -replace '^HKLM:\\', ''
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            $subKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::TakeOwnership -bor [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        if ($key) {
            $ownerAcl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner)
            $adminsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
            $ownerAcl.SetOwner($adminsSid)
            $key.SetAccessControl($ownerAcl)
            $key.Close()
        }
    } catch {
        Write-Host "    DEBUG: Could not take ownership of '$RegistryPath': $_" -ForegroundColor DarkYellow
    }

    # Step 2: now grant Administrators/SYSTEM Full Control
    try {
        $acl = Get-Acl -Path $RegistryPath
        foreach ($sid in @("S-1-5-32-544", "S-1-5-18")) {
            $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
                $identity, "FullControl", "ContainerInherit", "None", "Allow")
            $acl.SetAccessRule($rule)
        }
        Set-Acl -Path $RegistryPath -AclObject $acl -ErrorAction Stop
    } catch {
        Write-Host "    DEBUG: Could not grant ACL on '$RegistryPath': $_" -ForegroundColor DarkYellow
    }
}

function Set-UserAccountPicture {
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$ImageUrl
    )

    $user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "  WARNING: User '$UserName' not found, skipping profile picture." -ForegroundColor Red
        return
    }
    $sid = $user.SID.Value

    $tempImage = Join-Path $env:TEMP "$UserName-src.png"
    try {
        Invoke-KioskWebDownload -Uri $ImageUrl -OutFile $tempImage
    } catch {
        Write-Host "  WARNING: Profile picture for '$UserName' could not be downloaded: $_" -ForegroundColor Red
        return
    }

    # Validation: is the downloaded file actually a format supported by
    # GDI+? (Safety net in case of a 404 page or similar.)
    $fileBytes = [System.IO.File]::ReadAllBytes($tempImage)
    $isPng  = $fileBytes.Length -ge 8 -and $fileBytes[0] -eq 0x89 -and $fileBytes[1] -eq 0x50 -and $fileBytes[2] -eq 0x4E -and $fileBytes[3] -eq 0x47
    $isJpeg = $fileBytes.Length -ge 3 -and $fileBytes[0] -eq 0xFF -and $fileBytes[1] -eq 0xD8
    $isGif  = $fileBytes.Length -ge 6 -and $fileBytes[0] -eq 0x47 -and $fileBytes[1] -eq 0x49 -and $fileBytes[2] -eq 0x46

    if (-not ($isPng -or $isJpeg -or $isGif)) {
        Write-Host "  WARNING: The URL for '$UserName' did not return a valid image (size: $($fileBytes.Length) bytes)." -ForegroundColor Red
        Write-Host "  URL: $ImageUrl" -ForegroundColor Red
        Remove-Item $tempImage -Force -ErrorAction SilentlyContinue
        return
    }

    try {
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    } catch {
        Write-Host "  WARNING: System.Drawing not available - profile picture will only be copied as-is, without resizing." -ForegroundColor Red
        $destFolder = "C:\ProgramData\KioskConfig\AccountPictures\$sid"
        New-Item -Path $destFolder -ItemType Directory -Force | Out-Null
        Set-KioskFolderFullControl -FolderPath $destFolder
        $destFile = Join-Path $destFolder "Image192.jpg"
        Copy-Item $tempImage $destFile -Force
        $picPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users\$sid"
        if (-not (Test-Path $picPath)) { New-Item -Path $picPath -Force | Out-Null }
        Set-KioskRegistryKeyFullControl -RegistryPath $picPath
        New-ItemProperty -Path $picPath -Name "Image192" -PropertyType String -Value $destFile -Force | Out-Null
        Remove-Item $tempImage -Force -ErrorAction SilentlyContinue
        return
    }

    $destFolder = "C:\ProgramData\KioskConfig\AccountPictures\$sid"
    New-Item -Path $destFolder -ItemType Directory -Force | Out-Null
    Set-KioskFolderFullControl -FolderPath $destFolder

    # Verify the destination folder is actually writable before attempting
    # any saves - Bitmap.Save() throws the generic, unhelpful GDI+ "generic
    # error" for a folder that doesn't exist or isn't writable, instead of a
    # clear permissions/path error. Catching that here up front gives a much
    # more actionable message than letting it fail deep inside the loop.
    try {
        $writeTestFile = Join-Path $destFolder ".writetest"
        [System.IO.File]::WriteAllText($writeTestFile, "test")
        Remove-Item $writeTestFile -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  WARNING: Destination folder '$destFolder' is not writable even after explicitly granting Administrators/SYSTEM full control - skipping profile picture for '$UserName'." -ForegroundColor Red
        Write-Host "  Underlying error: $_" -ForegroundColor Red

        # Diagnose Controlled Folder Access status directly instead of just
        # pointing at the Settings UI - ACL grants have no effect against
        # CFA, since it blocks by process reputation above the ACL layer.
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            if ($mpPref.EnableControlledFolderAccess -eq 1) {
                Write-Host "  DIAGNOSIS: Controlled Folder Access is ENABLED on this device - this is very likely the cause," -ForegroundColor Red
                Write-Host "  since it blocks writes by process reputation regardless of NTFS permissions. Either add an exclusion" -ForegroundColor Red
                Write-Host "  for powershell.exe, or add '$(Split-Path $destFolder)' as an allowed folder." -ForegroundColor Red
            } else {
                Write-Host "  DIAGNOSIS: Controlled Folder Access is NOT enabled - the cause is something else (e.g. a third-party" -ForegroundColor Red
                Write-Host "  AV/EDR agent, or a custom security baseline applied to this device)." -ForegroundColor Red
            }
        } catch {
            Write-Host "  Could not query Controlled Folder Access status (Get-MpPreference unavailable)." -ForegroundColor DarkYellow
        }

        Remove-Item $tempImage -Force -ErrorAction SilentlyContinue
        return
    }

    $picPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users\$sid"
    if (-not (Test-Path $picPath)) { New-Item -Path $picPath -Force | Out-Null }
    Set-KioskRegistryKeyFullControl -RegistryPath $picPath

    # Single up-front test instead of discovering the same "access denied"
    # seven times over (once per image size). If this registry key is
    # locked down by a security policy that even Administrator-level
    # ownership/ACL changes can't override, that's a policy decision on
    # this device, not something fixable from within this script - skip
    # the profile picture cleanly and move on with one clear message.
    try {
        New-ItemProperty -Path $picPath -Name "Image32" -PropertyType String -Value "test" -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "  NOTE: '$picPath' is locked by a security policy that even Administrator ownership/ACL changes cannot override." -ForegroundColor DarkYellow
        Write-Host "  Skipping the profile picture for '$UserName' - this is a policy decision on this device, not something this script can work around." -ForegroundColor DarkYellow
        Write-Host "  If you want this resolved, check with whoever manages the Windows 11 security baseline about an exception for this registry path." -ForegroundColor DarkYellow
        Remove-Item $tempImage -Force -ErrorAction SilentlyContinue
        return
    }

    $sizes = 32, 40, 48, 96, 192, 240, 448
    try {
        # Load from a MemoryStream instead of Image.FromFile(): FromFile()
        # keeps a lock on the source file for the lifetime of the Image
        # object, which is a well-documented cause of the generic
        # "A generic error occurred in GDI+" exception on later operations.
        $imageBytes = [System.IO.File]::ReadAllBytes($tempImage)
        $memStream = New-Object System.IO.MemoryStream(,$imageBytes)
        $srcImage = [System.Drawing.Image]::FromStream($memStream)
    } catch {
        Write-Host "  WARNING: Image file for '$UserName' could not be loaded by GDI+: $_" -ForegroundColor Red
        Remove-Item $tempImage -Force -ErrorAction SilentlyContinue
        return
    }

    $successCount = 0
    foreach ($size in $sizes) {
        try {
            $destFile = Join-Path $destFolder "Image$size.jpg"
            $bmp = New-Object System.Drawing.Bitmap $size, $size
            $graphics = [System.Drawing.Graphics]::FromImage($bmp)
            $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $graphics.DrawImage($srcImage, 0, 0, $size, $size)
            $bmp.Save($destFile, [System.Drawing.Imaging.ImageFormat]::Jpeg)
            $graphics.Dispose()
            $bmp.Dispose()
            New-ItemProperty -Path $picPath -Name "Image$size" -PropertyType String -Value $destFile -Force | Out-Null
            $successCount++
        } catch {
            Write-Host "  WARNING: Could not save size ${size}px for '$UserName': $_" -ForegroundColor Red
        }
    }
    $srcImage.Dispose()
    $memStream.Dispose()
    Remove-Item $tempImage -Force -ErrorAction SilentlyContinue

    if ($successCount -gt 0) {
        Write-Host "  Profile picture for '$UserName' (SID $sid) set in $successCount of $($sizes.Count) sizes." -ForegroundColor Green
    } else {
        Write-Host "  WARNING: Profile picture for '$UserName' could not be set in any size." -ForegroundColor Red
    }
}

function Set-KioskLocalUsers {
    Write-Host "`n[9/13] Checking/creating local users 'Maintenance' and 'Kiosk'..." -ForegroundColor Yellow

    # Well-known SIDs instead of localized group names (works regardless of
    # language version: "Administrators"/"Administratoren" etc.)
    $adminGroup = Get-LocalGroup | Where-Object { $_.SID -eq "S-1-5-32-544" }
    $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq "S-1-5-32-545" }

    $userDefs = @(
        @{ Name = "Maintenance"; IsAdmin = $true;  PicUrl = $MaintenancePicUrl; Password = $MaintenancePasswordPlain },
        @{ Name = "Kiosk";       IsAdmin = $false; PicUrl = $KioskPicUrl;       Password = $null }
    )

    foreach ($u in $userDefs) {
        $existing = Get-LocalUser -Name $u.Name -ErrorAction SilentlyContinue

        if ($existing) {
            Write-Host "  User '$($u.Name)' already exists - skipping creation." -ForegroundColor Green

            # Ensure PasswordNeverExpires on every run (even for already
            # existing accounts) - relevant especially for "Kiosk" without a
            # password, since Windows would otherwise eventually require a
            # password change under the normal password expiration policy.
            try {
                Set-LocalUser -Name $u.Name -PasswordNeverExpires $true -ErrorAction Stop
            } catch {
                Write-Host "  WARNING: Could not set PasswordNeverExpires for '$($u.Name)': $_" -ForegroundColor Red
            }
        } else {
            try {
                if ($null -eq $u.Password) {
                    # No password - typically also requires the security policy
                    # "Accounts: Limit local account use of blank passwords to
                    # console logon only" to be set, see note at the end of the
                    # script.
                    #
                    # IMPORTANT: -PasswordNeverExpires is deliberately NOT
                    # combined with -NoPassword in the same New-LocalUser call.
                    # On some Windows 10 IoT builds/PowerShell versions this
                    # combination fails with "the parameter set cannot be
                    # resolved" (a parameter-set conflict in the cmdlet on
                    # that specific build) - setting it afterward via
                    # Set-LocalUser instead avoids that entirely and works
                    # everywhere.
                    New-LocalUser -Name $u.Name -NoPassword -FullName $u.Name `
                        -AccountNeverExpires -ErrorAction Stop | Out-Null
                } else {
                    $securePwd = ConvertTo-SecureString $u.Password -AsPlainText -Force
                    New-LocalUser -Name $u.Name -Password $securePwd -FullName $u.Name `
                        -AccountNeverExpires -ErrorAction Stop | Out-Null
                }
                Set-LocalUser -Name $u.Name -PasswordNeverExpires $true -ErrorAction Stop
            } catch {
                # Explicitly caught (rather than letting it terminate the whole
                # script via the global $ErrorActionPreference = 'Stop') so a
                # single failed account creation can't silently leave later
                # steps (e.g. auto-logon) acting as if the account exists when
                # it doesn't.
                Write-Host "  ERROR: Could not create user '$($u.Name)': $_" -ForegroundColor Red
                Write-Host "  Skipping group membership, profile picture, and (later) auto-logon for '$($u.Name)'." -ForegroundColor Red
                continue
            }

            # Verify the account actually exists now instead of trusting the
            # cmdlet's reported success - guards against edge cases where
            # New-LocalUser returns without a terminating error but the
            # account doesn't end up present (e.g. a leftover SAM/profile
            # conflict from an earlier interrupted run on this device).
            $verify = Get-LocalUser -Name $u.Name -ErrorAction SilentlyContinue
            if (-not $verify) {
                Write-Host "  ERROR: User '$($u.Name)' was not found after creation - something went wrong that didn't throw a normal error." -ForegroundColor Red
                Write-Host "  Skipping group membership, profile picture, and (later) auto-logon for '$($u.Name)'." -ForegroundColor Red
                continue
            }

            if ($u.IsAdmin) {
                Add-LocalGroupMember -Group $adminGroup -Member $u.Name -ErrorAction SilentlyContinue
            } else {
                # New-LocalUser already adds new accounts to the "Users"
                # group by default; ensured explicitly here just in case.
                Add-LocalGroupMember -Group $usersGroup -Member $u.Name -ErrorAction SilentlyContinue
            }

            if ($u.Password) {
                $Global:CreatedUserCredentials += [PSCustomObject]@{ User = $u.Name; Password = $u.Password }
            } else {
                $Global:CreatedUserCredentials += [PSCustomObject]@{ User = $u.Name; Password = "(no password / blank password)" }
            }
            Write-Host "  User '$($u.Name)' created ($(if ($u.IsAdmin) {'Administrator'} else {'Standard'}))." -ForegroundColor Green
        }

        # Set the profile picture regardless of whether the account was newly created or already existed
        Set-UserAccountPicture -UserName $u.Name -ImageUrl $u.PicUrl
    }
}

# ============================================================
# 7. AUTO-LOGON FOR "Kiosk"
# ============================================================
function Set-KioskAutoLogon {
    Write-Host "`n[10/13] Configuring auto-logon for 'Kiosk'..." -ForegroundColor Yellow

    $kioskUser = Get-LocalUser -Name "Kiosk" -ErrorAction SilentlyContinue
    if (-not $kioskUser) {
        Write-Host "  WARNING: User 'Kiosk' not found - skipping auto-logon setup." -ForegroundColor Red

        # Actively clean up any stale auto-logon configuration left over
        # from an earlier successful run on this device (e.g. if "Kiosk"
        # got created and configured before, then was later removed).
        # Without this, Windows would still try to auto-logon as "Kiosk" at
        # every boot based on the old registry values, even though this
        # run correctly determined the account doesn't exist.
        $winlogonPathCleanup = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        if (Test-Path $winlogonPathCleanup) {
            $currentDefaultUser = (Get-ItemProperty -Path $winlogonPathCleanup -Name "DefaultUserName" -ErrorAction SilentlyContinue).DefaultUserName
            if ($currentDefaultUser -eq "Kiosk") {
                Write-Host "  Found stale auto-logon configuration for 'Kiosk' from an earlier run - clearing it." -ForegroundColor DarkYellow
                Set-ItemProperty -Path $winlogonPathCleanup -Name "AutoAdminLogon" -Value "0" -Force -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $winlogonPathCleanup -Name "DefaultPassword" -ErrorAction SilentlyContinue
            }
        }
        return
    }

    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    # No "-Force" on an already existing system key like Winlogon:
    # New-Item -Force internally tries to delete and recreate the key,
    # which fails on this key with "Cannot delete a subkey tree...".
    # The key already exists on every Windows system anyway.
    if (-not (Test-Path $winlogonPath)) {
        New-Item -Path $winlogonPath -Force | Out-Null
    }

    New-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon"    -PropertyType String -Value "1" -Force | Out-Null
    New-ItemProperty -Path $winlogonPath -Name "DefaultUserName"   -PropertyType String -Value "Kiosk" -Force | Out-Null
    New-ItemProperty -Path $winlogonPath -Name "DefaultDomainName" -PropertyType String -Value $env:COMPUTERNAME -Force | Out-Null

    # "Kiosk" has no password -> deliberately leave DefaultPassword blank.
    # Auto-logon via Winlogon counts as a local console logon and is
    # therefore covered by the "blank passwords only at the console" policy.
    New-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -PropertyType String -Value "" -Force | Out-Null

    # Remove any previous logon attempt counter left over from earlier runs
    Remove-ItemProperty -Path $winlogonPath -Name "AutoLogonCount" -ErrorAction SilentlyContinue

    Write-Host "  Auto-logon for 'Kiosk' enabled (domain/machine: $env:COMPUTERNAME)." -ForegroundColor Green
    Write-Host "  Note: Takes effect from the next restart or next logoff." -ForegroundColor DarkYellow
}

# ============================================================
# 8. DISABLE NOTIFICATIONS (for all users)
# ============================================================
function Set-NotificationsPolicy {
    Write-Host "`n[5/13] Disabling notifications / Action Center..." -ForegroundColor Yellow

    # Officially documented GPO: "Remove Notifications and Action Center"
    # Computer Configuration > Administrative Templates > Start Menu and Taskbar
    $explorerPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    if (-not (Test-Path $explorerPolicyPath)) {
        New-Item -Path $explorerPolicyPath -Force | Out-Null
    }
    New-ItemProperty -Path $explorerPolicyPath -Name "DisableNotificationCenter" -PropertyType DWord -Value 1 -Force | Out-Null

    Write-Host "  DisableNotificationCenter=1 set (applies machine-wide to all users)." -ForegroundColor Green
}

$NOTIFICATIONS_USER_ACTION = {
    param($Root)
    # Additionally disable "normal" toast notifications per user
    # (independent of the Action Center policy above, affects e.g. Edge popups)
    $pushPath = "$Root\Software\Microsoft\Windows\CurrentVersion\PushNotifications"
    if (-not (Test-Path $pushPath)) {
        New-Item -Path $pushPath -Force | Out-Null
    }
    New-ItemProperty -Path $pushPath -Name "ToastEnabled" -PropertyType DWord -Value 0 -Force | Out-Null
}

# ============================================================
# 8b. DISABLE FIRST-RUN / WELCOME EXPERIENCE (machine-wide, all users incl. future ones)
# ============================================================
# Officially documented GPOs, all HKLM-scoped so no per-user hive loop is
# needed - applies to every account on the device, including "Kiosk" and
# "Maintenance" and any future account, without having to touch each profile.
function Set-KioskFirstRunExperience {
    Write-Host "`n[5b/13] Disabling Windows first-run/welcome experience (machine-wide)..." -ForegroundColor Yellow

    $cloudContentPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    if (-not (Test-Path $cloudContentPath)) { New-Item -Path $cloudContentPath -Force | Out-Null }

    # "Turn off the Windows Welcome Experience" - the "Let's finish setting
    # up your device" page shown on first sign-in and after major updates.
    New-ItemProperty -Path $cloudContentPath -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -PropertyType DWord -Value 1 -Force | Out-Null

    # "Turn off Microsoft consumer experiences" - broader: suggested/
    # pre-installed apps, tips, and other onboarding content.
    New-ItemProperty -Path $cloudContentPath -Name "DisableWindowsConsumerFeatures" -PropertyType DWord -Value 1 -Force | Out-Null

    # "Show first sign-in animation" = Disabled - skips the spinning "Hi"
    # animation on a brand-new account's very first logon.
    $systemPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (-not (Test-Path $systemPolicyPath)) { New-Item -Path $systemPolicyPath -Force | Out-Null }
    New-ItemProperty -Path $systemPolicyPath -Name "EnableFirstLogonAnimation" -PropertyType DWord -Value 0 -Force | Out-Null

    Write-Host "  Welcome experience, consumer features, and first-logon animation disabled for all users." -ForegroundColor Green
}

$FIRSTRUN_USER_ACTION = {
    param($Root)
    # Per-user belt-and-suspenders companion to the machine-wide policy
    # above - the specific toggle behind "Show me the Windows welcome
    # experience..." in Settings > Notifications lives here per profile.
    $cdmPath = "$Root\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    if (-not (Test-Path $cdmPath)) { New-Item -Path $cdmPath -Force | Out-Null }
    New-ItemProperty -Path $cdmPath -Name "SubscribedContent-310093Enabled" -PropertyType DWord -Value 0 -Force | Out-Null
}

# ============================================================
# 9. POWER SETTINGS (high performance, display/sleep never)
# ============================================================
function Set-KioskPowerSettings {
    Write-Host "`n[6/13] Configuring power settings..." -ForegroundColor Yellow

    # Set the power plan to "High performance" (powercfg alias SCHEME_MIN)
    powercfg /setactive SCHEME_MIN | Out-Null

    # Display: never turn off (AC = plugged in, DC = battery)
    powercfg /change monitor-timeout-ac 0
    powercfg /change monitor-timeout-dc 0

    # Standby/sleep: never
    powercfg /change standby-timeout-ac 0
    powercfg /change standby-timeout-dc 0

    Write-Host "  Power plan: High performance. Display and standby timeout: never (AC+DC)." -ForegroundColor Green
    Write-Host "  Note: For a kiosk running purely on mains power (no battery), the DC values are irrelevant but harmless." -ForegroundColor DarkYellow
}

# ============================================================
# 10. GERMAN LANGUAGE PACK (system + default for "Kiosk"/new users)
# ============================================================
function Install-KioskGermanLanguage {
    Write-Host "`n[12/13] Installing German language pack and setting it as default..." -ForegroundColor Yellow

    $langTag = "de-DE"

    # 1. Install the language pack component. Requires internet access to
    #    Windows Update - if your network (not the Edge domain allowlist
    #    from earlier, but a network-level/proxy firewall) blocks access to
    #    Windows Update endpoints, this will fail. In that case, add the
    #    language pack offline via ISO/WSUS instead.
    #    Deliberately only "Language.Basic" - it already includes the
    #    keyboard layout, UI language, and spell check, which is what
    #    actually matters here (see the barcode scanner keyboard layout
    #    issue this was built to fix). OCR/Handwriting/TextToSpeech/Speech
    #    are unrelated, much larger optional extras that were significantly
    #    slowing the script down for no benefit in this use case.
    $capabilityNames = @(
        "Language.Basic~~~$langTag~0.0.1.0"
    )

    $anyInstallFailed = $false
    $basicInstalled = $false
    foreach ($cap in $capabilityNames) {
        try {
            $capObj = Get-WindowsCapability -Online -Name $cap -ErrorAction Stop

            if ($capObj.State -eq "Installed") {
                Write-Host "  $($capObj.Name) already installed." -ForegroundColor Green
            } else {
                Write-Host "  Installing $($capObj.Name)..." -ForegroundColor Yellow
                $result = Add-WindowsCapability -Online -Name $capObj.Name -ErrorAction Stop

                # Recheck: Add-WindowsCapability doesn't necessarily throw an
                # error if the installation stalls in the background or a
                # restart is required - so re-query the status fresh instead
                # of blindly trusting the cmdlet's reported success.
                $recheck = Get-WindowsCapability -Online -Name $cap -ErrorAction Stop
                if ($recheck.State -eq "Installed") {
                    Write-Host "    -> installed successfully." -ForegroundColor Green
                } elseif ($result.RestartNeeded) {
                    Write-Host "    -> installed, restart required (status will show 'Installed' only afterwards)." -ForegroundColor DarkYellow
                } else {
                    Write-Host "    -> WARNING: status still '$($recheck.State)' after install attempt (not 'Installed')." -ForegroundColor Red
                    $anyInstallFailed = $true
                }
            }

            if ($cap -like "Language.Basic*" -and (Get-WindowsCapability -Online -Name $cap).State -eq "Installed") {
                $basicInstalled = $true
            }
        } catch {
            Write-Host "  WARNING: $cap could not be installed (possibly no access to Windows Update): $_" -ForegroundColor Red
            $anyInstallFailed = $true
        }
    }

    if (-not $basicInstalled) {
        Write-Host "  ABORTING: Language.Basic (core language pack) is not installed - skipping system/locale settings," -ForegroundColor Red
        Write-Host "  since they would be pointless without the language pack installed. Please check internet access to Windows Update." -ForegroundColor Red
        return
    }

    # 2. Set the system/display language. IMPORTANT: Set-WinUserLanguageList
    #    affects the CURRENTLY RUNNING session (i.e. the account this script
    #    is running under). This script should therefore ideally run under
    #    an administrator/technician account whose own language doesn't
    #    matter - not under a personal, actively used account.
    try {
        Set-WinSystemLocale -SystemLocale $langTag
        Set-WinHomeLocation -GeoId 94   # 94 = Germany
        Set-WinUserLanguageList -LanguageList $langTag -Force -ErrorAction Stop

        # 3. Apply this (now current) language setting as the default for
        #    the logon screen AND for all newly created profiles going
        #    forward. Deliberately done via control.exe/intl.cpl with an XML
        #    file instead of "Copy-UserInternationalSettingsToSystem" - per
        #    Microsoft's documentation, that cmdlet only exists on
        #    Windows 11, not on Windows 10 (IoT LTSC). The control.exe
        #    approach is the same mechanism used by unattend.xml answer
        #    files, and works identically on Windows 10 and 11.
        $xmlPath = Join-Path $env:TEMP "CopyIntlSettings.xml"
        @"
<gs:GlobalizationServices xmlns:gs="urn:longhornGlobalizationUnattend">
  <gs:UserList>
    <gs:User UserID="Current" CopySettingsToDefaultUserAcct="true" CopySettingsToSystemAcct="true"/>
  </gs:UserList>
</gs:GlobalizationServices>
"@ | Out-File -FilePath $xmlPath -Encoding utf8 -Force

        $controlExe = Join-Path $env:WINDIR "System32\control.exe"
        $proc = Start-Process -FilePath $controlExe -ArgumentList "intl.cpl,,/f:`"$xmlPath`"" -Wait -NoNewWindow -PassThru
        # Exit code 0 = applied immediately, exit code 1 = applied but a
        # restart is required (documented behavior of intl.cpl, not an
        # actual error). Only other exit codes warrant a real warning.
        if ($proc.ExitCode -eq 0) {
            Write-Host "  Language/regional settings applied for the system and new profiles." -ForegroundColor Green
        } elseif ($proc.ExitCode -eq 1) {
            Write-Host "  Language/regional settings set - will take full effect after a restart." -ForegroundColor DarkYellow
        } else {
            Write-Host "  WARNING: control.exe intl.cpl exited with unexpected exit code $($proc.ExitCode)." -ForegroundColor Red
        }
        Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  WARNING: Language/locale settings could not be fully applied: $_" -ForegroundColor Red
    }

    Write-Host "  German (de-DE) set as the system and default language for new profiles." -ForegroundColor Green
    if ($anyInstallFailed) {
        Write-Host "  Note: At least one language component could not be downloaded - see warnings above." -ForegroundColor DarkYellow
    }
}

$LANGUAGE_USER_ACTION = {
    param($Root)
    # Best-effort for ALREADY existing profiles (e.g. on a repeated script
    # run, after "Kiosk" has already logged on once in the meantime). For a
    # brand-new profile, the Default-profile path in
    # Install-KioskGermanLanguage takes care of this automatically instead.
    $intlPath = "$Root\Control Panel\International\User Profile"
    if (-not (Test-Path $intlPath)) { New-Item -Path $intlPath -Force | Out-Null }
    New-ItemProperty -Path $intlPath -Name "Languages" -PropertyType MultiString -Value @("de-DE") -Force | Out-Null

    # IMPORTANT: the modern "Languages" list above only drives newer
    # (UWP/XAML) apps like the Settings app. Legacy Win32 apps (Notepad,
    # and critically, USB HID keyboard input incl. barcode scanners running
    # in HID-keyboard mode) resolve keystrokes via the classic keyboard
    # layout, which is a SEPARATE registry location and does NOT get
    # updated automatically just by setting the language list above -
    # confirmed by seeing correct results in Settings but wrong (US-layout)
    # results in Notepad/browser for the same physical keypresses.
    $kbLayoutPath = "$Root\Keyboard Layout\Preload"
    if (-not (Test-Path $kbLayoutPath)) { New-Item -Path $kbLayoutPath -Force | Out-Null }

    # Clear any existing preload entries first, then set German (QWERTZ,
    # KLID 00000407) as the one and only, active (position "1") layout -
    # avoids a leftover US/other layout still being installed alongside it
    # and potentially becoming active again via a layout-switch shortcut.
    Get-Item $kbLayoutPath | Select-Object -ExpandProperty Property | ForEach-Object {
        Remove-ItemProperty -Path $kbLayoutPath -Name $_ -ErrorAction SilentlyContinue
    }
    New-ItemProperty -Path $kbLayoutPath -Name "1" -PropertyType String -Value "00000407" -Force | Out-Null

    # Also clear any layout substitution overrides that could remap the
    # German layout ID to something else (e.g. leftover IME substitutes).
    $kbSubstPath = "$Root\Keyboard Layout\Substitutes"
    if (Test-Path $kbSubstPath) {
        Remove-Item -Path $kbSubstPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Kiosk-only (not applied to "Maintenance" or the Default profile): adds
# additional keyboard layouts alongside German, which stays the
# active/default one (position "1"). Note: with the touch keyboard
# disabled in this script variant, these are reachable only via a
# physical external keyboard's layout-switch shortcut (Win+Space), not via
# an on-screen switcher - included for consistency in case a non-German
# physical keyboard ever gets connected.
$KIOSK_KEYBOARD_LAYOUTS_ACTION = {
    param($Root)
    $kbLayoutPath = "$Root\Keyboard Layout\Preload"
    if (-not (Test-Path $kbLayoutPath)) { New-Item -Path $kbLayoutPath -Force | Out-Null }

    Get-Item $kbLayoutPath | Select-Object -ExpandProperty Property | ForEach-Object {
        Remove-ItemProperty -Path $kbLayoutPath -Name $_ -ErrorAction SilentlyContinue
    }

    # "1" = active/default layout at logon (German). Additional numbered
    # entries are installed alongside it.
    $kioskLayouts = [ordered]@{
        "1" = "00000407"   # German (Germany) - default/active
        "2" = "0000040C"   # French (France)
        "3" = "00000410"   # Italian (Italy)
        "4" = "00000809"   # English (United Kingdom)
        "5" = "00000415"   # Polish
        "6" = "00000405"   # Czech
        "7" = "0000040A"   # Spanish (Spain)
        "8" = "00000401"   # Arabic (101, Saudi Arabia base layout - generic Arabic)
    }
    foreach ($key in $kioskLayouts.Keys) {
        New-ItemProperty -Path $kbLayoutPath -Name $key -PropertyType String -Value $kioskLayouts[$key] -Force | Out-Null
    }

    $kbSubstPath = "$Root\Keyboard Layout\Substitutes"
    if (Test-Path $kbSubstPath) {
        Remove-Item -Path $kbSubstPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================
# 12. AUTOHOTKEY - SUPPRESS THE LEFT CTRL KEY (touch keyboard)
# ============================================================
# There is no confirmed registry-based way to do this for the left Ctrl key
# (see the research notes further up in the script). Solution, confirmed
# working in the field: AutoHotkey blocking the SPECIFIC Ctrl+key
# combinations relevant for kiosk hardening (new tab/window, close, open,
# InPrivate, history, downloads, dev tools, view source, address bar, tab
# switching) rather than suppressing the Ctrl key itself. A blanket Ctrl
# suppression (with an RAlt-state check to spare AltGr) was tried first but
# proved unreliable - it intermittently broke AltGr-based characters (@, €,
# {, } on a German layout) due to a timing race between the synthetic Ctrl
# Windows generates for AltGr and the RAlt state check. Blocking specific
# combinations avoids that entirely, since AutoHotkey's "^" modifier only
# fires when Ctrl is the ONLY modifier held - Ctrl+Alt (AltGr) is
# structurally a different combination and is never matched.
#
# IMPORTANT - Difference from the partner setup: the partner uses their own
# PowerShell shell instead of Assigned Access, so they start AHK manually
# from their kiosk launcher script. In your Assigned Access mode there is no
# Explorer process and therefore no classic Startup folder - AHK is
# therefore started here via a scheduled task instead, run on every logon
# of "Kiosk".
function Install-KioskAutoHotkey {
    Write-Host "`n[11/13] Setting up AutoHotkey for left-Ctrl suppression..." -ForegroundColor Yellow

    $ahkCandidates = @(
        "C:\Program Files\AutoHotkey\AutoHotkey.exe",
        "C:\Program Files\AutoHotkey\AutoHotkey64.exe",
        "C:\Program Files\AutoHotkey\v2\AutoHotkey64.exe",
        "C:\Program Files\AutoHotkey\v1\AutoHotkey.exe"
    )
    $ahkExe = $ahkCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($ahkExe) {
        Write-Host "  AutoHotkey already installed: $ahkExe" -ForegroundColor Green
    } else {
        $wingetAvailable = $null -ne (Get-Command winget -ErrorAction SilentlyContinue)

        if ($wingetAvailable) {
            Write-Host "  Installing AutoHotkey via winget..." -ForegroundColor Yellow
            winget install AutoHotkey.AutoHotkey --silent --accept-source-agreements --accept-package-agreements *>$null
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  WARNING: winget installation failed (exit code $LASTEXITCODE)." -ForegroundColor Red
            }
            $ahkExe = $ahkCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
        }

        if (-not $ahkExe) {
            # Fallback for images without winget (common on Windows 10 IoT
            # LTSC): download the latest installer directly from the
            # official AutoHotkey GitHub Releases API instead of hardcoding
            # a version number that would go stale.
            Write-Host "  winget not available - downloading AutoHotkey directly from GitHub Releases instead..." -ForegroundColor Yellow
            try {
                $release = Invoke-RestMethod -Uri "https://api.github.com/repos/AutoHotkey/AutoHotkey/releases/latest" -UseBasicParsing
                $asset = $release.assets | Where-Object { $_.name -like "*_setup.exe" } | Select-Object -First 1
                if (-not $asset) {
                    Write-Host "  WARNING: No setup.exe asset found in the latest AutoHotkey release." -ForegroundColor Red
                    return
                }

                $installerPath = Join-Path $env:TEMP $asset.name
                Invoke-KioskWebDownload -Uri $asset.browser_download_url -OutFile $installerPath

                # /silent = unattended install, /Elevate = install for all
                # users instead of just the currently logged-on account
                # (relevant since this script may run under a different
                # account than "Kiosk").
                $proc = Start-Process -FilePath $installerPath -ArgumentList "/silent", "/Elevate" -Wait -PassThru
                if ($proc.ExitCode -ne 0) {
                    Write-Host "  WARNING: AutoHotkey installer exited with code $($proc.ExitCode)." -ForegroundColor Red
                }
                Remove-Item $installerPath -Force -ErrorAction SilentlyContinue

                $ahkExe = $ahkCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
            } catch {
                Write-Host "  WARNING: Direct download/install from GitHub failed (requires internet access to github.com): $_" -ForegroundColor Red
                return
            }
        }

        if (-not $ahkExe) {
            Write-Host "  WARNING: AutoHotkey was installed, but the .exe was not found at any of the expected paths." -ForegroundColor Red
            return
        }
        Write-Host "  AutoHotkey installed: $ahkExe" -ForegroundColor Green
    }

    # A blanket "suppress LCtrl unless RAlt is also down" approach was tried
    # first, but proved unreliable in practice - Windows doesn't guarantee
    # that RAlt is already registered as down at the exact moment the
    # synthetic Ctrl from AltGr arrives, so AltGr characters (@, €, {, })
    # could still break intermittently. More robust fix, confirmed working
    # in the field: block only the SPECIFIC Ctrl combinations that matter
    # for kiosk hardening (new tab/window, close, open, InPrivate, history,
    # downloads, dev tools, view source, address bar) instead of the Ctrl
    # key itself. AutoHotkey's "^" modifier only fires when Ctrl is the
    # ONLY modifier held, so AltGr (Ctrl+Alt together) is naturally
    # unaffected - no RAlt-timing race condition possible. Syntax is
    # identical between AHK v1 and v2 for this simpler form.
    $ahkScriptContent = @"
^o::return
^w::return
^t::return
^n::return
^p::return
^s::return
^f::return
^d::return
^h::return
^j::return
^u::return
^l::return
^k::return
^+t::return
^+n::return
^+j::return
^+i::return
^+delete::return
^tab::return
^+tab::return
"@

    $ahkScriptPath = "C:\ProgramData\remap.ahk"
    $ahkScriptContent | Out-File -FilePath $ahkScriptPath -Encoding UTF8 -Force
    Write-Host "  Remap script written (Ctrl+key combination blocking, AltGr-safe): $ahkScriptPath" -ForegroundColor Green

    # Scheduled task for autostart on "Kiosk" logon (replacement for the
    # Startup-folder mechanism that's missing in Assigned Access)
    $taskName = "KioskAutoHotkeyRemap"
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

        $action = New-ScheduledTaskAction -Execute $ahkExe -Argument "`"$ahkScriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User "Kiosk"
        $principal = New-ScheduledTaskPrincipal -UserId "Kiosk" -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null

        Write-Host "  Scheduled task '$taskName' created - starts AutoHotkey on every Kiosk logon." -ForegroundColor Green
    } catch {
        Write-Host "  WARNING: Scheduled task could not be created: $_" -ForegroundColor Red
    }
}

# ============================================================
# EXECUTION
# ============================================================
Set-FirewallRules
Set-EdgePolicies
Set-EdgeSitePermissions
Set-KioskCameraMicPrivacy
Set-KioskWallpaper
Set-EdgeUiSwipePolicy
Set-NotificationsPolicy
Set-KioskFirstRunExperience
Set-KioskPowerSettings

Write-Host "`n[7/13] Disabling touch/swipe gestures for all user profiles..." -ForegroundColor Yellow
Invoke-ForAllUserHives -Action $GESTURE_ACTION
Invoke-ForAllUserHives -Action $EDGEUI_USER_ACTION
Invoke-ForAllUserHives -Action $NOTIFICATIONS_USER_ACTION
Invoke-ForAllUserHives -Action $FIRSTRUN_USER_ACTION
Invoke-ForAllUserHives -Action $CAMERA_MIC_USER_ACTION

Write-Host "  Removing any stray Edge domain restriction from other profiles (bugfix cleanup)..." -ForegroundColor Yellow
Invoke-ForAllUserHives -Action $CLEANUP_STRAY_EDGE_DOMAIN_ACTION

Write-Host "  Setting the Edge domain restriction only for 'Kiosk'..." -ForegroundColor Yellow
Invoke-ForAllUserHives -Action $KIOSK_EDGE_DOMAIN_ACTION -OnlyUserNames @("Kiosk")

Write-Host "`n[8/13] Setting touch keyboard settings for all user profiles..." -ForegroundColor Yellow
Invoke-ForAllUserHives -Action $TOUCH_KEYBOARD_ACTION
Set-KioskTouchKeyboardMachineDefaults
Enable-KioskTouchKeyboardService

Set-KioskLocalUsers
Set-KioskAutoLogon
Install-KioskAutoHotkey

if ($SkipLanguagePack) {
    Write-Host "`n[12/13] Skipping German language pack because -SkipLanguagePack was specified." -ForegroundColor DarkYellow
} else {
    Install-KioskGermanLanguage
    Invoke-ForAllUserHives -Action $LANGUAGE_USER_ACTION
}

Write-Host "  Adding additional keyboard layouts (FR/IT/UK/PL/CZ/ES/AR) for 'Kiosk' only..." -ForegroundColor Yellow
Invoke-ForAllUserHives -Action $KIOSK_KEYBOARD_LAYOUTS_ACTION -OnlyUserNames @("Kiosk")

Write-Host "`n=== Done (v$ScriptVersion) ===" -ForegroundColor Cyan
Write-Host "Restarting automatically below so all settings take full effect." -ForegroundColor DarkYellow

if ($Global:CreatedUserCredentials.Count -gt 0) {
    Write-Host "`n=== NEWLY CREATED USERS - SAVE THESE PASSWORDS NOW ===" -ForegroundColor Red
    foreach ($cred in $Global:CreatedUserCredentials) {
        Write-Host "  $($cred.User) : $($cred.Password)" -ForegroundColor Red
    }
    Write-Host "These passwords are not stored anywhere - please copy them into your" -ForegroundColor Red
    Write-Host "password manager right away, this window will not show them again." -ForegroundColor Red
}

# ============================================================
# AUTOMATIC RESTART
# ============================================================
# Several settings (Edge policies, wallpaper, touch keyboard, language,
# auto-logon) only take full effect after a restart. Restarts automatically
# and unattended by default - no interactive prompt, since this script is
# meant to run remotely via RMM (ProV), where there is no console to answer
# a prompt on and an interactive Read-Host/key-polling loop causes RMM to
# report an error. This will forcibly log off any other currently
# signed-in users too. Pass -NoRestart to skip this (e.g. for testing).
try {
    Stop-Transcript | Out-Null
} catch {
    # Ignore transcript stop errors (e.g. if Start-Transcript never succeeded)
}

if ($NoRestart) {
    Write-Host "`nRestart skipped because -NoRestart was specified." -ForegroundColor DarkYellow
    Write-Host "Please restart the device manually so all settings can take full effect." -ForegroundColor DarkYellow
} else {
    Write-Host ""
    Write-Host "Restarting now (unattended) so all settings take full effect..." -ForegroundColor Yellow
    Restart-Computer -Force
}
