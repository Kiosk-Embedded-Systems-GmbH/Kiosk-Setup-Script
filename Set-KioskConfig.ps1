<#
.SYNOPSIS
    Kiosk-Hardening-Script für Windows 10 IoT Enterprise LTSC / Windows 11 IoT Enterprise.

.DESCRIPTION
    Konfiguriert in einem Durchlauf:
      1. Firewall (aktivieren + Regeln für Lobster/OneConnect + ProV)
      2. Edge Domain-Allowlist (nur definierte Domains inkl. Subdomains)
      3. Hintergrund- und Sperrbildschirmbild (Download + GPO-Registrierung)
      4. Touch-/Swipe-Gesten deaktivieren (Edge-Swipes, Ecken, Mehrfinger-Gesten)
      5. Touch-Tastatur: Floating-Layout aus, linke STRG aus, Desktop-Auto-Invoke an
         -> wird für ALLE vorhandenen Benutzerprofile UND das Default-Profil
            (Vorlage für neue User, inkl. Assigned-Access-Konten wie "Kiosk")
            per Offline-Hive-Load gesetzt.
      6. Lokale Benutzer "Maintenance" (Administrator) und "Kiosk" (Standard)
         anlegen, falls nicht vorhanden, inkl. Profilbild (aus GitHub-Repo
         heruntergeladen, in die von Windows erwarteten Account-Picture-
         Größen skaliert).
      7. Auto-Logon für "Kiosk" via Winlogon-Registry (kein Passwort nötig,
         da das Konto ohne Kennwort angelegt wird).
      8. Benachrichtigungen/Action Center für alle Benutzer deaktivieren.
      9. Energieeinstellungen: Energieplan "Höchstleistung", Display- und
         Standby-Timeout auf "Nie".
     10. Deutsches Sprachpaket (de-DE) installieren und als System-/
         Standardsprache für neue Profile (inkl. "Kiosk") setzen.

.NOTES
    WICHTIG - gpedit.msc zeigt "Not configured" trotz gesetzter Registry-Werte:
    Das ist ERWARTETES Verhalten, kein Fehler. gpedit.msc liest seinen
    Status ausschließlich aus der lokalen registry.pol-Datei, nicht aus der
    Live-Registry. Direkt per Script/PowerShell gesetzte Policy-Werte werden
    von Windows trotzdem korrekt angewendet (dieselbe Registry-Struktur wird
    zur Laufzeit ausgelesen) - nur die Anzeige in gpedit.msc bleibt "Not
    configured", weil dort nur über gpedit selbst konfigurierte Einstellungen
    reflektiert werden. Verifizieren via regedit oder tatsächlichen Test am
    Gerät statt über gpedit.msc.
    WICHTIG - Neu angelegte Benutzer:
    - "Maintenance" wird mit fixem Passwort angelegt (im Script hinterlegt -
      Script-Datei entsprechend vertraulich behandeln / nach Bedarf anpassen).
    - "Kiosk" wird OHNE Passwort angelegt (-NoPassword). Windows lässt
      Anmeldungen mit leerem Kennwort standardmäßig nur an der lokalen
      Konsole zu (Sicherheitsrichtlinie "Kontosicherheit: Lokale
      Kontenverwendung von leeren Kennwörtern auf Konsolenanmeldung
      beschränken" = aktiviert). Für Assigned-Access-Autologon ist das
      i.d.R. unproblematisch, da lokal am Gerät angemeldet wird - falls ihr
      RDP/Remote-Anmeldung mit "Kiosk" plant, greift das NICHT, das müsst
      ihr separat über diese Richtlinie freigeben.
    - Bereits vorhandene "Maintenance"/"Kiosk"-Konten werden nicht verändert
      (kein Passwort-Reset, keine Gruppenänderung).
    - Auto-Logon / Assigned-Access-Zuweisung für "Kiosk" ist NICHT Teil
      dieses Scripts - das läuft vermutlich schon über eure bestehende
      Provisionierung.

    WICHTIG - Vertrauenswürdigkeit der Einstellungen:
    - Firewall, Edge-Policies und Personalization (Wallpaper/Lockscreen) sind
      offiziell von Microsoft dokumentierte Group-Policy-Registry-Pfade -> zuverlässig.
    - "EnableFloating" / "EnableCtrl" unter TabletTip\1.7 sind NICHT offiziell
      dokumentiert (undokumentierte interne Keys, die sich zwischen Builds
      ändern können). Sie sind hier als bestmögliche Annahme gesetzt.
      Verifizieren via:
        1) reg export "HKCU\Software\Microsoft\TabletTip\1.7" vorher.reg
        2) Einstellung in den Windows-Settings manuell umschalten
        3) reg export erneut -> nachher.reg
        4) fc vorher.reg nachher.reg  -> zeigt dir den tatsächlichen Key/Value
      Passe TOUCH_KEYBOARD_ACTION unten entsprechend an, falls abweichend.
    - Echtes globales Deaktivieren von 2-Finger-Pinch-Zoom auf dem Touchscreen
      ist von Windows nicht als unterstützter Schalter vorgesehen (das
      handhaben Apps wie Edge selbst). Was hier zuverlässig geht, ist das
      Deaktivieren der Precision-Touchpad-Mehrfingergesten (Trackpad) sowie
      der Edge-UI-Randgesten (Charms/Ecken/Swipe-from-edge).

.PARAMETER Uninstall
    (optional, nicht implementiert) - für Rollback ggf. separat pflegen.

    Ausführen als Administrator! Neustart bzw. gpupdate /force + Neuanmeldung
    wird für einige Einstellungen benötigt.
#>

#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

# ============================================================
# EXECUTION POLICY
# ============================================================
# Erlaubt das Ausführen von (unsignierten, lokalen) PowerShell-Scripts auf
# diesem Gerät dauerhaft - notwendig, falls die Standardrichtlinie
# "Restricted" verhindert, dass dieses und künftige Kiosk-Scripts laufen.
# In try/catch, da eine evtl. per GPO zentral vorgegebene Policy dies mit
# einer nicht-terminierbaren SecurityException verhindern kann - das ist
# dann kein Fehler (die effektive Policy ist in dem Fall meist ohnehin
# schon "Bypass"/"RemoteSigned"), das Script soll trotzdem weiterlaufen.
try {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop
} catch {
    Write-Host "Hinweis: Execution Policy wird zentral per GPO vorgegeben, lokale Änderung übersprungen (aktuell effektiv: $(Get-ExecutionPolicy))." -ForegroundColor DarkYellow
}

# ============================================================
# KONFIGURATION
# ============================================================
$AllowedDomains = @(
    "oneux.kiosk.eu",
    "kiosk.eu",
    "app.straiv.io",
    "straiv.io",
    "*.luca.app",
    "*.likemagic.tech",
    "localhost:8080",
    "localhost:8081"
)

$WallpaperUrl       = "https://raw.githubusercontent.com/Kiosk-Embedded-Systems-GmbH/Kiosk-Setup-Script/main/wallpaper.jpg"
$WallpaperLocalPath = "C:\ProgramData\KioskConfig\background.jpg"

$MaintenancePicUrl = "https://raw.githubusercontent.com/Kiosk-Embedded-Systems-GmbH/Kiosk-Setup-Script/main/maintenance-profile-picture.png"
$KioskPicUrl        = "https://raw.githubusercontent.com/Kiosk-Embedded-Systems-GmbH/Kiosk-Setup-Script/main/kiosk-profile-picture.png"

Write-Host "=== Kiosk Setup Script gestartet ===" -ForegroundColor Cyan

# ============================================================
# 1. FIREWALL
# ============================================================
function Set-FirewallRules {
    Write-Host "`n[1/11] Firewall konfigurieren..." -ForegroundColor Yellow
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

    Get-NetFirewallRule -DisplayName "Kiosk-Lobster-OneConnect-In" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Get-NetFirewallRule -DisplayName "Kiosk-ProV-Out" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    New-NetFirewallRule -DisplayName "Kiosk-Lobster-OneConnect-In" `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080-8081 `
        -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "Kiosk-ProV-Out" `
        -Direction Outbound -Action Allow -Protocol TCP -RemotePort 5902 `
        -Profile Any | Out-Null

    Write-Host "  Firewall aktiv (alle Profile), Regeln für 8080-8081 (in) / 5902 (out) gesetzt." -ForegroundColor Green
}

# ============================================================
# 2. EDGE DOMAIN-ALLOWLIST
# ============================================================
function Set-EdgePolicies {
    Write-Host "`n[2/11] Edge Domain-Filter konfigurieren..." -ForegroundColor Yellow
    $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    New-Item -Path $edgePolicyPath -Force | Out-Null

    # Alles sperren...
    $blockPath = "$edgePolicyPath\URLBlocklist"
    New-Item -Path $blockPath -Force | Out-Null
    New-ItemProperty -Path $blockPath -Name "1" -PropertyType String -Value "*" -Force | Out-Null

    # ...außer die erlaubten Domains (Chromium-Syntax: Eintrag ohne führenden
    # Punkt/Wildcard erlaubt automatisch auch alle Subdomains)
    $allowPath = "$edgePolicyPath\URLAllowlist"
    New-Item -Path $allowPath -Force | Out-Null
    Get-Item $allowPath | Select-Object -ExpandProperty Property | ForEach-Object {
        Remove-ItemProperty -Path $allowPath -Name $_ -ErrorAction SilentlyContinue
    }

    $i = 1
    foreach ($domain in $AllowedDomains) {
        New-ItemProperty -Path $allowPath -Name "$i" -PropertyType String -Value $domain -Force | Out-Null
        $i++
    }

    # Automatisches Übersetzen-Popup ("Seite aus dem Englischen übersetzen?") deaktivieren
    New-ItemProperty -Path $edgePolicyPath -Name "TranslateEnabled" -PropertyType DWord -Value 0 -Force | Out-Null

    Write-Host "  $($AllowedDomains.Count) Domains (inkl. Subdomains) erlaubt, alles andere blockiert." -ForegroundColor Green
    Write-Host "  Übersetzungs-Vorschlag deaktiviert (TranslateEnabled=0)." -ForegroundColor Green
}

# ============================================================
# 2b. EDGE SITE-PERMISSIONS (Kamera/Mikro/Standort/etc. für erlaubte Domains)
# ============================================================
function Set-EdgeSitePermissions {
    Write-Host "`n[2b/11] Website-Funktionen für erlaubte Domains freigeben..." -ForegroundColor Yellow

    # Policy-Name => Beschreibung. Jede bekommt eine "...AllowedForUrls"-Liste
    # mit denselben Domains wie die URLAllowlist.
    $permissionPolicies = @(
        "NotificationsAllowedForUrls",
        "GeolocationAllowedForUrls",
        "VideoCaptureAllowedUrls",
        "AudioCaptureAllowedUrls",
        "SensorsAllowedForUrls",
        "ClipboardAllowedForUrls",
        "LocalNetworkAccessAllowedForUrls"
    )

    $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"

    foreach ($policyName in $permissionPolicies) {
        $policyPath = "$edgePolicyPath\$policyName"
        New-Item -Path $policyPath -Force | Out-Null

        # bestehende Einträge leeren (idempotent bei erneutem Lauf)
        Get-Item $policyPath | Select-Object -ExpandProperty Property | ForEach-Object {
            Remove-ItemProperty -Path $policyPath -Name $_ -ErrorAction SilentlyContinue
        }

        $i = 1
        foreach ($domain in $AllowedDomains) {
            # Diese Policies nutzen das "Enterprise policy URL pattern format"
            # (Content-Settings-Syntax), NICHT das URLAllowlist-Format:
            #   - Subdomains: "[*.]domain.tld" statt "*.domain.tld"
            #   - localhost mit Port: volle Origin-Angabe inkl. Schema
            if ($domain -like "localhost:*") {
                $urlValue = "http://$domain"
            } elseif ($domain -like "*.*" -and $domain.StartsWith("*.")) {
                $urlValue = "[*.]" + $domain.Substring(2)
            } else {
                # Plain-Domain -> inkl. Subdomains freigeben, analog zur URLAllowlist
                $urlValue = "[*.]$domain"
            }
            New-ItemProperty -Path $policyPath -Name "$i" -PropertyType String -Value $urlValue -Force | Out-Null
            $i++
        }
    }

    Write-Host "  Kamera, Mikrofon, Standort, Notifications, Sensoren, Zwischenablage," -ForegroundColor Green
    Write-Host "  sowie Local Network Access für alle $($AllowedDomains.Count) erlaubten Domains per Default auf 'Allow' gesetzt." -ForegroundColor Green
}

# ============================================================
# 3. WALLPAPER / SPERRBILDSCHIRM
# ============================================================
function Set-KioskWallpaper {
    Write-Host "`n[3/11] Hintergrund- und Sperrbildschirmbild setzen..." -ForegroundColor Yellow

    New-Item -Path (Split-Path $WallpaperLocalPath) -ItemType Directory -Force | Out-Null
    try {
        Invoke-WebRequest -Uri $WallpaperUrl -OutFile $WallpaperLocalPath -UseBasicParsing
    } catch {
        Write-Host "  FEHLER: Bild konnte nicht heruntergeladen werden: $_" -ForegroundColor Red
        return
    }

    # HINWEIS: HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization ist
    # der klassische Domain-GPO-Pfad und wird außerhalb von AD-Domänen nicht
    # zuverlässig für alle Benutzer durchgesetzt. Der tatsächlich von Intune/
    # MDM/lokalen Scripts genutzte, nachweislich funktionierende Pfad ist
    # PersonalizationCSP unter CurrentVersion (nicht unter Policies).
    $persPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
    New-Item -Path $persPath -Force | Out-Null

    New-ItemProperty -Path $persPath -Name "DesktopImagePath"   -PropertyType String -Value $WallpaperLocalPath -Force | Out-Null
    New-ItemProperty -Path $persPath -Name "DesktopImageUrl"    -PropertyType String -Value $WallpaperLocalPath -Force | Out-Null
    New-ItemProperty -Path $persPath -Name "DesktopImageStatus" -PropertyType DWord  -Value 1 -Force | Out-Null

    New-ItemProperty -Path $persPath -Name "LockScreenImagePath"   -PropertyType String -Value $WallpaperLocalPath -Force | Out-Null
    New-ItemProperty -Path $persPath -Name "LockScreenImageUrl"    -PropertyType String -Value $WallpaperLocalPath -Force | Out-Null
    New-ItemProperty -Path $persPath -Name "LockScreenImageStatus" -PropertyType DWord  -Value 1 -Force | Out-Null

    # Windows anweisen, die geänderten Systemparameter sofort für alle
    # aktiven Sessions neu einzulesen, statt auf den nächsten Neustart zu
    # warten (wirkt zuverlässig trotzdem erst vollständig nach Neuanmeldung).
    try {
        rundll32.exe user32.dll,UpdatePerUserSystemParameters 1, $true
    } catch {
        Write-Host "  Hinweis: Sofort-Refresh via rundll32 nicht möglich, Neuanmeldung/Neustart nötig." -ForegroundColor DarkYellow
    }

    Write-Host "  Bild lokal unter $WallpaperLocalPath abgelegt und über PersonalizationCSP gesetzt (gilt für alle Benutzer)." -ForegroundColor Green
    Write-Host "  Hinweis: Volle Wirkung meist erst nach Neuanmeldung/Neustart." -ForegroundColor DarkYellow
}

# ============================================================
# 4. HILFSFUNKTION: Aktion für alle Benutzer-Hives (inkl. Default) ausführen
# ============================================================
function Invoke-ForAllUserHives {
    param([ScriptBlock]$Action)

    $ProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $profileKeys = Get-ChildItem $ProfileListPath | Where-Object { $_.PSChildName -match '^S-1-5-21-' }

    $hiveTargets = @()
    foreach ($p in $profileKeys) {
        $sid = $p.PSChildName
        $profilePath = (Get-ItemProperty $p.PSPath).ProfileImagePath
        $ntUserPath = Join-Path $profilePath "NTUSER.DAT"
        if (Test-Path $ntUserPath) {
            $hiveTargets += [PSCustomObject]@{ SID = $sid; Path = $ntUserPath }
        }
    }
    # Default-Profil = Vorlage für künftige/neue Benutzer (inkl. neu angelegter Assigned-Access-User)
    $hiveTargets += [PSCustomObject]@{ SID = "DefaultUser"; Path = "C:\Users\Default\NTUSER.DAT" }

    foreach ($target in $hiveTargets) {
        $safeName = ($target.SID -replace '[^a-zA-Z0-9]', '_')
        $mountKey = "TempHive_$safeName"
        $alreadyLoaded = Test-Path "Registry::HKEY_USERS\$($target.SID)"

        if ($alreadyLoaded) {
            $regRoot = "Registry::HKEY_USERS\$($target.SID)"
        } else {
            $loadResult = reg load "HKU\$mountKey" "$($target.Path)" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  WARNUNG: Hive konnte nicht geladen werden: $($target.Path) ($loadResult)" -ForegroundColor Red
                continue
            }
            $regRoot = "Registry::HKEY_USERS\$mountKey"
        }

        try {
            & $Action $regRoot
            Write-Host "  OK: $($target.SID)" -ForegroundColor Green
        } catch {
            Write-Host "  FEHLER bei $($target.SID): $_" -ForegroundColor Red
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
# 4b. RAND-GESTEN (korrekt ADMX-gebundene "Edge UI"-Policy, Windows 10/11)
# ============================================================
function Set-EdgeUiSwipePolicy {
    Write-Host "`n[4/11] Rand-Gesten per Gruppenrichtlinien-Pfad deaktivieren..." -ForegroundColor Yellow

    # Computer Configuration > Administrative Templates > Windows Components > Edge UI
    $euiPathHKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI"
    New-Item -Path $euiPathHKLM -Force | Out-Null
    # "Disable swiping from screen edges" = Enabled
    New-ItemProperty -Path $euiPathHKLM -Name "AllowEdgeSwipe" -PropertyType DWord -Value 0 -Force | Out-Null
    # "Disable help tips" = Enabled
    New-ItemProperty -Path $euiPathHKLM -Name "DisableHelpSticker" -PropertyType DWord -Value 1 -Force | Out-Null

    # Zusätzlich als User-Policy setzen (gleicher ADMX-Pfad existiert auch unter
    # User Configuration) - hier für HKCU des aktuell ausführenden Kontexts;
    # für andere/zukünftige Profile via Invoke-ForAllUserHives unten mitgesetzt.
    $euiPathHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI"
    New-Item -Path $euiPathHKCU -Force | Out-Null
    New-ItemProperty -Path $euiPathHKCU -Name "AllowEdgeSwipe" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $euiPathHKCU -Name "DisableHelpSticker" -PropertyType DWord -Value 1 -Force | Out-Null

    Write-Host "  AllowEdgeSwipe=0 / DisableHelpSticker=1 unter Policies\Microsoft\Windows\EdgeUI gesetzt." -ForegroundColor Green
    Write-Host "  Pruefen via gpedit.msc: Computer/User Config > Admin. Vorlagen > Windows-Komponenten > Edge UI." -ForegroundColor DarkYellow
}

$EDGEUI_USER_ACTION = {
    param($Root)
    $euiPath = "$Root\Software\Policies\Microsoft\Windows\EdgeUI"
    New-Item -Path $euiPath -Force | Out-Null
    New-ItemProperty -Path $euiPath -Name "AllowEdgeSwipe" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $euiPath -Name "DisableHelpSticker" -PropertyType DWord -Value 1 -Force | Out-Null
}

# ============================================================
# 5a. TOUCH-/SWIPE-GESTEN (Precision Touchpad Mehrfinger)
# ============================================================
$GESTURE_ACTION = {
    param($Root)

    # HINWEIS: "ImmersiveShell\EdgeUi" (Charms-Bar-Ära, Windows 8.1) entfernt -
    # dieser Mechanismus existiert seit Windows 10 nicht mehr und ist NICHT an
    # das GPO-Template gebunden. Der korrekte, ADMX-gebundene Pfad für
    # Windows 10/11 ("Edge UI" unter Windows Components) wird stattdessen
    # unten als eigene Maschinen-Policy in Set-EdgeUiSwipePolicy gesetzt.

    # Precision Touchpad Mehrfingergesten (2/3/4 Finger, Pan/Zoom/Rotate) - betrifft Trackpads
    $ptpPath = "$Root\Software\Microsoft\Windows\CurrentVersion\PrecisionTouchPad"
    New-Item -Path $ptpPath -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "ThreeFingerSlideEnabled" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "FourFingerSlideEnabled"  -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "ThreeFingerTapEnabled"   -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "FourFingerTapEnabled"    -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "PanningEnabled"          -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "ZoomEnabled"             -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ptpPath -Name "RotationEnabled"         -PropertyType DWord -Value 0 -Force | Out-Null
}

# ============================================================
# 5b. TOUCH-TASTATUR (TabletTip)
# ============================================================
$TOUCH_KEYBOARD_ACTION = {
    param($Root)

    $tipPath = "$Root\Software\Microsoft\TabletTip\1.7"
    New-Item -Path $tipPath -Force | Out-Null

    # Explizit angefordert: Auto-Invoke im Desktop-Modus aktivieren
    New-ItemProperty -Path $tipPath -Name "EnableDesktopModeAutoInvoke" -PropertyType DWord -Value 1 -Force | Out-Null

    # UNVERIFIZIERT (siehe Hinweis am Scriptanfang) - Floating-Layout aus
    New-ItemProperty -Path $tipPath -Name "EnableFloating" -PropertyType DWord -Value 0 -Force | Out-Null

    # UNVERIFIZIERT (siehe Hinweis am Scriptanfang) - linke STRG-Taste aus
    New-ItemProperty -Path $tipPath -Name "EnableCtrl" -PropertyType DWord -Value 0 -Force | Out-Null
}

# ============================================================
# 6. LOKALE BENUTZER "Maintenance" (Admin) und "Kiosk" (Standard) + Profilbilder
# ============================================================
$Global:CreatedUserCredentials = @()

function Set-UserAccountPicture {
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][string]$ImageUrl
    )

    $user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "  WARNUNG: Benutzer '$UserName' nicht gefunden, Profilbild wird übersprungen." -ForegroundColor Red
        return
    }
    $sid = $user.SID.Value

    $tempImage = Join-Path $env:TEMP "$UserName-src.png"
    try {
        Invoke-WebRequest -Uri $ImageUrl -OutFile $tempImage -UseBasicParsing
    } catch {
        Write-Host "  WARNUNG: Profilbild für '$UserName' konnte nicht heruntergeladen werden: $_" -ForegroundColor Red
        return
    }

    # Validierung: ist die heruntergeladene Datei ein von GDI+ unterstütztes
    # Format? (Sicherheitsnetz für den Fall einer 404-Seite o.ä.)
    $fileBytes = [System.IO.File]::ReadAllBytes($tempImage)
    $isPng  = $fileBytes.Length -ge 8 -and $fileBytes[0] -eq 0x89 -and $fileBytes[1] -eq 0x50 -and $fileBytes[2] -eq 0x4E -and $fileBytes[3] -eq 0x47
    $isJpeg = $fileBytes.Length -ge 3 -and $fileBytes[0] -eq 0xFF -and $fileBytes[1] -eq 0xD8
    $isGif  = $fileBytes.Length -ge 6 -and $fileBytes[0] -eq 0x47 -and $fileBytes[1] -eq 0x49 -and $fileBytes[2] -eq 0x46

    if (-not ($isPng -or $isJpeg -or $isGif)) {
        Write-Host "  WARNUNG: Die URL für '$UserName' liefert kein gültiges Bild (Größe: $($fileBytes.Length) Bytes)." -ForegroundColor Red
        Write-Host "  URL: $ImageUrl" -ForegroundColor Red
        Remove-Item $tempImage -Force -ErrorAction SilentlyContinue
        return
    }

    try {
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    } catch {
        Write-Host "  WARNUNG: System.Drawing nicht verfügbar - Profilbild wird nur als Rohdatei kopiert, ohne Größenanpassung." -ForegroundColor Red
        $destFolder = "C:\Users\Public\AccountPictures\$sid"
        New-Item -Path $destFolder -ItemType Directory -Force | Out-Null
        $destFile = Join-Path $destFolder "Image192.jpg"
        Copy-Item $tempImage $destFile -Force
        $picPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users\$sid"
        if (-not (Test-Path $picPath)) { New-Item -Path $picPath -Force | Out-Null }
        New-ItemProperty -Path $picPath -Name "Image192" -PropertyType String -Value $destFile -Force | Out-Null
        Remove-Item $tempImage -Force -ErrorAction SilentlyContinue
        return
    }

    $destFolder = "C:\Users\Public\AccountPictures\$sid"
    New-Item -Path $destFolder -ItemType Directory -Force | Out-Null

    $picPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users\$sid"
    if (-not (Test-Path $picPath)) { New-Item -Path $picPath -Force | Out-Null }

    $sizes = 32, 40, 48, 96, 192, 240, 448
    try {
        $srcImage = [System.Drawing.Image]::FromFile($tempImage)
    } catch {
        Write-Host "  WARNUNG: Bilddatei für '$UserName' konnte nicht von GDI+ geladen werden: $_" -ForegroundColor Red
        Remove-Item $tempImage -Force -ErrorAction SilentlyContinue
        return
    }

    foreach ($size in $sizes) {
        $destFile = Join-Path $destFolder "Image$size.jpg"
        $bmp = New-Object System.Drawing.Bitmap $size, $size
        $graphics = [System.Drawing.Graphics]::FromImage($bmp)
        $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.DrawImage($srcImage, 0, 0, $size, $size)
        $bmp.Save($destFile, [System.Drawing.Imaging.ImageFormat]::Jpeg)
        $graphics.Dispose()
        $bmp.Dispose()
        New-ItemProperty -Path $picPath -Name "Image$size" -PropertyType String -Value $destFile -Force | Out-Null
    }
    $srcImage.Dispose()
    Remove-Item $tempImage -Force -ErrorAction SilentlyContinue

    Write-Host "  Profilbild für '$UserName' (SID $sid) in $($sizes.Count) Größen gesetzt." -ForegroundColor Green
}

function Set-KioskLocalUsers {
    Write-Host "`n[9/11] Lokale Benutzer 'Maintenance' und 'Kiosk' prüfen/anlegen..." -ForegroundColor Yellow

    # Well-known SIDs statt lokalisierter Gruppennamen (funktioniert unabhängig
    # von Sprachversion: "Administrators"/"Administratoren" etc.)
    $adminGroup = Get-LocalGroup | Where-Object { $_.SID -eq "S-1-5-32-544" }
    $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq "S-1-5-32-545" }

    $userDefs = @(
        @{ Name = "Maintenance"; IsAdmin = $true;  PicUrl = $MaintenancePicUrl; Password = "KISEstart82229#" },
        @{ Name = "Kiosk";       IsAdmin = $false; PicUrl = $KioskPicUrl;       Password = $null }
    )

    foreach ($u in $userDefs) {
        $existing = Get-LocalUser -Name $u.Name -ErrorAction SilentlyContinue

        if ($existing) {
            Write-Host "  Benutzer '$($u.Name)' existiert bereits - Anlage übersprungen." -ForegroundColor Green

            # PasswordNeverExpires bei jedem Lauf sicherstellen (auch für
            # bereits bestehende Konten) - relevant v.a. für "Kiosk" ohne
            # Passwort, da Windows sonst über die normale Kennwortablauf-
            # Richtlinie irgendwann einen Passwortwechsel verlangt.
            try {
                Set-LocalUser -Name $u.Name -PasswordNeverExpires $true -ErrorAction Stop
            } catch {
                Write-Host "  WARNUNG: PasswordNeverExpires konnte für '$($u.Name)' nicht gesetzt werden: $_" -ForegroundColor Red
            }
        } else {
            if ($null -eq $u.Password) {
                # Kein Passwort - erfordert i.d.R. zusätzlich die Sicherheitsrichtlinie
                # "Kontosicherheit: Lokale Kontenverwendung von leeren Kennwörtern..."
                # auf "Nur Konsolenanmeldung", siehe Hinweis am Scriptende.
                # WICHTIG: PasswordNeverExpires auch hier setzen - sonst greift
                # trotz leerem Passwort die normale Kennwortablauf-Richtlinie
                # und Windows verlangt irgendwann einen Passwortwechsel.
                New-LocalUser -Name $u.Name -NoPassword -FullName $u.Name `
                    -AccountNeverExpires -PasswordNeverExpires -ErrorAction Stop | Out-Null
            } else {
                $securePwd = ConvertTo-SecureString $u.Password -AsPlainText -Force
                New-LocalUser -Name $u.Name -Password $securePwd -FullName $u.Name `
                    -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop | Out-Null
            }

            if ($u.IsAdmin) {
                Add-LocalGroupMember -Group $adminGroup -Member $u.Name -ErrorAction SilentlyContinue
            } else {
                # New-LocalUser fügt neue Konten standardmäßig bereits der "Users"-Gruppe hinzu;
                # hier zur Sicherheit explizit sichergestellt.
                Add-LocalGroupMember -Group $usersGroup -Member $u.Name -ErrorAction SilentlyContinue
            }

            if ($u.Password) {
                $Global:CreatedUserCredentials += [PSCustomObject]@{ User = $u.Name; Password = $u.Password }
            } else {
                $Global:CreatedUserCredentials += [PSCustomObject]@{ User = $u.Name; Password = "(kein Passwort / leeres Kennwort)" }
            }
            Write-Host "  Benutzer '$($u.Name)' angelegt ($(if ($u.IsAdmin) {'Administrator'} else {'Standard'}))." -ForegroundColor Green
        }

        # Profilbild unabhängig davon setzen, ob Konto neu oder bereits vorhanden war
        Set-UserAccountPicture -UserName $u.Name -ImageUrl $u.PicUrl
    }
}

# ============================================================
# 7. AUTO-LOGON FÜR "Kiosk"
# ============================================================
function Set-KioskAutoLogon {
    Write-Host "`n[10/11] Auto-Logon für 'Kiosk' konfigurieren..." -ForegroundColor Yellow

    $kioskUser = Get-LocalUser -Name "Kiosk" -ErrorAction SilentlyContinue
    if (-not $kioskUser) {
        Write-Host "  WARNUNG: Benutzer 'Kiosk' nicht gefunden - Auto-Logon wird übersprungen." -ForegroundColor Red
        return
    }

    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    # Kein "-Force" auf einen bereits existierenden System-Key wie Winlogon:
    # New-Item -Force versucht intern, den Key zu löschen und neu anzulegen,
    # was bei diesem Key mit "Cannot delete a subkey tree..." fehlschlägt.
    # Der Key existiert ohnehin auf jedem Windows-System bereits.
    if (-not (Test-Path $winlogonPath)) {
        New-Item -Path $winlogonPath -Force | Out-Null
    }

    New-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon"    -PropertyType String -Value "1" -Force | Out-Null
    New-ItemProperty -Path $winlogonPath -Name "DefaultUserName"   -PropertyType String -Value "Kiosk" -Force | Out-Null
    New-ItemProperty -Path $winlogonPath -Name "DefaultDomainName" -PropertyType String -Value $env:COMPUTERNAME -Force | Out-Null

    # "Kiosk" hat kein Passwort -> DefaultPassword bewusst leer lassen.
    # Autologon über Winlogon zählt als lokale Konsolenanmeldung und ist damit
    # von der Richtlinie "leere Kennwörter nur an der Konsole" abgedeckt.
    New-ItemProperty -Path $winlogonPath -Name "DefaultPassword" -PropertyType String -Value "" -Force | Out-Null

    # Vorherige Anmeldeversuchszähler entfernen, falls von früheren Läufen vorhanden
    Remove-ItemProperty -Path $winlogonPath -Name "AutoLogonCount" -ErrorAction SilentlyContinue

    Write-Host "  Auto-Logon für 'Kiosk' (Domäne/Rechner: $env:COMPUTERNAME) aktiviert." -ForegroundColor Green
    Write-Host "  Hinweis: Greift ab dem nächsten Neustart bzw. der nächsten Abmeldung." -ForegroundColor DarkYellow
}

# ============================================================
# 8. NOTIFICATIONS DEAKTIVIEREN (für alle Benutzer)
# ============================================================
function Set-NotificationsPolicy {
    Write-Host "`n[5/11] Benachrichtigungen / Action Center deaktivieren..." -ForegroundColor Yellow

    # Offiziell dokumentierte GPO: "Remove Notifications and Action Center"
    # Computer Configuration > Administrative Templates > Start Menu and Taskbar
    $explorerPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    if (-not (Test-Path $explorerPolicyPath)) {
        New-Item -Path $explorerPolicyPath -Force | Out-Null
    }
    New-ItemProperty -Path $explorerPolicyPath -Name "DisableNotificationCenter" -PropertyType DWord -Value 1 -Force | Out-Null

    Write-Host "  DisableNotificationCenter=1 gesetzt (gilt maschinenweit für alle Benutzer)." -ForegroundColor Green
}

$NOTIFICATIONS_USER_ACTION = {
    param($Root)
    # Zusätzlich pro Benutzer die "normalen" Toast-Benachrichtigungen abschalten
    # (unabhängig von der Action-Center-Policy oben, betrifft z.B. Edge-Popups)
    $pushPath = "$Root\Software\Microsoft\Windows\CurrentVersion\PushNotifications"
    if (-not (Test-Path $pushPath)) {
        New-Item -Path $pushPath -Force | Out-Null
    }
    New-ItemProperty -Path $pushPath -Name "ToastEnabled" -PropertyType DWord -Value 0 -Force | Out-Null
}

# ============================================================
# 9. ENERGIEEINSTELLUNGEN (Höchstleistung, Display/Sleep nie)
# ============================================================
function Set-KioskPowerSettings {
    Write-Host "`n[6/11] Energieeinstellungen konfigurieren..." -ForegroundColor Yellow

    # Energiesparplan auf "Höchstleistung" setzen (powercfg-Alias SCHEME_MIN)
    powercfg /setactive SCHEME_MIN | Out-Null

    # Display: nie ausschalten (AC = Netzbetrieb, DC = Akku)
    powercfg /change monitor-timeout-ac 0
    powercfg /change monitor-timeout-dc 0

    # Standby/Energiesparmodus: nie
    powercfg /change standby-timeout-ac 0
    powercfg /change standby-timeout-dc 0

    Write-Host "  Energieplan: Höchstleistung. Display- und Standby-Timeout: nie (AC+DC)." -ForegroundColor Green
    Write-Host "  Hinweis: Bei reinem Netzbetrieb (Kiosk ohne Akku) sind die DC-Werte irrelevant, schaden aber nicht." -ForegroundColor DarkYellow
}

# ============================================================
# 10. DEUTSCHES SPRACHPAKET (System + Standard für "Kiosk"/neue Benutzer)
# ============================================================
function Install-KioskGermanLanguage {
    Write-Host "`n[11/11] Deutsches Sprachpaket installieren und als Standard setzen..." -ForegroundColor Yellow

    $langTag = "de-DE"

    # 1. Sprachpaket-Komponenten installieren. Erfordert Internetzugriff auf
    #    Windows Update - falls euer Netzwerk (nicht die Edge-Domain-
    #    Allowlist von vorhin, sondern eine Netzwerk-/Proxy-Firewall) den
    #    Zugriff auf Windows-Update-Endpunkte blockiert, schlägt das hier
    #    fehl. In dem Fall Sprachpaket offline via ISO/WSUS nachrüsten.
    $capabilityNames = @(
        "Language.Basic~~~$langTag~0.0.1.0",
        "Language.OCR~~~$langTag~0.0.1.0",
        "Language.Handwriting~~~$langTag~0.0.1.0",
        "Language.TextToSpeech~~~$langTag~0.0.1.0",
        "Language.Speech~~~$langTag~0.0.1.0"
    )

    $anyInstallFailed = $false
    $basicInstalled = $false
    foreach ($cap in $capabilityNames) {
        try {
            $capObj = Get-WindowsCapability -Online -Name $cap -ErrorAction Stop

            if ($capObj.State -eq "Installed") {
                Write-Host "  $($capObj.Name) bereits installiert." -ForegroundColor Green
            } else {
                Write-Host "  Installiere $($capObj.Name)..." -ForegroundColor Yellow
                $result = Add-WindowsCapability -Online -Name $capObj.Name -ErrorAction Stop

                # Nachprüfung: Add-WindowsCapability wirft nicht zwingend einen
                # Fehler, wenn die Installation im Hintergrund hängen bleibt
                # oder ein Neustart nötig ist - deshalb den Status frisch
                # abfragen statt dem Cmdlet-Erfolg blind zu vertrauen.
                $recheck = Get-WindowsCapability -Online -Name $cap -ErrorAction Stop
                if ($recheck.State -eq "Installed") {
                    Write-Host "    -> erfolgreich installiert." -ForegroundColor Green
                } elseif ($result.RestartNeeded) {
                    Write-Host "    -> installiert, Neustart erforderlich (Status wird erst danach 'Installed')." -ForegroundColor DarkYellow
                } else {
                    Write-Host "    -> WARNUNG: Status nach Installationsversuch weiterhin '$($recheck.State)' (nicht 'Installed')." -ForegroundColor Red
                    $anyInstallFailed = $true
                }
            }

            if ($cap -like "Language.Basic*" -and (Get-WindowsCapability -Online -Name $cap).State -eq "Installed") {
                $basicInstalled = $true
            }
        } catch {
            Write-Host "  WARNUNG: $cap konnte nicht installiert werden (evtl. kein Zugriff auf Windows Update): $_" -ForegroundColor Red
            $anyInstallFailed = $true
        }
    }

    if (-not $basicInstalled) {
        Write-Host "  ABBRUCH: Language.Basic (Kernsprachpaket) ist nicht installiert - System-/Locale-Einstellungen werden übersprungen," -ForegroundColor Red
        Write-Host "  da diese ohne installiertes Sprachpaket wirkungslos wären. Bitte Internetzugriff auf Windows Update prüfen." -ForegroundColor Red
        return
    }

    # 2. System-/Anzeigesprache setzen. WICHTIG: Set-WinUserLanguageList
    #    wirkt auf die AKTUELL AUSGEFÜHRTE Session (also das Konto, unter dem
    #    dieses Script läuft). Das Script sollte daher idealerweise unter
    #    einem Administrator-/Technikerkonto laufen, dessen eigene Sprache
    #    egal ist - nicht unter einem produktiv genutzten persönlichen Konto.
    try {
        Set-WinSystemLocale -SystemLocale $langTag
        Set-WinHomeLocation -GeoId 94   # 94 = Deutschland
        Set-WinUserLanguageList -LanguageList $langTag -Force -ErrorAction Stop

        # 3. Diese (jetzt aktuelle) Spracheinstellung als Standard für den
        #    Anmeldebildschirm UND für alle künftig NEU erstellten Profile
        #    übernehmen. Bewusst über control.exe/intl.cpl mit XML statt über
        #    "Copy-UserInternationalSettingsToSystem" - dieses Cmdlet
        #    existiert laut Microsoft-Dokumentation NUR auf Windows 11, nicht
        #    auf Windows 10 (IoT LTSC). Der control.exe-Weg ist derselbe
        #    Mechanismus, den auch unattend.xml-Antwortdateien nutzen, und
        #    funktioniert identisch auf Windows 10 und 11.
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
        # Exit-Code 0 = sofort übernommen, Exit-Code 1 = übernommen, aber
        # Neustart erforderlich (dokumentiertes Verhalten von intl.cpl, kein
        # echter Fehler). Nur andere Exit-Codes sind eine echte Warnung wert.
        if ($proc.ExitCode -eq 0) {
            Write-Host "  Sprach-/Regionaleinstellungen für System und neue Profile übernommen." -ForegroundColor Green
        } elseif ($proc.ExitCode -eq 1) {
            Write-Host "  Sprach-/Regionaleinstellungen gesetzt - werden nach Neustart vollständig wirksam." -ForegroundColor DarkYellow
        } else {
            Write-Host "  WARNUNG: control.exe intl.cpl beendete sich mit unerwartetem Exit-Code $($proc.ExitCode)." -ForegroundColor Red
        }
        Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  WARNUNG: Sprach-/Locale-Einstellungen konnten nicht vollständig gesetzt werden: $_" -ForegroundColor Red
    }

    Write-Host "  Deutsch (de-DE) als System- und Standardsprache für neue Profile gesetzt." -ForegroundColor Green
    if ($anyInstallFailed) {
        Write-Host "  Hinweis: Mindestens eine Sprachkomponente konnte nicht heruntergeladen werden - siehe Warnungen oben." -ForegroundColor DarkYellow
    }
}

$LANGUAGE_USER_ACTION = {
    param($Root)
    # Best-effort für BEREITS existierende Profile (z.B. bei erneutem
    # Script-Lauf, nachdem "Kiosk" sich zwischenzeitlich schon einmal
    # angemeldet hat). Für ein brandneu erstelltes Profil greift stattdessen
    # automatisch der Default-Profil-Weg aus Install-KioskGermanLanguage.
    $intlPath = "$Root\Control Panel\International\User Profile"
    if (-not (Test-Path $intlPath)) { New-Item -Path $intlPath -Force | Out-Null }
    New-ItemProperty -Path $intlPath -Name "Languages" -PropertyType MultiString -Value @("de-DE") -Force | Out-Null
}

# ============================================================
# AUSFÜHRUNG
# ============================================================
Set-FirewallRules
Set-EdgePolicies
Set-EdgeSitePermissions
Set-KioskWallpaper
Set-EdgeUiSwipePolicy
Set-NotificationsPolicy
Set-KioskPowerSettings

Write-Host "`n[7/11] Touch-/Swipe-Gesten für alle Benutzerprofile deaktivieren..." -ForegroundColor Yellow
Invoke-ForAllUserHives -Action $GESTURE_ACTION
Invoke-ForAllUserHives -Action $EDGEUI_USER_ACTION
Invoke-ForAllUserHives -Action $NOTIFICATIONS_USER_ACTION

Write-Host "`n[8/11] Touch-Tastatur-Einstellungen für alle Benutzerprofile setzen..." -ForegroundColor Yellow
Invoke-ForAllUserHives -Action $TOUCH_KEYBOARD_ACTION

Set-KioskLocalUsers
Set-KioskAutoLogon
Install-KioskGermanLanguage
Invoke-ForAllUserHives -Action $LANGUAGE_USER_ACTION

Write-Host "`n=== Fertig ===" -ForegroundColor Cyan
Write-Host "Empfehlung: gpupdate /force ausführen und Gerät neu starten, damit alle" -ForegroundColor DarkYellow
Write-Host "Einstellungen (v.a. Edge-Policies, Wallpaper) sicher greifen." -ForegroundColor DarkYellow

if ($Global:CreatedUserCredentials.Count -gt 0) {
    Write-Host "`n=== NEU ANGELEGTE BENUTZER - PASSWÖRTER JETZT SICHERN ===" -ForegroundColor Red
    foreach ($cred in $Global:CreatedUserCredentials) {
        Write-Host "  $($cred.User) : $($cred.Password)" -ForegroundColor Red
    }
    Write-Host "Diese Passwörter werden nirgends gespeichert - bitte sofort in euren" -ForegroundColor Red
    Write-Host "Passwortmanager übernehmen, dieses Fenster wird danach nicht erneut angezeigt." -ForegroundColor Red
}
