<#
.SYNOPSIS
    Windows Debloat Script for Privacy-Minded Users
.DESCRIPTION
    Removes bloatware, disables telemetry, and configures privacy settings.
    Automatically requests Administrator privileges if needed.
.NOTES
    - Creates a restore point before making changes
    - Some changes require a restart to take effect
    - Review each section and comment out anything you want to keep
#>

# Self-elevate to Administrator if not already running as admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    } catch {
        Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
        Write-Host "Right-click PowerShell and select 'Run as Administrator', then run this script again." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    exit
}

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

Clear-Host
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║                                                               ║" -ForegroundColor Cyan
Write-Host "  ║           WINDOWS DEBLOAT & PRIVACY SCRIPT                    ║" -ForegroundColor Cyan
Write-Host "  ║                                                               ║" -ForegroundColor Cyan
Write-Host "  ║     Free & Open Source - No Spyware, No BS                    ║" -ForegroundColor Cyan
Write-Host "  ║                                                               ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  This script is 100% FREE and open source." -ForegroundColor White
Write-Host "  Created by Tom Spark - a self-funded independent VPN" -ForegroundColor Gray
Write-Host "  review channel on YouTube. No corporate sponsors." -ForegroundColor Gray
Write-Host ""
Write-Host "  If this script helped you, consider supporting through" -ForegroundColor Gray
Write-Host "  the affiliate links below (costs you nothing extra):" -ForegroundColor Gray
Write-Host ""
Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   NORDVPN - Stop Your ISP From Spying On You" -ForegroundColor Green
Write-Host ""
Write-Host "   This script blocks Microsoft's tracking, but your ISP still" -ForegroundColor White
Write-Host "   sees EVERY website you visit. They log it and sell it." -ForegroundColor White
Write-Host "   A VPN encrypts your traffic so your ISP sees nothing." -ForegroundColor White
Write-Host ""
Write-Host "   GET 4 EXTRA MONTHS + BIG DISCOUNT:" -ForegroundColor Yellow
Write-Host "   https://nordvpn.tomspark.tech/" -ForegroundColor Cyan
Write-Host ""
$OpenNord = Read-Host "   Open NordVPN link in browser? (y/n)"
if ($OpenNord -eq "y" -or $OpenNord -eq "Y") {
    Start-Process "https://nordvpn.tomspark.tech/"
}
Write-Host ""
Write-Host "  ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   INCOGNI - Remove Yourself From Data Broker Sites" -ForegroundColor Green
Write-Host ""
Write-Host "   Your name, address, phone number, and more are being sold" -ForegroundColor White
Write-Host "   by 180+ data brokers right now. This is how doxxing happens." -ForegroundColor White
Write-Host "   Incogni sends removal requests on your behalf automatically." -ForegroundColor White
Write-Host ""
Write-Host "   PROTECT YOUR IDENTITY:" -ForegroundColor Yellow
Write-Host "   https://incogni.tomspark.tech/" -ForegroundColor Cyan
Write-Host ""
$OpenIncogni = Read-Host "   Open Incogni link in browser? (y/n)"
if ($OpenIncogni -eq "y" -or $OpenIncogni -eq "Y") {
    Start-Process "https://incogni.tomspark.tech/"
}
Write-Host ""
Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   MANUAL PRIVACY CHECKLIST" -ForegroundColor Magenta
Write-Host ""
Write-Host "   [1] USE A LOCAL ACCOUNT (not Microsoft account)" -ForegroundColor White
Write-Host "       Settings > Accounts > Sign in with local account instead" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   [2] ENABLE BITLOCKER - Encrypt your drive" -ForegroundColor White
Write-Host "       Search 'BitLocker' > Turn on BitLocker" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   [3] DITCH EDGE - Use Firefox, Brave, or LibreWolf" -ForegroundColor White
Write-Host "       firefox.com | brave.com | librewolf.net" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   [4] INSTALL UBLOCK ORIGIN - Best ad/tracker blocker" -ForegroundColor White
Write-Host "       Get it from your browser's extension store" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   [5] REMOVE OEM BLOATWARE - Dell/HP/Lenovo spyware" -ForegroundColor White
Write-Host "       Uninstall: SupportAssist, TouchPoint Analytics, etc." -ForegroundColor DarkGray
Write-Host ""
Write-Host "   [6] REVIEW APP PERMISSIONS - Camera, Mic, Location" -ForegroundColor White
Write-Host "       Settings > Privacy & Security > App Permissions" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   [7] USE BITWARDEN - Free open-source password manager" -ForegroundColor White
Write-Host "       bitwarden.com - Stop reusing passwords!" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   [8] ENABLE 2FA - Use Aegis, Raivo, or Bitwarden TOTP" -ForegroundColor White
Write-Host "       Never use SMS for two-factor authentication" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Press any key to start the debloat process..." -ForegroundColor Yellow
Write-Host ""
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# Create a system restore point first
Write-Host "[*] Creating System Restore Point..." -ForegroundColor Yellow
Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
Checkpoint-Computer -Description "Before Windows Debloat" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue

#region ============== REMOVE BLOATWARE APPS ==============
Write-Host "[*] Removing Bloatware Apps..." -ForegroundColor Yellow

$BloatwareApps = @(
    # Microsoft Bloatware
    "Microsoft.3DBuilder"
    "Microsoft.549981C3F5F10"          # Cortana
    "Microsoft.Advertising.Xaml"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MixedReality.Portal"
    "Microsoft.Office.OneNote"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    "Microsoft.WindowsAlarms"
    "Microsoft.WindowsCommunicationsApps"  # Mail & Calendar
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "MicrosoftTeams"
    "Microsoft.Todos"
    "Microsoft.PowerAutomateDesktop"
    "Microsoft.BingSearch"
    "Microsoft.WindowsCamera"              # Comment out if you use camera
    "Microsoft.GamingApp"                  # Comment out if you game
    "Microsoft.Xbox.TCUI"                  # Comment out if you game
    "Microsoft.XboxApp"                    # Comment out if you game
    "Microsoft.XboxGameOverlay"            # Comment out if you game
    "Microsoft.XboxGamingOverlay"          # Comment out if you game
    "Microsoft.XboxIdentityProvider"       # Comment out if you game
    "Microsoft.XboxSpeechToTextOverlay"    # Comment out if you game

    # Third-party Bloatware
    "2FE3CB00.PicsArt-PhotoStudio"
    "46928bounde.EclipseManager"
    "4DF9E0F8.Netflix"
    "613EBCEA.PolarrPhotoEditorAcademicEdition"
    "6Wunderkinder.Wunderlist"
    "7EE7776C.LinkedInforWindows"
    "89006A2E.AutodeskSketchBook"
    "9E2F88E3.Twitter"
    "A278AB0D.DisneyMagicKingdoms"
    "A278AB0D.MarchofEmpires"
    "ActiproSoftwareLLC.562882FEEB491"
    "AdobeSystemsIncorporated.AdobePhotoshopExpress"
    "CAF9E577.Plex"
    "ClearChannelRadioDigital.iHeartRadio"
    "D52A8D61.FarmVille2CountryEscape"
    "D5EA27B7.Duolingo-LearnLanguagesforFree"
    "DB6EA5DB.CyberLinkMediaSuiteEssentials"
    "DolbyLaboratories.DolbyAccess"
    "Drawboard.DrawboardPDF"
    "Fitbit.FitbitCoach"
    "Flipboard.Flipboard"
    "GAMELOFTSA.Asphalt8Airborne"
    "KeeperSecurityInc.Keeper"
    "king.com.BubbleWitch3Saga"
    "king.com.CandyCrushFriends"
    "king.com.CandyCrushSaga"
    "king.com.CandyCrushSodaSaga"
    "king.com.FarmHeroesSaga"
    "Nordcurrent.CookingFever"
    "PandoraMediaInc.29680B314EFC2"
    "PricelinePartnerNetwork.Booking.comBi498tele498702702702"
    "SpotifyAB.SpotifyMusic"
    "ThumbmunkeysLtd.PhototasticCollage"
    "WinZipComputing.WinZipUniversal"
    "XINGAG.XING"
    "flaregamesGmbH.RoyalRevolt2"
    "Clipchamp.Clipchamp"
    "Disney.37853FC22B2CE"
    "BytedancePte.Ltd.TikTok"
)

foreach ($App in $BloatwareApps) {
    Write-Host "  Removing: $App" -ForegroundColor Gray
    Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}
#endregion

#region ============== DISABLE TELEMETRY & DATA COLLECTION ==============
Write-Host "[*] Disabling Telemetry & Data Collection..." -ForegroundColor Yellow

# Disable Telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

# Disable Application Telemetry
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0

# Disable Customer Experience Improvement Program
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0 -ErrorAction SilentlyContinue
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0

# Disable Diagnostic Data
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -Type DWord -Value 1

# Disable Feedback
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Type DWord -Value 0

# Disable Tailored Experiences
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

# Disable Advertising ID
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

# Disable Error Reporting
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" -ErrorAction SilentlyContinue

# Disable DiagTrack Service
Stop-Service "DiagTrack" -Force -ErrorAction SilentlyContinue
Set-Service "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue

# Disable dmwappushservice (WAP Push Message Routing Service)
Stop-Service "dmwappushservice" -Force -ErrorAction SilentlyContinue
Set-Service "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue
#endregion

#region ============== PRIVACY SETTINGS ==============
Write-Host "[*] Configuring Privacy Settings..." -ForegroundColor Yellow

# Disable Activity History
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

# Disable Location Tracking
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1

# Disable App Launch Tracking
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 0

# Disable Website Access to Language List
New-Item -Path "HKCU:\Control Panel\International\User Profile" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1

# Disable Input Personalization (Typing/Inking)
New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0

# Disable Online Speech Recognition
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 0

# Disable App Diagnostics
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" -Name "Value" -Type String -Value "Deny"

# Disable Clipboard History
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowClipboardHistory" -Type DWord -Value 0

# Disable Timeline
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
#endregion

#region ============== DISABLE CORTANA ==============
Write-Host "[*] Disabling Cortana..." -ForegroundColor Yellow

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWebOverMeteredConnections" -Type DWord -Value 0

# Disable Cortana in Search
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Type DWord -Value 0
#endregion

#region ============== DISABLE WINDOWS SUGGESTIONS & ADS ==============
Write-Host "[*] Disabling Windows Suggestions & Ads..." -ForegroundColor Yellow

# Disable Start Menu Suggestions
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0

# Disable Suggested Apps
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0

# Disable Tips, Tricks, and Suggestions
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0

# Disable Lock Screen Spotlight & Tips
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0

# Disable Settings App Suggestions
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0

# Disable "Get the most out of Windows" Welcome Experience
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
#endregion

#region ============== DISABLE SCHEDULED TASKS (TELEMETRY) ==============
Write-Host "[*] Disabling Telemetry Scheduled Tasks..." -ForegroundColor Yellow

$TasksToDisable = @(
    "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
    "Microsoft\Windows\Application Experience\ProgramDataUpdater"
    "Microsoft\Windows\Autochk\Proxy"
    "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
    "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
    "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    "Microsoft\Windows\Feedback\Siuf\DmClient"
    "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
    "Microsoft\Windows\Maps\MapsToastTask"
    "Microsoft\Windows\Maps\MapsUpdateTask"
    "Microsoft\Windows\Shell\FamilySafetyMonitor"
    "Microsoft\Windows\Shell\FamilySafetyRefreshTask"
    "Microsoft\Windows\Windows Error Reporting\QueueReporting"
    "Microsoft\Windows\Application Experience\StartupAppTask"
    "Microsoft\Windows\PI\Sqm-Tasks"
    "Microsoft\Windows\NetTrace\GatherNetworkInfo"
)

foreach ($Task in $TasksToDisable) {
    Disable-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue | Out-Null
}
#endregion

#region ============== BLOCK TELEMETRY VIA HOSTS ==============
Write-Host "[*] Blocking Telemetry Domains via Hosts File..." -ForegroundColor Yellow

$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$TelemetryDomains = @(
    "vortex.data.microsoft.com"
    "vortex-win.data.microsoft.com"
    "telecommand.telemetry.microsoft.com"
    "telecommand.telemetry.microsoft.com.nsatc.net"
    "oca.telemetry.microsoft.com"
    "oca.telemetry.microsoft.com.nsatc.net"
    "sqm.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com.nsatc.net"
    "watson.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com.nsatc.net"
    "redir.metaservices.microsoft.com"
    "choice.microsoft.com"
    "choice.microsoft.com.nsatc.net"
    "df.telemetry.microsoft.com"
    "reports.wes.df.telemetry.microsoft.com"
    "wes.df.telemetry.microsoft.com"
    "services.wes.df.telemetry.microsoft.com"
    "sqm.df.telemetry.microsoft.com"
    "telemetry.microsoft.com"
    "watson.ppe.telemetry.microsoft.com"
    "telemetry.appex.bing.net"
    "telemetry.urs.microsoft.com"
    "telemetry.appex.bing.net:443"
    "settings-sandbox.data.microsoft.com"
    "vortex-sandbox.data.microsoft.com"
    "survey.watson.microsoft.com"
    "watson.live.com"
    "watson.microsoft.com"
    "statsfe2.ws.microsoft.com"
    "corpext.msitadfs.glbdns2.microsoft.com"
    "compatexchange.cloudapp.net"
    "cs1.wpc.v0cdn.net"
    "a-0001.a-msedge.net"
    "statsfe2.update.microsoft.com.akadns.net"
    "sls.update.microsoft.com.akadns.net"
    "fe2.update.microsoft.com.akadns.net"
    "diagnostics.support.microsoft.com"
    "corp.sts.microsoft.com"
    "statsfe1.ws.microsoft.com"
    "pre.footprintpredict.com"
    "i1.services.social.microsoft.com"
    "i1.services.social.microsoft.com.nsatc.net"
    "feedback.windows.com"
    "feedback.microsoft-hohm.com"
    "feedback.search.microsoft.com"
)

$HostsContent = Get-Content $HostsPath -ErrorAction SilentlyContinue
$NewEntries = @()

foreach ($Domain in $TelemetryDomains) {
    if ($HostsContent -notcontains "0.0.0.0 $Domain") {
        $NewEntries += "0.0.0.0 $Domain"
    }
}

if ($NewEntries.Count -gt 0) {
    Add-Content -Path $HostsPath -Value "`n# Windows Telemetry Block"
    Add-Content -Path $HostsPath -Value $NewEntries
}
#endregion

#region ============== PERFORMANCE TWEAKS ==============
Write-Host "[*] Applying Performance Tweaks..." -ForegroundColor Yellow

# Disable Background Apps
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2 -ErrorAction SilentlyContinue

# Disable Hibernation (saves disk space)
powercfg /h off

# Disable Fast Startup (can cause issues)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0

# Disable SysMain (Superfetch) - Optional, can improve SSD life
# Stop-Service "SysMain" -Force -ErrorAction SilentlyContinue
# Set-Service "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue

# Disable Windows Search Indexing - Optional, uncomment if you don't use search
# Stop-Service "WSearch" -Force -ErrorAction SilentlyContinue
# Set-Service "WSearch" -StartupType Disabled -ErrorAction SilentlyContinue
#endregion

#region ============== EXPLORER & UI TWEAKS ==============
Write-Host "[*] Applying Explorer & UI Tweaks..." -ForegroundColor Yellow

# Show File Extensions
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

# Show Hidden Files
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1

# Disable Recent Files in Quick Access
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0

# Disable Frequent Folders in Quick Access
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0

# Use This PC as Default Explorer View
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

# Disable Edge Desktop Shortcut on Update
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Type DWord -Value 1

# Disable "Look For An App In The Store" for Unknown Extensions
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1

# Disable Windows Ink Workspace
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Type DWord -Value 0
#endregion

#region ============== WINDOWS UPDATE SETTINGS ==============
Write-Host "[*] Configuring Windows Update (Not Disabling - Security Risk)..." -ForegroundColor Yellow

# Disable Auto-Restart After Updates
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1

# Disable Driver Updates Through Windows Update
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Disable P2P Update Downloads Outside Local Network
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
#endregion

#region ============== OPTIONAL: REMOVE ONEDRIVE ==============
Write-Host "[*] Removing OneDrive..." -ForegroundColor Yellow

# Stop OneDrive
Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue

# Uninstall OneDrive
if (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") {
    Start-Process "$env:SystemRoot\System32\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait
}
if (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") {
    Start-Process "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait
}

# Remove OneDrive Leftovers
Remove-Item -Path "$env:USERPROFILE\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\OneDriveTemp" -Recurse -Force -ErrorAction SilentlyContinue

# Disable OneDrive via Group Policy
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1

# Remove OneDrive from Explorer Sidebar
New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force -ErrorAction SilentlyContinue
#endregion

#region ============== FIREWALL RULES FOR TELEMETRY ==============
Write-Host "[*] Adding Firewall Rules to Block Telemetry..." -ForegroundColor Yellow

# Block Telemetry IPs
$TelemetryIPs = @(
    "134.170.30.202"
    "137.116.81.24"
    "157.56.106.189"
    "184.86.53.99"
    "2.22.61.43"
    "2.22.61.66"
    "204.79.197.200"
    "23.218.212.69"
    "65.39.117.230"
    "65.55.108.23"
)

Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound -Action Block -RemoteAddress $TelemetryIPs -ErrorAction SilentlyContinue | Out-Null
#endregion

#region ============== WINDOWS 11 SPECIFIC ==============
Write-Host "[*] Applying Windows 11 Specific Tweaks..." -ForegroundColor Yellow

# Disable Copilot
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type DWord -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type DWord -Value 1

# Disable Recall (AI Screenshot Feature - Windows 11 24H2+)
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Type DWord -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Type DWord -Value 1

# Disable Widgets
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 0

# Disable Chat Icon (Teams)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Type DWord -Value 0

# Disable Search Highlights
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDynamicSearchBoxEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Restore Classic Right-Click Menu (Windows 11)
New-Item -Path "HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Type String -Value ""
#endregion

#region ============== WINDOWS DEFENDER HARDENING ==============
Write-Host "[*] Configuring Windows Defender (Keeping Protection, Reducing Telemetry)..." -ForegroundColor Yellow

# Disable Defender Sample Submission
Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue

# Disable Defender Cloud-Based Protection Telemetry (keeps local protection)
# Uncomment below if you want to disable cloud lookups (reduces protection slightly)
# Set-MpPreference -MAPSReporting 0 -ErrorAction SilentlyContinue

# Disable SpyNet Reporting
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2

# Keep Defender enabled but disable reporting
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 0 -ErrorAction SilentlyContinue
#endregion

#region ============== NETWORK PRIVACY ==============
Write-Host "[*] Configuring Network Privacy Settings..." -ForegroundColor Yellow

# Set DNS to Cloudflare (Privacy-Focused) - IPv4
# Change to your preferred DNS: Quad9 (9.9.9.9), AdGuard (94.140.14.14), etc.
$PrivateDNS = "1.1.1.1", "1.0.0.1"
$Adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($Adapter in $Adapters) {
    Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses $PrivateDNS -ErrorAction SilentlyContinue
}

# Enable DNS over HTTPS (Windows 11)
# Note: Requires DNS server that supports DoH
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -Type DWord -Value 2 -ErrorAction SilentlyContinue

# Disable NetBIOS over TCP/IP (reduces network exposure)
$RegKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
Get-ChildItem $RegKey | ForEach-Object {
    Set-ItemProperty -Path "$RegKey\$($_.PSChildName)" -Name "NetbiosOptions" -Type DWord -Value 2 -ErrorAction SilentlyContinue
}

# Disable LLMNR (Link-Local Multicast Name Resolution)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0

# Disable SMBv1 (Security Risk)
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue

# Disable WiFi Sense
New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0
#endregion

#region ============== REMOTE ACCESS HARDENING ==============
Write-Host "[*] Hardening Remote Access Settings..." -ForegroundColor Yellow

# Disable Remote Assistance
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Type DWord -Value 0

# Disable Remote Desktop (uncomment if you don't use it)
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
# Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

# Disable Find My Device
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" -Name "AllowFindMyDevice" -Type DWord -Value 0

# Disable Device Portal
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WebManagement\Service" -Name "EnableWebManagement" -Type DWord -Value 0 -ErrorAction SilentlyContinue
#endregion

#region ============== ADDITIONAL SERVICES TO DISABLE ==============
Write-Host "[*] Disabling Additional Privacy-Invasive Services..." -ForegroundColor Yellow

$ServicesToDisable = @(
    "DiagTrack"                    # Connected User Experiences and Telemetry
    "dmwappushservice"             # Device Management WAP Push
    "SysMain"                      # Superfetch - Optional, uncomment if on SSD
    # "WSearch"                    # Windows Search - Uncomment if you don't use search
    "MapsBroker"                   # Downloaded Maps Manager
    "lfsvc"                        # Geolocation Service
    "SharedAccess"                 # Internet Connection Sharing
    "RemoteRegistry"               # Remote Registry
    "RetailDemo"                   # Retail Demo Service
    "WMPNetworkSvc"                # Windows Media Player Network Sharing
    "WerSvc"                       # Windows Error Reporting Service
    "XblAuthManager"               # Xbox Live Auth Manager (comment if gaming)
    "XblGameSave"                  # Xbox Live Game Save (comment if gaming)
    "XboxNetApiSvc"                # Xbox Live Networking Service (comment if gaming)
    "XboxGipSvc"                   # Xbox Accessory Management (comment if gaming)
)

foreach ($Service in $ServicesToDisable) {
    Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue
    Set-Service -Name $Service -StartupType Disabled -ErrorAction SilentlyContinue
}
#endregion

#region ============== FINAL CLEANUP ==============
Write-Host "[*] Running Final Cleanup..." -ForegroundColor Yellow

# Clear Temp Files
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

# Clear Windows Update Cache
Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
#endregion

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║                                                               ║" -ForegroundColor Green
Write-Host "  ║                    DEBLOAT COMPLETE!                          ║" -ForegroundColor Green
Write-Host "  ║                                                               ║" -ForegroundColor Green
Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  A System Restore Point was created: 'Before Windows Debloat'" -ForegroundColor Cyan
Write-Host "  If anything breaks, you can restore from there." -ForegroundColor Cyan
Write-Host ""
Write-Host "  ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  REMEMBER: This script only fixes Windows. Your ISP still" -ForegroundColor Yellow
Write-Host "  sees everything unless you use a VPN." -ForegroundColor Yellow
Write-Host ""
Write-Host "  NordVPN (4 months free): https://nordvpn.tomspark.tech/" -ForegroundColor Cyan
$OpenNordEnd = Read-Host "  Open NordVPN link? (y/n)"
if ($OpenNordEnd -eq "y" -or $OpenNordEnd -eq "Y") {
    Start-Process "https://nordvpn.tomspark.tech/"
}
Write-Host ""
Write-Host "  Remove your data online: https://incogni.tomspark.tech/" -ForegroundColor Cyan
$OpenIncogniEnd = Read-Host "  Open Incogni link? (y/n)"
if ($OpenIncogniEnd -eq "y" -or $OpenIncogniEnd -eq "Y") {
    Start-Process "https://incogni.tomspark.tech/"
}
Write-Host ""
Write-Host "  ───────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Please RESTART your computer for all changes to take effect." -ForegroundColor White
Write-Host ""

# Prompt for restart
$Restart = Read-Host "  Restart now? (y/n)"
if ($Restart -eq "y" -or $Restart -eq "Y") {
    Restart-Computer -Force
} else {
    Write-Host ""
    Write-Host "  Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
