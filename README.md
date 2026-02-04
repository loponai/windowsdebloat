# Windows Debloat & Privacy Script

A one-shot PowerShell script that removes bloatware, disables telemetry, and hardens privacy settings on Windows 10/11.

**Free & Open Source** - No spyware, no BS.

---

## Quick Start

1. **Download** the script: [Windows-Debloat.ps1](https://raw.githubusercontent.com/loponai/windowsdebloat/main/Windows-Debloat.ps1)

2. **Right-click PowerShell** → Run as Administrator

3. **Run these commands:**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
cd ~\Downloads
.\Windows-Debloat.ps1
```

4. **Restart** when prompted

> A System Restore Point is created automatically before any changes are made.

---

## What It Does

### Removes Bloatware (70+ Apps)
- Candy Crush, Solitaire, and other games
- Microsoft Teams, Skype, Your Phone
- Xbox apps (optional - comment out if you game)
- Third-party junk (TikTok, Netflix, Spotify preinstalls)
- OneDrive (fully removed)

### Disables Telemetry
- Windows telemetry and diagnostic data
- Customer Experience Improvement Program
- Application telemetry
- Error reporting
- Blocks 50+ Microsoft telemetry domains via hosts file
- Firewall rules blocking telemetry IPs

### Privacy Hardening
- Disables Cortana
- Disables Copilot AI
- Disables Recall (Windows 11 24H2 AI screenshots)
- Disables advertising ID and targeted ads
- Disables activity history and timeline
- Disables location tracking
- Disables input personalization (typing/inking data)
- Disables clipboard history sync

### Windows 11 Specific
- Removes Widgets
- Removes Teams chat icon
- Restores classic right-click context menu
- Disables search highlights

### Network Privacy
- Sets DNS to Cloudflare (1.1.1.1) - easily changeable
- Enables DNS over HTTPS
- Disables NetBIOS over TCP/IP
- Disables LLMNR
- Disables SMBv1 (security risk)
- Disables WiFi Sense

### Security Hardening
- Disables Remote Assistance
- Disables Find My Device
- Windows Defender kept ON (just reduces telemetry)

### Performance Tweaks
- Disables background apps
- Disables hibernation
- Shows file extensions
- Shows hidden files
- Opens Explorer to "This PC"

---

## Customization

The script is fully commented. To keep something:

1. Open `Windows-Debloat.ps1` in a text editor
2. Find the section you want to modify
3. Comment out lines with `#`

**Example:** Keep Xbox apps for gaming:
```powershell
# "Microsoft.GamingApp"                  # Comment out if you game
# "Microsoft.Xbox.TCUI"                  # Comment out if you game
```

---

## Take Your Privacy Further

This script fixes Windows, but your **ISP still sees everything** you do online.

### NordVPN - Hide Your Traffic
Your ISP logs every website you visit. A VPN encrypts your connection so they see nothing.

**Get 4 extra months + discount:** https://nordvpn.tomspark.tech/

### Incogni - Remove Your Data From Brokers
180+ data brokers are selling your name, address, and phone number right now. This is how doxxing happens. Incogni sends removal requests automatically.

**Protect your identity:** https://incogni.tomspark.tech/

---

## Manual Privacy Checklist

Things you should do manually:

| Step | What | Why |
|------|------|-----|
| 1 | Use a local account | Microsoft accounts sync everything to the cloud |
| 2 | Enable BitLocker | Encrypts your drive - protects against theft |
| 3 | Switch browser | Use Firefox, Brave, or LibreWolf instead of Edge |
| 4 | Install uBlock Origin | Best ad/tracker blocker |
| 5 | Remove OEM bloatware | Dell/HP/Lenovo install their own spyware |
| 6 | Review app permissions | Settings → Privacy → Check camera, mic, location |
| 7 | Use Bitwarden | Free password manager - stop reusing passwords |
| 8 | Enable 2FA | Use Aegis/Raivo, never SMS |

---

## Restore / Undo

If something breaks:

1. Search "Recovery" in Start Menu
2. Open "Recovery Options"
3. Click "Open System Restore"
4. Select restore point: **"Before Windows Debloat"**

---

## About

Created by **Tom Spark** - a self-funded independent VPN review channel on YouTube.

No corporate sponsors. No BS.

If this script helped you, consider using the affiliate links above - costs you nothing extra and helps keep the project going.

---

## License

MIT License - Do whatever you want with it.
