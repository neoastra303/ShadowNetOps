# RedTeam Terminal - Quick Start Guide

## 🚀 Launch the Application

Simply run:

```bash
python redteam.py
```

## 🎯 What You'll See

1. **Cyberpunk ASCII Banner** - RedTeam logo in neon cyan
2. **Main Menu** - 5 tool options displayed in a styled table
3. **Interactive Prompt** - `redteam@cyber ~$` command prompt

## 🛠️ Tool Overview

### 1️⃣ Network Reconnaissance
- **What it does**: Scans network targets for open ports
- **Input**: IP address or domain (e.g., `192.168.1.1` or `example.com`)
- **Output**: Colored table showing port status (open/closed/filtered)
- **Example**:
  ```
  Enter target IP or domain: 192.168.1.1
  
  Results:
  Port 22   SSH      ✓ OPEN
  Port 80   HTTP     ✓ OPEN
  Port 443  HTTPS    ✓ OPEN
  ```

### 2️⃣ Vulnerability Assessment
- **What it does**: Scans for security vulnerabilities with CVE database
- **Input**: Target domain or IP
- **Output**: Severity-rated vulnerability list (Critical/High/Medium/Low)
- **Features**: 
  - Color-coded severity levels (Red for Critical, Yellow for Medium, etc.)
  - CVE identifiers
  - Vulnerability descriptions
  - Summary statistics

### 3️⃣ Password Strength Tester
- **What it does**: Analyzes password security
- **Input**: Password to test (hidden input)
- **Output**: 
  - Strength rating (Very Weak → Very Strong)
  - Visual progress bar
  - Estimated crack time
  - Requirements checklist (length, uppercase, numbers, etc.)
- **Example**:
  ```
  Strength: Very Strong ■■■■■■■■■■ 100%
  Estimated crack time: Years
  
  ✓ At least 12 characters
  ✓ Uppercase letters
  ✓ Lowercase letters
  ✓ Numbers
  ✓ Special characters
  ```

### 4️⃣ OSINT Tools
- **What it does**: Open-source intelligence gathering
- **Input**: Domain, IP, or email
- **Output**: Public information like:
  - WHOIS registration data
  - DNS records
  - SSL certificate info
  - Breach database results
  - Social media profiles
  - Technology stack detection

### 5️⃣ Exit
- Clean shutdown of the terminal

## ⌨️ Navigation Tips

- Use **number keys (1-5)** to select tools
- Press **Ctrl+C** at any time to exit (graceful shutdown)
- All inputs have **default values** - just press Enter to use them
- Invalid inputs show **clear error messages**

## 🎨 Cyberpunk Features

- **Neon Colors**: Cyan, Magenta, Green glowing text
- **ASCII Art**: Slant-style RedTeam banner
- **Progress Bars**: Animated scanning indicators
- **Tables**: Bordered, styled data presentation
- **Status Indicators**: ✓ ✗ ● symbols for visual feedback

## 🔐 Security Note

**This is a simulation tool for educational purposes.**

- Port scanning is **simulated** (no actual network traffic)
- Vulnerabilities are **mock data** from a sample database
- Password testing is **local** (no data sent anywhere)
- OSINT results are **example data** (no real API calls)

Perfect for:
- Security training
- Demonstration purposes
- Learning cybersecurity concepts
- Understanding red team tools

## 💡 Pro Tips

1. **Quick Testing**: Use the default values to see results instantly
2. **Keyboard Shortcuts**: Ctrl+C for clean exit anywhere
3. **Menu Loop**: After each tool completes, you're back at the main menu
4. **Visual Feedback**: Watch for colored status messages and progress bars
5. **Error Handling**: Invalid inputs are caught with helpful error messages

## 📁 File Structure

```
redteam.py              # Main application (run this)
tools/
  ├── network_recon.py  # Port scanning module
  ├── vuln_scanner.py   # Vulnerability assessment
  ├── password_tester.py # Password strength analyzer
  └── osint_tools.py    # Intelligence gathering
```

## 🎬 Example Session

```bash
$ python redteam.py

  ____          _ _____
 |  _ \ ___  __| |_   _|__  __ _ _ __ ___
 | |_) / _ \/ _` | | |/ _ \/ _` | '_ ` _ \
 |  _ <  __/ (_| | | |  __/ (_| | | | | | |
 |_| \_\___|\__,_| |_|\___|\__,_|_| |_| |_|

╔══════════════════════════════════════════╗
║  Terminal v2.1.0                         ║
║  Cybersecurity Operations Platform       ║
╚══════════════════════════════════════════╝

     ⚡ Available Tools ⚡
┌────┬──────────────────────┬────────────────┐
│ 1  │ Network Recon        │ Port scanning  │
│ 2  │ Vuln Assessment      │ CVE database   │
│ 3  │ Password Tester      │ Strength test  │
│ 4  │ OSINT Tools          │ Intel gathering│
│ 5  │ Exit                 │ Quit           │
└────┴──────────────────────┴────────────────┘

redteam@cyber ~$ 1

═══ Network Reconnaissance ═══
Enter target IP or domain [192.168.1.1]: 

Scanning ports... ━━━━━━━━━━━━━ 100%

✓ Scan complete: 6 open ports found

redteam@cyber ~$ 5

Shutting down RedTeam Terminal...
✓ Session terminated
```

---

**Ready to explore? Run `python redteam.py` now!** 🚀
