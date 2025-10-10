# RedTeam Terminal 🛡️

A cyberpunk-themed cybersecurity red team CLI tool for network reconnaissance, vulnerability assessment, password testing, and OSINT operations.

## Features

### 🔍 Network Reconnaissance
- Port scanning simulation
- Service detection
- Network discovery
- Real-time scan results with color-coded status

### 🛡️ Vulnerability Assessment
- CVE database scanning
- Security configuration checks
- Severity-based reporting (Critical, High, Medium, Low)
- Detailed vulnerability descriptions

### 🔑 Password Strength Tester
- Real-time password analysis
- Entropy calculation
- Crack time estimation
- Security requirements validation

### 🌐 OSINT Tools
- Domain/IP/Email lookup
- WHOIS data
- Breach database checks
- Social media profile discovery
- DNS and SSL certificate analysis

## Installation

The application is already set up with all required dependencies:
- `rich` - Beautiful terminal UI
- `colorama` - Cross-platform colored output
- `pyfiglet` - ASCII art banners
- `requests` - HTTP requests (for future API integrations)

## Usage

Run the RedTeam Terminal:

```bash
python redteam.py
```

Or make it executable and run directly:

```bash
chmod +x redteam.py
./redteam.py
```

## Menu Navigation

Once launched, you'll see the main menu with 5 options:

1. **Network Reconnaissance** - Scan network targets and discover open ports
2. **Vulnerability Assessment** - Run security scans and identify vulnerabilities
3. **Password Strength Tester** - Analyze password security
4. **OSINT Tools** - Perform open-source intelligence gathering
5. **Exit** - Quit the terminal

## Cyberpunk Aesthetics

The terminal features:
- 🎨 Cyan and magenta neon colors
- ⚡ ASCII art banners
- 📊 Beautiful tables and progress bars
- 🌟 Glowing status indicators
- 💫 Animated scanning effects

## Security Note

⚠️ **Educational/Training Purpose Only**

This tool is designed for:
- Security training and education
- Penetration testing in authorized environments
- Security awareness demonstrations
- Learning about cybersecurity concepts

**Always obtain proper authorization before conducting any security testing.**

## Architecture

```
redteam.py              # Main application entry point
tools/
  ├── network_recon.py  # Network reconnaissance module
  ├── vuln_scanner.py   # Vulnerability assessment module
  ├── password_tester.py # Password strength testing module
  └── osint_tools.py    # OSINT operations module
```

## Example Session

```
$ python redteam.py

  ____          _ _____
 |  _ \ ___  __| |_   _|__  __ _ _ __ ___
 | |_) / _ \/ _` | | |/ _ \/ _` | '_ ` _ \
 |  _ <  __/ (_| | | |  __/ (_| | | | | | |
 |_| \_\___|\__,_| |_|\___|\__,_|_| |_| |_|

╔══════════════════════════════════════════════╗
║  Terminal v2.1.0                             ║
║  Cybersecurity Operations Platform           ║
║  Network Recon | Vuln Assessment | OSINT     ║
╚══════════════════════════════════════════════╝

     ⚡ Available Tools ⚡
┌────┬────────────────────────────┬─────────────────────────────┐
│ ID │ Tool                       │ Description                 │
├────┼────────────────────────────┼─────────────────────────────┤
│ 1  │ Network Reconnaissance     │ Port scanning and discovery │
│ 2  │ Vulnerability Assessment   │ CVE database scanning       │
│ 3  │ Password Strength Tester   │ Analyze password security   │
│ 4  │ OSINT Tools               │ Intelligence gathering       │
│ 5  │ Exit                      │ Quit the terminal           │
└────┴────────────────────────────┴─────────────────────────────┘

redteam@cyber ~$ _
```

## Future Enhancements

Potential additions:
- Actual network scanning capabilities
- Real CVE database integration
- Export reports (PDF, JSON, CSV)
- Multi-threaded scanning
- Custom vulnerability signatures
- Collaborative red team features
- Integration with real OSINT APIs
- Historical scan comparison

## License

MIT License - Free for educational and authorized security testing purposes.
