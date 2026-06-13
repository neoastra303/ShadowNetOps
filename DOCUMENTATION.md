# ShadowNetOps — Comprehensive Documentation

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Usage](#usage)
5. [Tools Overview](#tools-overview)
6. [CLI Features](#cli-features)
7. [Security & Legal](#security--legal)
8. [Development](#development)
9. [Troubleshooting](#troubleshooting)

---

## Overview

ShadowNetOps is a cyberpunk-themed CLI security platform with **14 integrated modules** covering network reconnaissance, vulnerability assessment, password analysis, OSINT, social engineering, forensics, reporting, web attacks, wireless attacks, malware analysis, reverse engineering, and cryptography.

### Key Features

- 14 tools across 13 categories + exit
- Modular architecture with `BaseTool` abstract class
- Rich CLI with columns, syntax highlighting, spinners, pagination
- Global keyboard shortcuts (`q`=quit, `b`=back)
- Configurable via `config.ini`
- Dependency management for external tools
- 23+ unit tests with GitHub CI (Python 3.10–3.12)

---

## Installation

### Prerequisites

- Python 3.8+
- pip

### Setup

```bash
git clone https://github.com/neoastra303/ShadowNetOps.git
cd ShadowNetOps
pip install -r requirements.txt
python redteam.py
```

### Dependencies

| Package        | Purpose                                                 |
| -------------- | ------------------------------------------------------- |
| `rich`         | Terminal UI (tables, panels, columns, syntax, progress) |
| `requests`     | HTTP requests (Wayback Machine, header analysis)        |
| `pycryptodome` | AES encryption/decryption, RSA key generation           |
| `configparser` | Configuration file handling                             |
| `pytest`       | Unit testing                                            |

---

## Configuration

The application uses `config.ini` for runtime settings. Managed by `config_manager.py` which resolves the path relative to the script directory (not CWD).

### Sections

- **GENERAL** — version, theme, debug mode
- **NETWORK_RECON** — scan type, concurrency, timeout, ports, simulation mode
- **VULN_SCANNER** — severity threshold, CVE DB URL, scan depth
- **PASSWORD_TESTER** — min length, char requirements, entropy threshold
- **OSINT_TOOLS** — timeout, rate limiting, Tor proxy
- **SECURITY** — consent prompts, logging, log path
- **REPORTING** — default format, PDF/CSV/JSON export, report directory
- **ADVANCED** — retries, threading, max threads

Defaults are auto-created if `config.ini` is missing.

---

## Usage

### Main Menu

```
┌═══ Available Tools & Categories ═══┐
│  1. Network Reconnaissance          │   8. Miscellaneous Utilities
│  2. Vulnerability Assessment        │   9. Web Attack Tools
│  3. Password Strength Tester        │  10. Wireless Attack Tools
│  4. OSINT Tools                     │  11. Malware Analysis
│  5. Social Engineering Toolkit      │  12. Reverse Engineering
│  6. Forensics                       │  13. Cryptography Tools
│  7. Reporting                       │  14. Exit
└─────────────────────────────────────┘
Shortcuts: [q]=quit  [b]=back
shadow@netops ~$
```

### Shortcuts

| Key          | Action                    |
| ------------ | ------------------------- |
| `q` / `quit` | Exit immediately          |
| `b` / `back` | Return to main menu       |
| `<Enter>`    | Refresh current menu      |
| `y` / `n`    | Advance paginated results |

### Workflow

1. Launch: `python redteam.py`
2. Select a tool category (1–13)
3. Follow sub-menu prompts for the specific tool
4. View results — long outputs are paginated
5. Press `b` to go back, `q` to quit

---

## Tools Overview

### 1. Network Reconnaissance (`tools/network_recon.py`)

- **Port Scanning** — socket-based TCP port probe with service detection
- **Host Discovery** — ping sweep / ARP scan
- **Banner Grabbing** — service banner retrieval
- **OS Detection** — TTL-based fingerprinting
- **Traceroute** — ICMP/UDP path tracing
- **DNS Enumeration** — A, AAAA, MX, NS record lookup

### 2. Vulnerability Assessment (`tools/vuln_scanner.py`)

- CVE database lookup
- Nmap NSE script scanning
- SSL/TLS security evaluation
- Nikto web server scan
- Configuration weakness checks

### 3. Password Strength Tester (`tools/password_tester.py`)

- Entropy calculation (Shannon)
- Crack time estimation (brute-force)
- Character set analysis
- Common pattern detection
- Security policy validation

### 4. OSINT Tools (`redteam.py:osint_tools_menu`)

- **holehe** — check email usage across online services
- **h8mail** — email breach/OSINT lookup
- **sherlock** — username search across 400+ social networks
- **theHarvester** — domain/email/IP intelligence gathering

### 5. Social Engineering Toolkit (`tools/social_engineering.py`)

- Phishing simulation
- Pretexting scenario generator
- Impersonation scripts
- Credential harvesting simulation
- Spear phishing campaign designer
- DDoS attack demo

### 6. Forensics (`tools/forensics.py`)

- Disk image analysis
- Memory dump artifact search
- File hashing (MD5, SHA1, SHA256)
- Network packet capture (tcpdump)
- Windows registry analysis
- System timeline reconstruction
- Log file analysis

### 7. Reporting (`tools/reporting.py`)

- Executive summary generation
- PDF export (stub — requires reportlab)
- CSV/JSON findings export

### 8. Miscellaneous Utilities (`tools/misc_utils.py`)

- Hash calculator (MD5, SHA1, SHA256)
- Base64 encoder/decoder
- Random password generator

### 9. Web Attack Tools (`redteam.py:web_attack_tools_menu`)

- **SQLMap** — automatic SQL injection detection
- **XSStrike** — cross-site scripting scanner
- **CSRF PoC Generator** — proof-of-concept creation
- **ffuf** — directory/file fuzzing with wordlist
- **Nikto** — comprehensive web server scan
- **subfinder** — passive subdomain enumeration
- **whatweb** — technology stack fingerprinting
- **HTTP Header Analysis** — security headers audit
- **Wayback Machine** — historical URL discovery via archive.org

### 10. Wireless Attack Tools (`redteam.py:wireless_attack_tools_menu`)

- **airodump-ng** — WiFi network scanning + handshake capture
- **hashcat** — WPA/WPA2 password cracking
- **blue_hydra** — Bluetooth device discovery
- **wifite** — automated wireless audit
- **aireplay-ng** — deauthentication attack
- **reaver** — WPS PIN brute-force
- Evil Twin AP creation guide
- Phishing captive portal guide
- PMKID capture guide

### 11. Malware Analysis (`redteam.py:malware_analysis_menu`)

- **Static Analysis** — `file` command + signature detection
- **Dynamic Analysis** — sandbox workflow (Cuckoo/ANY.RUN)
- **String Extraction** — `strings` command with pagination
- **YARA Scanner** — custom rule matching
- **PE Header Analysis** — MZ header validation
- **Network Traffic** — `tcpdump` live capture
- **Memory Forensics** — Volatility workflow guide

### 12. Reverse Engineering (`redteam.py:reverse_engineering_menu`)

- **Disassembler** — `objdump -d` with pagination
- **Debugger** — GDB workflow guide
- **Decompiler** — objdump + Ghidra/IDA Pro guide
- **Binary Analysis** — `file` + `xxd` hex dump
- **FLIRT Recognition** — IDA Pro signature guide
- **String Decryption** — hex decode + XOR brute-force
- **Packer Detection** — UPX signature check

### 13. Cryptography Tools (`redteam.py:cryptography_tools_menu`)

- **Hash Calculator** — MD5/SHA1/SHA256 for files
- **AES-256-CBC** — encrypt/decrypt via pycryptodome
- **Encoding** — Base64, Hex, URL encode + auto-decode
- **Hash Identifier** — length-based algorithm detection
- **SSL Certificate Check** — live host cert inspection
- **Key Generation** — RSA 2048-bit / AES-256
- **Digital Signatures** — sign + verify (SHA256)

---

## CLI Features

### Style System

All colors are centralized in `S` dict at the top of `redteam.py`:

```python
S = {
    "title": "bold cyan",
    "header": "bold magenta",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "info": "cyan",
    "dim": "dim",
}
```

### Shared Validators (`tools/base_tool.py`)

```python
URL_PATTERN    — matches http/https URLs
DOMAIN_PATTERN — matches domain names
IP_PATTERN     — matches IPv4 addresses
DANGEROUS_CHARS — shell injection blacklist
BaseTool.validate_url() / validate_domain() / validate_target()
```

### Progress Wrapper

```python
self._subprocess_run(cmd_args, timeout=60, spinner_text="Scanning...")
```

All subprocess calls show a live spinner with 60s default timeout.

---

## Security & Legal

⚠️ **CRITICAL:** This tool is for **authorized security testing only**. See [LEGAL_DISCLAIMER.md](LEGAL_DISCLAIMER.md).

### Built-in Safeguards

- **Target validation** — regex-based IP/domain/URL filtering
- **Input sanitization** — blocks shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`, etc.)
- **Consent prompts** — authorization reminders before tool execution
- **Dependency warnings** — alerts for missing tools
- **No auto-install** — installation requires manual user action

---

## Development

### Extending

1. Create a new class inheriting from `BaseTool` in `tools/`
2. Implement `run()`
3. Import and instantiate in `redteam.py`
4. Add handler in `run()` loop dispatch table

### Testing

```bash
python -m pytest tests/ -v
```

Tests cover: URL/domain/IP patterns, input validation, config manager CRUD, module imports.

### CI

GitHub Actions runs on push/PR to `main`:

- Python 3.10, 3.11, 3.12 matrix
- `pip install -r requirements.txt`
- `python -m pytest tests/ -v --tb=short`

---

## Troubleshooting

| Symptom                                   | Fix                                        |
| ----------------------------------------- | ------------------------------------------ |
| `ModuleNotFoundError`                     | Run `pip install -r requirements.txt`      |
| Config file not found                     | `config_manager.py` auto-creates defaults  |
| Subprocess tool not found (e.g. `sqlmap`) | Install the tool manually                  |
| AES/RSA error                             | `pip install pycryptodome`                 |
| `Syntax` rendering issues                 | Upgrade rich: `pip install --upgrade rich` |

---

_Last updated: June 2026_
