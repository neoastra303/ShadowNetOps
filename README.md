<p align="center">
  <img src="https://img.shields.io/badge/ShadowNetOps-v2.1.0-00d4ff?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-MIT-00d4ff?style=for-the-badge"/>
  <img src="https://img.shields.io/github/stars/neoastra303/ShadowNetOps?style=for-the-badge&color=00d4ff"/>
  <img src="https://img.shields.io/badge/python-3.8%2B-00d4ff?style=for-the-badge&logo=python&logoColor=white"/>
</p>

<h1 align="center">⚡ ShadowNetOps ⚡</h1>
<p align="center"><b>Advanced Network Security Operations & Red Teaming Platform</b></p>
<p align="center">A cyberpunk-themed CLI suite with 14 integrated security modules for reconnaissance, exploitation analysis, forensics, and reporting.</p>

---

## 🚀 Quick Start

```bash
git clone https://github.com/neoastra303/ShadowNetOps.git
cd ShadowNetOps
pip install -r requirements.txt
python redteam.py
```

**Requires:** Python 3.8+

---

## 📋 Menu Overview

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

---

## 🧩 Module Reference

| #   | Module                         | Key Capabilities                                                                                                                      |
| --- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Network Reconnaissance**     | Port scanning, host discovery, service detection, OS fingerprinting, traceroute, DNS enum                                             |
| 2   | **Vulnerability Assessment**   | CVE scanning, nmap NSE scripts, SSL/TLS analysis, Nikto web scanning, config checks                                                   |
| 3   | **Password Strength Tester**   | Entropy calc, crack time estimation, pattern detection, char set analysis, dictionary check                                           |
| 4   | **OSINT Tools**                | holehe (email), h8mail (breach), sherlock (username), theHarvester (domain/IP)                                                        |
| 5   | **Social Engineering Toolkit** | Phishing simulation, pretexting, impersonation, credential harvesting, spear phishing                                                 |
| 6   | **Forensics**                  | Disk/memory analysis, artifact search, file hashing, network forensics, registry/timeline/log analysis                                |
| 7   | **Reporting**                  | Executive summary, PDF/JSON/CSV export                                                                                                |
| 8   | **Misc Utilities**             | Hash calculator, Base64 encoder/decoder, random password generator                                                                    |
| 9   | **Web Attack Tools**           | SQLMap (SQLi), XSStrike (XSS), CSRF PoC, ffuf (fuzzing), Nikto, subfinder, whatweb, header analysis, Wayback Machine                  |
| 10  | **Wireless Attack Tools**      | airodump-ng (scan/capture), hashcat (WPA), blue_hydra, wifite, aireplay-ng (deauth), reaver (WPS)                                     |
| 11  | **Malware Analysis**           | Static/dynamic analysis, YARA scanning, PE header analysis, tcpdump capture, volatility hints                                         |
| 12  | **Reverse Engineering**        | objdump disassembly, GDB debugging, hex dump, XOR decryption, UPX detection                                                           |
| 13  | **Cryptography Tools**         | Hash calculator (MD5/SHA1/SHA256), AES-256 encrypt/decrypt, Base64/Hex/URL encode, SSL cert check, RSA/AES keygen, digital signatures |
| 14  | **Exit**                       | Quit the terminal                                                                                                                     |

---

## ⌨️ Shortcuts

| Key          | Action                    |
| ------------ | ------------------------- |
| `q` / `quit` | Exit from anywhere        |
| `b` / `back` | Return to main menu       |
| `<Enter>`    | Refresh menu              |
| `y` / `n`    | Pagination (more results) |

---

## 🎨 CLI Features

- **2-column menu layout** — faster navigation via `rich.Columns`
- **Syntax highlighting** — command output colored with `rich.Syntax` (monokai)
- **Live spinners** — `rich.progress.Progress` wraps every subprocess call
- **Pagination** — long result sets show "More? (y/n)"
- **Markdown help** — `rich.markdown.Markdown` for info screens
- **Theme system** — centralized `S` dict for one-line color changes

---

## 🏗️ Architecture

```
ShadowNetOps/
├── redteam.py                 # Main entry point (770 lines)
├── config.ini                 # Runtime configuration
├── config_manager.py          # Config parser + defaults
├── requirements.txt           # Dependencies
├── tools/                     # 13 modular tool packages
│   ├── base_tool.py           # Abstract base with validators
│   ├── network_recon.py
│   ├── vuln_scanner.py
│   ├── password_tester.py
│   ├── osint_tools.py
│   ├── social_engineering.py
│   ├── forensics.py
│   ├── reporting.py
│   ├── misc_utils.py
│   ├── dependency_manager.py
│   ├── malware_analysis.py
│   ├── reverse_engineering.py
│   └── cryptography_tools.py
├── tests/                     # 23 unit tests (pytest)
│   ├── test_base_tool.py
│   ├── test_config_manager.py
│   └── test_imports.py
├── .github/workflows/         # CI (Python 3.10-3.12)
└── docs/                      # Documentation
```

---

## 🧪 Testing

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## ⚖️ Legal & Ethical Use

This tool is for **authorized security testing only**. Unauthorized use may violate computer fraud laws. See [LEGAL_DISCLAIMER.md](LEGAL_DISCLAIMER.md) for full terms.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

<p align="center"><i>ShadowNetOps — Empowering authorized security professionals.</i></p>
