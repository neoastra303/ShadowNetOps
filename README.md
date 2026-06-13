<p align="center">
  <img src="https://img.shields.io/badge/ShadowNetOps-v2.1.0-00d4ff?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-MIT-00d4ff?style=for-the-badge"/>
  <img src="https://img.shields.io/github/stars/neoastra303/ShadowNetOps?style=for-the-badge&color=00d4ff"/>
  <img src="https://img.shields.io/badge/python-3.8%2B-00d4ff?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/tests-23%20passing-00d4ff?style=for-the-badge"/>
</p>

<h1 align="center">⚡ ShadowNetOps ⚡</h1>
<p align="center"><b>Advanced Network Security Operations & Red Teaming Platform</b></p>
<p align="center">A cyberpunk-themed interactive CLI suite with 14 integrated security modules for reconnaissance, exploitation analysis, forensics, and reporting.</p>

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

## 🎮 Interactive CLI

All menus and prompts use **arrow-key navigation** via [Questionary](https://github.com/tmbo/questionary):

```
┃ Select a tool category
┃ ▸ Network Reconnaissance
┃   Vulnerability Assessment
┃   Password Strength Tester
┃   OSINT Tools
┃   ... (scroll with ↑↓)
```

| Input     | Behaviour           |
| --------- | ------------------- |
| `↑` / `↓` | Navigate menu items |
| `Enter`   | Confirm selection   |
| `Esc`     | Go back / cancel    |
| `q`       | Quit from main menu |

---

## 🧩 Module Reference

| #   | Module                         | Key Capabilities                                                                                                                                             |
| --- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | **Network Reconnaissance**     | Port scanning, host discovery, service detection, OS fingerprinting, traceroute, DNS enum                                                                    |
| 2   | **Vulnerability Assessment**   | CVE scanning, nmap NSE scripts, SSL/TLS analysis, Nikto web scanning, config checks                                                                          |
| 3   | **Password Strength Tester**   | Entropy calc, crack time estimation, pattern detection, char set analysis                                                                                    |
| 4   | **OSINT Tools**                | holehe (email), h8mail (breach), sherlock (username), theHarvester (domain/IP)                                                                               |
| 5   | **Social Engineering Toolkit** | Phishing simulation, pretexting, impersonation, credential harvesting, spear phishing                                                                        |
| 6   | **Forensics**                  | Disk/memory analysis, artifact search, file hashing, network forensics, registry/timeline/log analysis, file carving, steganography, browser/email artifacts |
| 7   | **Reporting**                  | Executive summary, findings management, JSON/CSV/HTML export                                                                                                 |
| 8   | **Misc Utilities**             | Hash calculator, Base64 encoder/decoder, random password generator                                                                                           |
| 9   | **Web Attack Tools**           | SQLMap (SQLi), XSStrike (XSS), CSRF PoC, ffuf (fuzzing), Nikto, subfinder, whatweb, header analysis, Wayback Machine                                         |
| 10  | **Wireless Attack Tools**      | airodump-ng (scan/capture), hashcat (WPA), blue_hydra, wifite, aireplay-ng (deauth), reaver (WPS)                                                            |
| 11  | **Malware Analysis**           | Static/dynamic analysis, YARA scanning, PE header analysis, tcpdump capture, volatility hints                                                                |
| 12  | **Reverse Engineering**        | objdump disassembly, GDB debugging, hex dump, XOR decryption, UPX detection                                                                                  |
| 13  | **Cryptography Tools**         | Hash calculator (MD5/SHA1/SHA256), AES-256 encrypt/decrypt, Base64/Hex/URL encode, hash identifier, SSL cert check, RSA/AES keygen, digital signatures       |
| 14  | **Exit**                       | Quit the terminal                                                                                                                                            |

---

## 🎨 CLI Features

- **Arrow-key menus** — questionary-powered interactive selection with cyber-themed styling
- **Inline validation** — URLs, domains, emails validated during input, not after
- **Syntax highlighting** — command output colored with `rich.Syntax` (monokai theme)
- **Live spinners** — `rich.progress.Progress` wraps every subprocess call
- **Pagination** — long result sets show "Show more?" prompt with default yes
- **Hidden input** — password prompts mask characters via `questionary.password()`
- **Theme system** — centralized `CYBER_STYLE` in `base_tool.py` for one-line colour changes

---

## 🏗️ Architecture

```
ShadowNetOps/
├── redteam.py                 # Main entry point + inline menu handlers
├── config.ini                 # Runtime configuration
├── config_manager.py          # Config parser + defaults
├── requirements.txt           # Dependencies
├── tools/                     # 8 modular tool packages
│   ├── base_tool.py           # Abstract base, shared patterns, CYBER_STYLE
│   ├── network_recon.py       # Port scanning, host discovery, etc.
│   ├── vuln_scanner.py        # CVE scanning, SSL/TLS, Nikto, etc.
│   ├── password_tester.py     # Strength analysis
│   ├── osint_tools.py         # Email/domain/username OSINT
│   ├── social_engineering.py  # Phishing, pretexting, etc.
│   ├── forensics.py           # Disk/memory/log/network forensics
│   ├── reporting.py           # JSON/CSV/HTML export
│   ├── misc_utils.py          # Encoding, hashing, passwords
│   └── dependency_manager.py  # External tool verification
├── tests/                     # 23 unit tests (pytest)
│   ├── test_base_tool.py
│   ├── test_config_manager.py
│   └── test_imports.py
└── .github/workflows/         # CI (Python 3.10-3.12)
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
