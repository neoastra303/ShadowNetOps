<p align="center">
  <img src="https://img.shields.io/badge/ShadowNetOps-v2.1.0-38bdf8?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-MIT-38bdf8?style=for-the-badge"/>
  <img src="https://img.shields.io/github/stars/neoastra303/ShadowNetOps?style=for-the-badge&color=38bdf8"/>
  <img src="https://img.shields.io/badge/python-3.8%2B-38bdf8?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/tests-23%20passing-4ade80?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/UI-Questionary-c084fc?style=for-the-badge"/>
</p>

<pre align="center">
        ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
        ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
        ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
        ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
        ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
        ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
</pre>

<p align="center">
  <b>Advanced Network Security Operations & Red Teaming Platform</b><br>
  <i>14 integrated modules · questionary-powered UI · Rich output · 23 unit tests</i>
</p>

<br>

---

## <b>Quick Start</b>

```bash
git clone https://github.com/neoastra303/ShadowNetOps.git
cd ShadowNetOps
pip install -r requirements.txt
python redteam.py
```

> Requires Python 3.8+

---

## <b>Interactive CLI</b>

All menus use **arrow-key navigation** via [Questionary](https://github.com/tmbo/questionary) with a soft cyber palette:

```
  ┃ Select a tool category
  ┃ ▸ Network Reconnaissance
  ┃   Vulnerability Assessment
  ┃   Password Strength Tester
  ┃   OSINT Tools
  ┃   ⋮ (scroll with ↑↓)
```

| Key       | Action              |
| --------- | ------------------- |
| `↑` / `↓` | Navigate menu items |
| `Enter`   | Confirm selection   |
| `Esc`     | Go back / cancel    |
| `q`       | Quit from main menu |

### Banner

On startup you'll see an ASCII block-art logo with rounded panel, module subtitle, and version — styled in a soft sky-blue / lavender palette for eye comfort.

---

## <b>Modules</b>

| #   | Module                         | Key Capabilities                                                                                                                                                                     |
| --- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | **Network Reconnaissance**     | Port scanning, host discovery, service detection, OS fingerprinting, traceroute, DNS enumeration                                                                                     |
| 2   | **Vulnerability Assessment**   | CVE scanning, nmap NSE scripts, SSL/TLS analysis, Nikto web scanning, configuration checks                                                                                           |
| 3   | **Password Strength Tester**   | Entropy calculation, crack-time estimation, pattern detection, character-set analysis                                                                                                |
| 4   | **OSINT Tools**                | holehe (email), h8mail (breach lookup), sherlock (username), theHarvester (domain/IP)                                                                                                |
| 5   | **Social Engineering Toolkit** | Phishing simulation, pretexting, impersonation, credential harvesting, spear phishing                                                                                                |
| 6   | **Forensics**                  | Disk & memory analysis, artifact search, file hashing, network forensics, registry / timeline / log analysis, file carving, steganography, browser & email artifacts                 |
| 7   | **Reporting**                  | Executive summary, findings management, export to JSON / CSV / HTML                                                                                                                  |
| 8   | **Misc Utilities**             | Hash calculator, Base64 encode/decode, random password generator                                                                                                                     |
| 9   | **Web Attack Tools**           | SQLMap (SQLi), XSStrike (XSS), CSRF PoC, ffuf (fuzzing), Nikto, subfinder, whatweb, header analysis, Wayback Machine archive search                                                  |
| 10  | **Wireless Attack Tools**      | airodump-ng (scan / capture), hashcat (WPA cracking), blue_hydra, wifite, aireplay-ng (deauth), reaver (WPS)                                                                         |
| 11  | **Malware Analysis**           | Static & dynamic analysis, YARA scanning, PE header analysis, tcpdump capture, Volatility memory analysis hints                                                                      |
| 12  | **Reverse Engineering**        | objdump disassembly, GDB debugging, hex dump, XOR decryption, UPX packer detection                                                                                                   |
| 13  | **Cryptography Tools**         | Hash calculator (MD5 / SHA1 / SHA256), AES-256-CBC encrypt/decrypt, Base64/Hex/URL encoding, hash type identifier, SSL certificate check, RSA/AES key generation, digital signatures |
| 14  | **Exit**                       | Quit the terminal                                                                                                                                                                    |

---

## <b>CLI Features</b>

| Feature                 | Description                                                             |
| ----------------------- | ----------------------------------------------------------------------- |
| **Arrow-key menus**     | questionary-powered interactive selection with soft cyber styling       |
| **ASCII banner**        | Block-art "SHADOW" logo on startup with gradient-style panel            |
| **Inline validation**   | URLs, domains, and emails validated during input, not after             |
| **Syntax highlighting** | Command output rendered with `rich.Syntax` (monokai theme)              |
| **Live spinners**       | `rich.progress.Progress` wraps every subprocess call                    |
| **Pagination**          | Long result sets prompt "Show more?" with default yes                   |
| **Hidden input**        | Password prompts mask characters via `questionary.password()`           |
| **Theme system**        | Centralized `CYBER_STYLE` in `base_tool.py` for one-line colour changes |
| **Soft palette**        | Sky blue, lavender, soft green, slate gray — chosen for eye comfort     |

---

## <b>Architecture</b>

```
ShadowNetOps/
│
├── redteam.py                  # Main entry point — banner, menu routing, inline handlers
├── config.ini                  # Runtime configuration
├── config_manager.py           # Config parser with defaults
├── requirements.txt            # Python dependencies
│
├── tools/                      # Modular tool packages
│   ├── base_tool.py            # Abstract base class, shared URL/DOMAIN/IP patterns, CYBER_STYLE
│   ├── network_recon.py        # Port scanning, host discovery, banner grabbing, OS detection, traceroute
│   ├── vuln_scanner.py         # General vuln scan, nmap NSE, SSL/TLS, Nikto, CVE lookup
│   ├── password_tester.py      # Strength analysis with progress bar and crack-time estimate
│   ├── osint_tools.py          # WHOIS, DNS, subdomain discovery, email/phone/social OSINT
│   ├── social_engineering.py   # Phishing, pretexting, impersonation, credential harvesting
│   ├── forensics.py            # Disk, memory, network, registry, timeline, log, stego, browser, email
│   ├── reporting.py            # Executive summary, findings management, JSON/CSV/HTML export
│   ├── misc_utils.py           # Hashing, Base64 encode/decode, password generator
│   └── dependency_manager.py   # External tool verification and install guidance
│
├── tests/                      # 23 unit tests (pytest)
│   ├── test_base_tool.py       # URL/DOMAIN/IP pattern validation (11 tests)
│   ├── test_config_manager.py  # Config read/write/boolean/int/list (9 tests)
│   └── test_imports.py         # Module import verification (3 tests)
│
└── .github/workflows/          # CI pipeline (Python 3.10 / 3.11 / 3.12)
```

---

## <b>Testing</b>

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## <b>Legal & Ethical Use</b>

This tool is for **authorized security testing only**. Unauthorized use may violate computer fraud laws. See [LEGAL_DISCLAIMER.md](LEGAL_DISCLAIMER.md) for full terms.

---

## <b>License</b>

MIT — see [LICENSE](LICENSE).

---

<p align="center"><i>ShadowNetOps — empowering authorized security professionals.</i></p>
