# ShadowNetOps — Tools Reference

## Table of Contents

1. [Network Reconnaissance](#1-network-reconnaissance)
2. [Vulnerability Assessment](#2-vulnerability-assessment)
3. [Password Strength Tester](#3-password-strength-tester)
4. [OSINT Tools](#4-osint-tools)
5. [Social Engineering Toolkit](#5-social-engineering-toolkit)
6. [Forensics](#6-forensics)
7. [Reporting](#7-reporting)
8. [Miscellaneous Utilities](#8-miscellaneous-utilities)
9. [Web Attack Tools](#9-web-attack-tools)
10. [Wireless Attack Tools](#10-wireless-attack-tools)
11. [Malware Analysis](#11-malware-analysis)
12. [Reverse Engineering](#12-reverse-engineering)
13. [Cryptography Tools](#13-cryptography-tools)

---

## 1. Network Reconnaissance

**File:** `tools/network_recon.py` · **Class:** `NetworkRecon(BaseTool)`

### Capabilities

- **Port Scanning** — TCP connect scan against target host/range
- **Host Discovery** — ping sweep to identify live hosts
- **Banner Grabbing** — retrieve service banners for fingerprinting
- **OS Detection** — TTL-based operating system identification
- **Traceroute** — ICMP/UDP path tracing to target
- **DNS Enumeration** — A, AAAA, MX, NS, TXT record retrieval

### Usage

```
1 → Network Reconnaissance → [select scan type] → enter target
```

### External Dependencies

- Python socket (built-in)
- ping (system utility)
- nmap (optional, for enhanced scanning)

---

## 2. Vulnerability Assessment

**File:** `tools/vuln_scanner.py` · **Class:** `VulnScanner(BaseTool)`

### Capabilities

- **General Scan** — basic vulnerability assessment with severity ratings
- **Nmap Script Scan** — runs nmap NSE vulnerability scripts
- **SSL/TLS Analysis** — checks for weak ciphers, expired certs, protocol support
- **Web Vulnerability Scan** — Nikto-based web server assessment
- **CVE Lookup** — searches known CVE databases for target

### Usage

```
2 → Vulnerability Assessment → [select scan type] → enter target
```

### External Dependencies

- nmap (optional)
- nikto (optional)
- sslscan / testssl.sh (optional)

---

## 3. Password Strength Tester

**File:** `tools/password_tester.py` · **Class:** `PasswordTester`

### Capabilities

- Entropy calculation (Shannon bits)
- Crack time estimation (brute-force, dictionary, hybrid)
- Character set diversity analysis
- Common pattern detection (dates, sequences, repeats)
- Security policy validation (length, case, digits, special chars)

### Usage

```
3 → Password Strength Tester → enter password
```

### External Dependencies

None (pure Python)

---

## 4. OSINT Tools

**Defined in:** `redteam.py:osint_tools_menu()`

### Tools

| #   | Tool             | Description                                     | External Dep                    |
| --- | ---------------- | ----------------------------------------------- | ------------------------------- |
| 1   | **holehe**       | Check if email is registered on online services | `pip install holehe`            |
| 2   | **h8mail**       | Email breach lookup and OSINT                   | `pip install h8mail`            |
| 3   | **sherlock**     | Username search across 400+ social networks     | `pip install sherlock`          |
| 4   | **theHarvester** | Domain/email/IP intelligence gathering          | `sudo apt install theharvester` |

### Usage

```
4 → OSINT Tools → [select tool] → enter target
```

### Input Validation

- Emails: regex `[^@]+@[^@]+\.[^@]+`
- Domains: `DOMAIN_PATTERN` from `base_tool.py`

---

## 5. Social Engineering Toolkit

**File:** `tools/social_engineering.py` · **Class:** `SocialEngineeringToolkit`

### Capabilities

- Phishing simulation email/page generator
- Pretexting scenario development
- Impersonation script templates
- Credential harvesting simulation
- Spear phishing campaign designer
- DDoS attack demonstration (educational)

### Usage

```
5 → Social Engineering Toolkit → [select technique]
```

### External Dependencies

None (demonstration/educational content)

---

## 6. Forensics

**File:** `tools/forensics.py` · **Class:** `ForensicsTools(BaseTool)`

### Capabilities

- **Disk Analysis** — file system examination and artifact recovery
- **Memory Dump Analysis** — RAM dump artifact extraction
- **Artifact Search** — file type and pattern searching
- **File Hashing** — MD5/SHA1/SHA256 integrity verification
- **Network Forensics** — packet capture analysis via tcpdump
- **Registry Analysis** — Windows registry hive examination
- **Timeline Analysis** — system activity timeline reconstruction
- **Log Analysis** — system/application log review

### Usage

```
6 → Forensics → [select analysis type]
```

### External Dependencies

- Sleuth Kit (`fls`, `mactime`) — optional
- Volatility — optional
- strings — optional
- tcpdump / tshark — optional

---

## 7. Reporting

**File:** `tools/reporting.py` · **Class:** `ReportingModule`

### Capabilities

- Executive summary generation
- PDF export (requires reportlab)
- JSON findings export
- CSV findings export

### Usage

```
7 → Reporting → [select format]
```

### External Dependencies

- reportlab (optional, for PDF)

---

## 8. Miscellaneous Utilities

**File:** `tools/misc_utils.py` · **Class:** `MiscUtilities`

### Capabilities

- **Hash Calculator** — MD5/SHA1/SHA256 of input text
- **Base64 Encoder/Decoder** — encode/decode text
- **Random Password Generator** — configurable length/charset

### Usage

```
8 → Miscellaneous Utilities → [select utility]
```

### External Dependencies

None (pure Python)

---

## 9. Web Attack Tools

**Defined in:** `redteam.py:web_attack_tools_menu()`

### Tools

| #   | Tool                      | Description                               | External Dep                 |
| --- | ------------------------- | ----------------------------------------- | ---------------------------- |
| 1   | **SQL Injection**         | sqlmap automatic SQLi detection           | `sudo apt install sqlmap`    |
| 2   | **XSS Tester**            | XSStrike cross-site scripting scanner     | `pip install xsstrike`       |
| 3   | **CSRF PoC**              | Proof-of-concept generator                | None (demo)                  |
| 4   | **Directory Brute Force** | ffuf URL fuzzing with wordlist            | `sudo apt install ffuf`      |
| 5   | **Nikto Scanner**         | Comprehensive web server scan             | `sudo apt install nikto`     |
| 6   | **Subdomain Scanner**     | Passive subdomain discovery via subfinder | `sudo apt install subfinder` |
| 7   | **Tech Stack Detection**  | whatweb technology fingerprinting         | `sudo apt install whatweb`   |
| 8   | **HTTP Headers**          | Security headers audit via `requests`     | Python requests              |
| 9   | **Wayback Machine**       | Historical URL search via archive.org API | Python requests              |

### Input Validation

All URL inputs validated with `URL_PATTERN` regex (`^https?://...`).
Domain inputs validated with `DOMAIN_PATTERN`.

---

## 10. Wireless Attack Tools

**Defined in:** `redteam.py:wireless_attack_tools_menu()`

### Tools

| #   | Tool                  | Description                        | External Dep               |
| --- | --------------------- | ---------------------------------- | -------------------------- |
| 1   | **WiFi Scanner**      | airodump-ng network discovery      | aircrack-ng suite          |
| 2   | **Handshake Capture** | airodump-ng WPA handshake capture  | aircrack-ng suite          |
| 3   | **WPA Cracking**      | hashcat password cracking          | `sudo apt install hashcat` |
| 4   | **Bluetooth Scanner** | blue_hydra device discovery        | `pip install blue_hydra`   |
| 5   | **Wifite**            | Automated wireless audit           | `sudo apt install wifite`  |
| 6   | **GPS Mapping**       | Kismet-based geolocation (guide)   | kismet                     |
| 7   | **Deauth Attack**     | aireplay-ng deauthentication       | aircrack-ng suite          |
| 8   | **Evil Twin**         | hostapd rogue AP (guide)           | hostapd                    |
| 9   | **Phishing Portal**   | Fluxion captive portal (guide)     | fluxion                    |
| 10  | **PMKID Capture**     | hcxdumptool PMKID (guide)          | hcxdumptool                |
| 11  | **WPS Attack**        | reaver WPS PIN brute-force         | `sudo apt install reaver`  |
| 12  | **Signal Jammer**     | mdk4 jamming (educational warning) | mdk4                       |

### Interface

Wireless interface required (e.g., `wlan0`). Most tools require monitor mode and root.

---

## 11. Malware Analysis

**Defined in:** `redteam.py:malware_analysis_menu()`

### Tools

| #   | Tool                   | Description                          | External Dep              |
| --- | ---------------------- | ------------------------------------ | ------------------------- |
| 1   | **Static Analysis**    | `file` command + signature detection | `file` (built-in)         |
| 2   | **Dynamic Analysis**   | Sandbox workflow guide               | Cuckoo / ANY.RUN          |
| 3   | **String Extraction**  | `strings` command with pagination    | binutils                  |
| 4   | **YARA Scanner**       | Custom rule matching engine          | `pip install yara-python` |
| 5   | **PE Header Analysis** | MZ header validation                 | Python builtins           |
| 6   | **Network Traffic**    | `tcpdump` live capture               | tcpdump                   |
| 7   | **Memory Dump**        | Volatility workflow guide            | `pip install volatility3` |

---

## 12. Reverse Engineering

**Defined in:** `redteam.py:reverse_engineering_menu()`

### Tools

| #   | Tool                     | Description                    | External Dep      |
| --- | ------------------------ | ------------------------------ | ----------------- |
| 1   | **Disassembler**         | `objdump -d` with pagination   | binutils          |
| 2   | **Debugger**             | GDB workflow guide             | gdb               |
| 3   | **Decompiler**           | objdump + Ghidra/IDA Pro guide | Ghidra / IDA Pro  |
| 4   | **Binary Analysis**      | `file` + `xxd` hex dump        | binutils / xxd    |
| 5   | **Function Recognition** | FLIRT signature guide          | IDA Pro           |
| 6   | **String Decryption**    | Hex decode + XOR brute-force   | Python builtins   |
| 7   | **Packer Detection**     | UPX signature check via `file` | `file` (built-in) |

---

## 13. Cryptography Tools

**Defined in:** `redteam.py:cryptography_tools_menu()`

### Tools

| #   | Tool                      | Description                           | External Dep               |
| --- | ------------------------- | ------------------------------------- | -------------------------- |
| 1   | **Hash Calculator**       | MD5/SHA1/SHA256 file hashing          | Python hashlib             |
| 2   | **Encryption/Decryption** | AES-256-CBC via pycryptodome          | `pip install pycryptodome` |
| 3   | **Encoding/Decoding**     | Base64, Hex, URL encode + auto-decode | Python base64/urllib       |
| 4   | **Hash Identifier**       | Length-based algorithm detection      | Python builtins            |
| 5   | **Certificate Analysis**  | Live SSL/TLS cert inspection          | Python ssl/socket          |
| 6   | **Key Generation**        | RSA 2048-bit / AES-256 keygen         | pycryptodome / hashlib     |
| 7   | **Digital Signatures**    | SHA256 sign + verify                  | Python hashlib             |

### Encryption Example

```python
# Encrypt
mode = "encrypt"
text = "sensitive data"
password = "my-secret-password"
# Output: base64-encoded AES-256-CBC ciphertext

# Decrypt
mode = "decrypt"
text = "<base64 ciphertext>"
password = "my-secret-password"
# Output: "sensitive data"
```

---

_All tools are designed for authorized security testing and educational purposes. Ensure proper authorization before use._
