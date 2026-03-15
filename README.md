
```
    ███████╗██╗██████╗ ███╗   ███╗██╗    ██╗ █████╗ ██████╗ ███████╗
    ██╔════╝██║██╔══██╗████╗ ████║██║    ██║██╔══██╗██╔══██╗██╔════╝
    █████╗  ██║██████╔╝██╔████╔██║██║ █╗ ██║███████║██████╔╝███████╗
    ██╔══╝  ██║██╔══██╗██║╚██╔╝██║██║███╗██║██╔══██║██╔══██╗╚════██║
    ██║     ██║██║  ██║██║ ╚═╝ ██║╚███╔███╔╝██║  ██║██║  ██║███████║
    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
    ═════════════════════════════════════════════════════════════════
         FIRMWARE SECURITY ANALYSIS TOOLKIT v2.0 - KEY DETECTION
              "Because every firmware has a skeleton key"
    ═════════════════════════════════════════════════════════════════
```

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg?style=flat-square&logo=python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square">
  <img src="https://img.shields.io/badge/CTF-Ready-red.svg?style=flat-square">
  <img src="https://img.shields.io/badge/Research-Grade-orange.svg?style=flat-square">
</p>

---

## 🦀 Overview

**Firmware Security Analysis Toolkit (FSAT)** is a comprehensive Python framework for analyzing embedded firmware images to detect encryption keys, backdoors, vulnerabilities, and suspicious patterns. Built for security researchers, CTF players, and hardware reverse engineers who need to dissect opaque binary blobs without the vendor's blessing.

### Key Capabilities

| Feature | Description |
|---------|-------------|
| **🔑 Key Detection** | Automatically discovers encryption keys, certificates, and hardcoded credentials within firmware packages |
| **🔓 Auto-Decryption** | Attempts decryption using known research keys from CVEs, security conferences, and open-source projects |
| **🎯 Multi-Vendor Support** | Panasonic, Samsung, Engenius, Netgear, TP-Link, D-Link, ZTE, Huawei, and generic embedded formats |
| **🐛 Backdoor Detection** | Scans for hardcoded credentials, suspicious network indicators, and known backdoor patterns |
| **📊 Entropy Analysis** | Calculates Shannon entropy to identify encrypted/obfuscated sections |
| **📦 Extraction Engine** | Handles SquashFS, UBIFS, JFFS2, TAR, ZIP, GZIP, XZ, and vendor-specific formats |

---

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/frankSx/firmware-security-toolkit.git
cd firmware-security-toolkit

# Install dependencies
pip install cryptography

# Run analysis on a firmware image
python firmware_analyzer.py router_firmware.bin

# With specific decryption key
python firmware_analyzer.py encrypted.bin -k "SAMSUNG_DECRYPT_KEY"

# Specify output directory
python firmware_analyzer.py firmware.bin -o ./analysis_output
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    FirmwareAnalyzer                         │
│                      (Orchestrator)                         │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
    ┌──────────▼──────────┐        ┌──────────▼──────────┐
    │   KeyDetector       │        │  FirmwareExtractor  │
    │  - Pattern matching │        │  - Magic bytes      │
    │  - Binary strings   │        │  - Multi-format     │
    │  - Config parsing   │        │  - Vendor-specific  │
    └──────────┬──────────┘        └──────────┬──────────┘
               │                              │
    ┌──────────▼──────────┐        ┌──────────▼──────────┐
    │ FirmwareDecryptor   │        │ BackdoorDetector    │
    │  - Known CVE keys   │        │  - Credential scan  │
    │  - AES/XOR/Custom   │        │  - Network patterns │
    │  - Brute force      │        │  - Suspicious funcs │
    └─────────────────────┘        └─────────────────────┘
```

---

## 🔬 Research Key Database

The toolkit includes a comprehensive database of **legitimate research keys** from publicly disclosed CVEs and security conferences:

### Supported Vendors

| Vendor | Source | Key Types |
|--------|--------|-----------|
| **Netgear** | CVE-2016-1555, CVE-2017-5897 | `Netgear2016!`, `V1V2V3V4V5V6V7V8V9` |
| **TP-Link** | CVE-2018-12598 | `TPLINK_FW_DEC`, `TpLinkDecKey!` |
| **D-Link** | CVE-2015-2050, CVE-2014-7323 | `D-Link-fw-key`, `DIR8XXKEY` |
| **ZTE** | CVE-2014-0899 | `ZTE_FW_KEY`, `zte2014key` |
| **OpenWrt** | Documentation | `OpenWrtEncryptionKey` |
| **Common** | Embedded Research | Weak XOR keys, default AES keys |

### Key Detection Patterns

```python
# Hex keys (128/192/256-bit)
[0-9a-fA-F]{32}  # AES-128
[0-9a-fA-F]{64}  # AES-256

# Variable assignments
encryption_key\s*[=:]\s*["']?([^"'\s]+)["']?
aes_key\s*[=:]\s*["']?([^"'\s]+)["']?
secret_key\s*[=:]\s*["']?([^"'\s]+)["']?

# Binary string extraction
strings -n 8 firmware.bin | grep -i key
```

---

## 🎯 Usage Examples

### Basic Analysis

```bash
$ python firmware_analyzer.py panasonic_dmr_firmware.bin

[*] Analyzing firmware: panasonic_dmr_firmware.bin
[*] Detected type: panasonic
[*] Entropy: 7.89 - Likely encrypted: True
[*] Extracted to: /tmp/firmware_analysis_abc123/panasonic_root
[*] Searching for encryption keys in firmware...
[+] Found 3 potential keys:
    - hardcoded_key: PANASONIC_FW_KEY_01 in etc/config.xml
    - hex_256: a3f5c8e9d2b1... in bin/upgrade_tool
    - binary_string: Found near decrypt_key in lib/libfwupdate.so

[!] DECRYPTION KEY NEEDED: Panasonic firmware key (check release notes)
[+] SUCCESS: Decrypted using key from etc/config.xml
```

### Batch Processing

```bash
#!/bin/bash
# analyze_all.sh - Process entire firmware collection

for fw in ./firmwares/*.bin; do
    echo "[*] Processing: $fw"
    python firmware_analyzer.py "$fw" -o "./output/$(basename $fw .bin)"
done
```

### Integration with Binwalk

```python
from firmware_analyzer import FirmwareAnalyzer

# Custom extraction with binwalk signatures
analyzer = FirmwareAnalyzer("unknown_firmware.bin")
info = analyzer.analyze()

if info.is_encrypted:
    print(f"[!] Encryption detected: {info.encryption_method}")
    print(f"[+] Found keys: {len(info.found_keys)}")
    for key in info.found_keys:
        print(f"    - {key['type']}: {key['file']}")
```

---

## 🛡️ Security Findings

The toolkit categorizes findings by severity:

| Severity | Category | Example |
|----------|----------|---------|
| **CRITICAL** | Backdoor Indicators | `bindshell`, `reverse shell`, `rootkit` |
| **HIGH** | Hardcoded Credentials | `admin:admin`, `root:root` |
| **HIGH** | Suspicious Functions | `exec()`, `system()`, `eval()` |
| **MEDIUM** | Suspicious Network | External IPs, unexpected URLs |
| **LOW** | Suspicious Filename | `backdoor.sh`, `exploit.py` |

---

## 📋 Requirements

### Core Dependencies

```
Python 3.8+
cryptography>=3.0.0  # For AES decryption
```

### Optional Tools (for extraction)

```
binwalk        # Firmware extraction
unsquashfs     # SquashFS handling
7z             # Archive extraction
strings        # Binary string extraction
```

### Installation

```bash
# Ubuntu/Debian
sudo apt-get install binwalk squashfs-tools p7zip-full

# macOS
brew install binwalk p7zip

# Python dependencies
pip install -r requirements.txt
```

---

## 🧪 CTF & Research Applications

### Capture The Flag

- **Firmware Challenges**: Extract flags from embedded CTF challenges
- **Crypto Challenges**: Decrypt firmware using discovered keys
- **Reversing**: Analyze ARM/MIPS binaries in extracted filesystems

### Hardware Security Research

- **IoT Auditing**: Analyze consumer IoT devices for vulnerabilities
- **Supply Chain**: Verify firmware integrity before deployment
- **Forensics**: Extract evidence from embedded systems

### Educational Use

- **Training**: Learn firmware structure and embedded security
- **Demonstrations**: Show real-world encryption weaknesses
- **Research**: Document vendor-specific security practices

---

## 📝 Output Format

### Analysis Report Structure

```
output/
├── analysis_report.txt      # Human-readable findings
├── extracted/               # Decompressed firmware contents
│   ├── squashfs_root/       # Filesystem extraction
│   ├── decrypted_firmware   # Decrypted binary (if applicable)
│   └── keys_found.json      # Structured key data
└── findings/
    ├── credentials.txt      # Hardcoded passwords
    ├── suspicious_ips.txt   # Network indicators
    └── backdoor_evidence/   # Screenshots/logs
```

---

## ⚠️ Legal & Ethics

```
╔══════════════════════════════════════════════════════════════════╗
║  WARNING: This tool is for authorized security research only     ║
║                                                                  ║
║  • Only analyze firmware you own or have permission to test      ║
║  • Research keys are from PUBLICLY DISCLOSED CVEs only           ║
║  • Do not use for unauthorized access to devices or networks     ║
║  • Comply with all local laws regarding reverse engineering      ║
║  • Report vulnerabilities responsibly to vendors                 ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## 🤝 Contributing

Contributions welcome! Priority areas:

- [ ] Additional vendor firmware formats
- [ ] New CVE research keys (publicly disclosed only)
- [ ] Improved decryption algorithms
- [ ] GUI frontend (PyQt/Web)
- [ ] YARA rule integration
- [ ] Automated exploit generation

### Code Style

- Follow PEP 8
- Include type hints
- Document all functions
- Add tests for new features

---

## 🦀 About the Author

**frankSx** — Security researcher, CTF player, hardware reverse engineer

- Blog: [frankhacks.blogspot.com](https://frankhacks.blogspot.com)
- Research: Embedded systems, IoT security, firmware exploitation
- Philosophy: *"Every device has a story written in bytes"*

```
    ╔═══════════════════════════════════════════════════════════════╗
    ║  "In the 13th Hour, when the stack is deep and the            ║
    ║   entropy is high, that's where we find the truth."           ║
    ║                                          — frankSx            ║
    ╚═══════════════════════════════════════════════════════════════╝
```

---

## 📜 License

MIT License - See [LICENSE](LICENSE) file

**Disclaimer**: This tool is provided for educational and research purposes only. The authors assume no liability for misuse or damage caused by this program.

---

<p align="center">
  <sub>Built with 🦀 and midnight coffee</sub>
</p>
<p align="center">
  <sub>13th Hour Research Division | 2026</sub>
</p>
