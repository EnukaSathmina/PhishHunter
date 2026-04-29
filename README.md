# 🎣 PhishHunter - Advanced Phishing Detection Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Code Style](https://img.shields.io/badge/code%20style-pep8-orange.svg)](https://www.python.org/dev/peps/pep-0008/)
[![Made by Enuka](https://img.shields.io/badge/Made%20by-Enuka-blueviolet)]()

> **Multi-factor phishing URL detector that analyzes domains, SSL certificates, and URL patterns to identify malicious links before you click them.**

> [!CAUTION]
> **EDUCATIONAL USE ONLY**
> 
> This tool is designed for legitimate security research, defensive analysis, and educational purposes.
> Unauthorized use against systems you do not own or lack explicit permission to test is **ILLEGAL**.
> The user assumes all legal responsibility. The author does not condone malicious activity.

# 🛠️ Installation

### Prerequisites
   - Python 3.8 or higher
   - pip package manager
   - Internet connection (for WHOIS/SSL lookups)

### Clone the repository
```bash
git clone https://github.com/EnukaSathmina/PhishHunter.git
```
```
cd phishhunter
```

### Install dependencies
```
pip install -r requirements.txt
```

### Run the tool
```
python run.py
```

# ✨ Features

| Feature | Description | Risk Indicator |
|---------|-------------|----------------|
| 🔍 **Domain Age Check** | WHOIS lookup to detect newly registered domains | `< 7 days = 🔴 CRITICAL`<br>`< 30 days = 🟡 SUSPICIOUS` |
| 🔒 **SSL Certificate Validation** | Verifies certificate validity, issuer, and expiration | `Expired/Invalid = 🔴 DANGEROUS` |
| 📊 **URL Pattern Analysis** | Detects suspicious keywords, IP addresses, and obfuscation | `Keywords found = ⚠️ WARNING` |
| 🎯 **Typosquatting Detection** | Identifies domains impersonating popular brands | `Brand mismatch = 🔴 PHISHING` |
| 🚫 **Risky TLD Flagging** | Flags cheap/abused TLDs (.xyz, .top, .tk, etc.) | `Risky TLD = 🟠 HIGH RISK` |
| 🌐 **DNS Resolution Check** | Verifies if domain actually exists | `No DNS = 🔴 FAKE DOMAIN` |


# 📋 How It Works

| Step | Action | Output |
|:----:|--------|--------|
| 1 | 🔗 URL Input | User provides URL |
| 2 | ⚙️ Analyzer | Runs 4 parallel checks |
| 3 | 🔍 Domain Age Check | WHOIS lookup |
| 4 | 🔒 SSL Validation | Certificate verification |
| 5 | 📊 Pattern Analysis | URL structure scan |
| 6 | 🎯 Typosquatting | Brand impersonation check |
| 7 | 📈 Risk Calculation | Score 0-100 |
| 8 | 🔴 Verdict | Safe → Dangerous |


## Sample Output

```text
🔍 Analyzing: https://paypal.com.login-secure.xyz/login/verify/

=======================================================
VERDICT: 🔴 DANGEROUS
RISK SCORE: 87/100

DETAILS:
🚨 This URL shows strong indicators of a phishing attempt!

⚠️ Domain registered 5 days ago (< 30 days) - Suspicious
✅ Valid SSL certificate from Let's Encrypt, expires in 87 days
⚠️ Suspicious keywords found: login, verify, paypal
⚠️ Unusually cheap TLD (.xyz)
=======================================================
```

## 📄 License

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.

This license ensures that:
- 🔓 The code remains open source
- 🛡️ Modified versions must also be open source (copyleft)
- 🔁 Improvements must be shared with the community

⚠️ Ethical Use Notice:
This tool is intended for educational purposes, defensive security research, and authorized penetration testing only.

Any use of this software for illegal activities, including phishing, fraud, or unauthorized system access, is strictly discouraged and the author assumes no responsibility for such misuse.

<h2 align="center">👨‍💻 Author</h2>

<p align="center">
  Made by <b>Enuka Sathmina</b>
</p>
