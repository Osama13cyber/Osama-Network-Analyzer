# 🛡️ OSAMA NETWORK ANALYZER v2.0
[![GitHub Followers](https://img.shields.io/github/followers/Osama13cyber?style=social)](https://github.com/Osama13cyber)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**OSAMA NETWORK ANALYZER** is a high-performance network discovery and security auditing tool. It combines Scapy's packet-level power with a sleek Flask-based web interface to provide real-time visibility into local network infrastructure.



## 🚀 Key Features
* **ARP Discovery:** Rapidly identifies all active hosts on the subnet.
* **Port Analysis:** Scans for critical service ports (SSH, HTTP, FTP, RDP, SMB).
* **Vendor Resolution:** Instantly identifies device manufacturers (Apple, Samsung, Cisco, etc.).
* **Risk Profiling:** Automatically flags unsecured ports (e.g., SMB/Telnet) as **HIGH RISK**.
* **Interactive Dashboard:** Modern dark-mode UI for clear data visualization.
* **CLI Branding:** Custom ASCII art for a professional terminal experience.

## 🛠️ Installation

### 1. Prerequisites
* **Python 3.8+**
* **Npcap (Windows only):** Essential for packet injection. Download at [npcap.com](https://npcap.com/).

### 2. Setup
```bash
# Clone the repository
git clone [https://github.com/Osama13cyber/Osama-Network-Analyzer.git](https://github.com/Osama13cyber/Osama-Network-Analyzer.git)
cd Osama-Network-Analyzer

# Install required libraries
pip install -r requirements.txt
