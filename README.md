# 🔐 Security Best Practices Generator (Governance Edition)

A governance-oriented command-line tool that generates structured security best practices for:

- 🪟 Windows workstations
- 🐧 Linux servers / desktops
- 🌐 Web servers

Each recommendation is presented as a **control** with:

- a unique **ID** (e.g. `W-AC-01`),
- a **priority level** (`P1`, `P2`, `P3`),
- a **governance-friendly description**.

This project is designed to showcase skills in **security governance, policy writing, and risk-based prioritization**, which are key for roles such as **RSSI (CISO)** or **DSI (CIO)**.

---

## ✨ Features

- Targets:
  - `windows`
  - `linux`
  - `webserver`
- Output formats:
  - human-readable **text**
  - **Markdown** (ideal for policies, internal wikis, audits)
- Governance-oriented structure:
  - Security controls grouped by domain:
    - Accounts & Authentication  
    - System Hardening  
    - Network & Firewall  
    - Updates & Patch Management  
    - Logging & Monitoring  
    - Backup & Recovery  
    - Web Security Headers / TLS (for web servers)
  - Each control includes:
    - `ID`
    - `Priority` (`P1` = critical, `P2` = important, `P3` = recommended)

---

## 🛠️ Installation

### Requirements

- Python **3.8+**

### Clone the repository

```bash
git clone https://github.com/yxng-hrz/security-best-practices-generator.git
cd security-best-practices-generator
