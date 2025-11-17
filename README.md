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
```

🚀 Usage

Display help:

python best_practices_generator.py --help


Generate Windows best practices as text:

python best_practices_generator.py --target windows


Generate Linux best practices as Markdown:

python best_practices_generator.py --target linux --format markdown


Generate Web Server best practices as Markdown and save to a file:

python best_practices_generator.py --target webserver --format markdown --output webserver_controls.md

📌 Example Output (Markdown, Linux)
# Security Best Practices – linux

## 1. Accounts & Authentication

- **[P1] [L-AC-01]** Enforce strong password policies using PAM (length, complexity, history).
- **[P1] [L-AC-02]** Disable direct root login via SSH and require `sudo` for privileged operations.
- **[P2] [L-AC-03]** Lock or remove unused local and default accounts.
- **[P2] [L-AC-04]** Use SSH keys instead of passwords for administrative access.

## 2. System Hardening

- **[P1] [L-SH-01]** Remove unnecessary packages, services, and daemons.
- **[P1] [L-SH-02]** Configure secure default file permissions and restrictive umasks.
...

🧩 Design & Governance Approach

This tool is intentionally simple and oriented towards governance:

Each recommendation is treated as a security control.

Controls include:

a control identifier (per environment and domain),

a priority level (P1 / P2 / P3).

Output can be:

copy-pasted into a security policy,

used as a checklist for audits,

integrated into an IT governance toolkit.

This demonstrates:

capacity to structure security requirements,

understanding of risk-based prioritization,

ability to produce documentation ready for RSSI/DSI usage.

🧪 Possible Enhancements

Add a --level filter (e.g. --min-priority P1 to only show critical controls).

Map each control to frameworks (e.g. ISO 27001, NIST CSF) as additional metadata.

Export to JSON / YAML for integration with GRC tools.

Build a small web UI on top of the generator (Flask / FastAPI).
