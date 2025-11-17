# 🔐 Security Best Practices Generator (Governance Edition)

A governance-oriented CLI tool that generates **structured security best practices** for:

- 🪟 Windows workstations / servers  
- 🐧 Linux servers / desktops  
- 🌐 Web servers  

Each recommendation is presented as a **control**, with:

- An **ID** (e.g. `WIN-ACC-01`, `LNX-SYS-02`, `WEB-TLS-01`)  
- A **priority level**:
  - `P1 – Critical`
  - `P2 – High`
  - `P3 – Medium`
- A **category** (Accounts, System Hardening, Network, etc.)

This is designed to look like a **real-world governance artifact** used by a **CISO/RSSI** or **CIO/DSI**.

---

## ✨ Features

- Targets:
  - `windows`
  - `linux`
  - `webserver`
- Formats:
  - `text`  → console / quick review
  - `markdown` → documentation, wiki, or policy annex
- Governance style:
  - Unique control IDs
  - Priority levels (P1/P2/P3)
  - Grouped by domain (Accounts, Hardening, Network, Logging, Backup, Web Security, TLS, etc.)

---

## 🛠️ Installation

### Requirements

- Python **3.8+**

### Clone the repository

```bash
git clone https://github.com/<your-username>/security-best-practices-generator.git
cd security-best-practices-generator
```

🚀 Usage

Display help:

python best_practices_generator.py --help

Generate Windows best practices (text)
python best_practices_generator.py --target windows --format text

Generate Linux best practices (Markdown) and save to file
python best_practices_generator.py --target linux --format markdown --output linux_baseline.md

Generate Web Server best practices (Markdown) for a wiki
python best_practices_generator.py --target webserver --format markdown --output webserver_security_baseline.md

📌 Example Output (Markdown, Windows)
# Security Best Practices – windows

## 1. Accounts & Authentication

1. **WIN-ACC-01** `[P1 – Critical]` Enforce strong password policies (length, complexity, history, expiration).
2. **WIN-ACC-02** `[P1 – Critical]` Enable account lockout policies after multiple failed login attempts.
3. **WIN-ACC-03** `[P2 – High]` Use multi-factor authentication (MFA) for privileged and remote access.
4. **WIN-ACC-04** `[P2 – High]` Regularly review local users/groups and remove or disable unused accounts.
5. **WIN-ACC-05** `[P3 – Medium]` Rename or disable the default local Administrator account when possible.

## 2. System Hardening

1. **WIN-SYS-01** `[P1 – Critical]` Remove or disable unused software, services, and legacy components.
2. **WIN-SYS-02** `[P1 – Critical]` Restrict local administrator rights and use standard accounts for daily work.
...

🧩 Governance Model

Each control is structured as:

ID: platform + domain + sequence

WIN-ACC-01, LNX-NET-03, WEB-TLS-02, etc.

Priority:

P1 – Critical: must-have for a secure baseline

P2 – High: strong recommendation, short-term implementation

P3 – Medium: improvement, medium-term or contextual

This structure makes it easy to:

build security baselines,

reference controls in policies/procedures,

create implementation roadmaps (start with P1, then P2, then P3).

🧪 Possible Extensions

Ideas to evolve the project:

Add --level or --priority-min to filter only P1 or P1+P2 controls.

Export in json or yaml for integration with GRC tools.

Add mappings (e.g. ISO 27001, CIS Controls) as metadata.

Build a small web frontend (Flask/FastAPI) for browsing controls.
