#!/usr/bin/env python3

"""
Security Best Practices Generator (Governance Edition)

Generates structured, governance-style security controls for:
- Windows
- Linux
- Web Server

Controls include:
- ID (e.g. WIN-ACC-01)
- Priority (P1 / P2 / P3)
- Description

Usage examples:
    python best_practices_generator.py --target windows --format text
    python best_practices_generator.py --target linux --format markdown --output linux_baseline.md
    python best_practices_generator.py --target webserver --format markdown --output web_baseline.md
"""

import argparse
from typing import Dict, List, TypedDict


class Control(TypedDict):
    id: str
    priority: str
    description: str


BEST_PRACTICES: Dict[str, Dict[str, List[Control]]] = {
    "windows": {
        "Accounts & Authentication": [
            {
                "id": "WIN-ACC-01",
                "priority": "P1 – Critical",
                "description": "Enforce strong password policies (length, complexity, history, expiration).",
            },
            {
                "id": "WIN-ACC-02",
                "priority": "P1 – Critical",
                "description": "Enable account lockout policies after multiple failed login attempts.",
            },
            {
                "id": "WIN-ACC-03",
                "priority": "P2 – High",
                "description": "Use multi-factor authentication (MFA) for privileged and remote access.",
            },
            {
                "id": "WIN-ACC-04",
                "priority": "P2 – High",
                "description": "Regularly review local users and groups and remove or disable unused accounts.",
            },
            {
                "id": "WIN-ACC-05",
                "priority": "P3 – Medium",
                "description": "Rename or disable the default local Administrator account when possible.",
            },
        ],
        "System Hardening": [
            {
                "id": "WIN-SYS-01",
                "priority": "P1 – Critical",
                "description": "Remove or disable unused software, services, and legacy components.",
            },
            {
                "id": "WIN-SYS-02",
                "priority": "P1 – Critical",
                "description": "Restrict local administrator rights and use standard accounts for daily work.",
            },
            {
                "id": "WIN-SYS-03",
                "priority": "P2 – High",
                "description": "Enable full-disk encryption (e.g. BitLocker) on laptops and sensitive workstations.",
            },
            {
                "id": "WIN-SYS-04",
                "priority": "P2 – High",
                "description": "Configure automatic screen lock with a short inactivity timeout and password on resume.",
            },
            {
                "id": "WIN-SYS-05",
                "priority": "P3 – Medium",
                "description": "Harden PowerShell usage and enable detailed PowerShell logging for administrative actions.",
            },
        ],
        "Network & Firewall": [
            {
                "id": "WIN-NET-01",
                "priority": "P1 – Critical",
                "description": "Enable and configure Windows Defender Firewall with restrictive inbound rules.",
            },
            {
                "id": "WIN-NET-02",
                "priority": "P1 – Critical",
                "description": "Block inbound traffic by default and only allow required ports and applications.",
            },
            {
                "id": "WIN-NET-03",
                "priority": "P2 – High",
                "description": "Disable legacy and insecure network protocols (e.g. SMBv1).",
            },
            {
                "id": "WIN-NET-04",
                "priority": "P2 – High",
                "description": "Use VPN with strong encryption for remote access to internal resources.",
            },
            {
                "id": "WIN-NET-05",
                "priority": "P3 – Medium",
                "description": "Segment networks (workstations, servers, guests) using VLANs and ACLs.",
            },
        ],
        "Updates & Patch Management": [
            {
                "id": "WIN-UPD-01",
                "priority": "P1 – Critical",
                "description": "Enable automatic Windows Updates or manage updates centrally (e.g. WSUS/SCCM).",
            },
            {
                "id": "WIN-UPD-02",
                "priority": "P1 – Critical",
                "description": "Apply critical security patches in a timely manner on all workstations and servers.",
            },
            {
                "id": "WIN-UPD-03",
                "priority": "P2 – High",
                "description": "Regularly patch third-party applications (browsers, Java, PDF readers, etc.).",
            },
            {
                "id": "WIN-UPD-04",
                "priority": "P2 – High",
                "description": "Define and document a patch management process including testing and rollback.",
            },
            {
                "id": "WIN-UPD-05",
                "priority": "P3 – Medium",
                "description": "Schedule maintenance windows to limit business impact of updates and reboots.",
            },
        ],
        "Logging & Monitoring": [
            {
                "id": "WIN-LOG-01",
                "priority": "P1 – Critical",
                "description": "Enable advanced audit policies (logon events, privilege use, object access).",
            },
            {
                "id": "WIN-LOG-02",
                "priority": "P1 – Critical",
                "description": "Forward security logs to a central logging or SIEM solution for correlation.",
            },
            {
                "id": "WIN-LOG-03",
                "priority": "P2 – High",
                "description": "Monitor failed logons, privilege escalations, and suspicious account behavior.",
            },
            {
                "id": "WIN-LOG-04",
                "priority": "P2 – High",
                "description": "Regularly review antivirus and endpoint protection logs for detected threats.",
            },
            {
                "id": "WIN-LOG-05",
                "priority": "P3 – Medium",
                "description": "Define alert thresholds and incident handling procedures for key security events.",
            },
        ],
        "Backup & Recovery": [
            {
                "id": "WIN-BCK-01",
                "priority": "P1 – Critical",
                "description": "Implement regular backups of critical data and system configurations.",
            },
            {
                "id": "WIN-BCK-02",
                "priority": "P1 – Critical",
                "description": "Store backups in a separate location and protect them from direct access and ransomware.",
            },
            {
                "id": "WIN-BCK-03",
                "priority": "P2 – High",
                "description": "Test backup restoration procedures regularly and document the results.",
            },
            {
                "id": "WIN-BCK-04",
                "priority": "P2 – High",
                "description": "Ensure encryption keys and BitLocker recovery keys are securely stored.",
            },
            {
                "id": "WIN-BCK-05",
                "priority": "P3 – Medium",
                "description": "Define RPO/RTO objectives and verify that backup frequency and retention meet them.",
            },
        ],
    },
    "linux": {
        "Accounts & Authentication": [
            {
                "id": "LNX-ACC-01",
                "priority": "P1 – Critical",
                "description": "Enforce strong password policies using PAM (length, complexity, history).",
            },
            {
                "id": "LNX-ACC-02",
                "priority": "P1 – Critical",
                "description": "Disable direct root login over SSH (`PermitRootLogin no`).",
            },
            {
                "id": "LNX-ACC-03",
                "priority": "P2 – High",
                "description": "Use `sudo` with least-privilege configurations instead of direct root access.",
            },
            {
                "id": "LNX-ACC-04",
                "priority": "P2 – High",
                "description": "Lock or remove unused user accounts and default system accounts.",
            },
            {
                "id": "LNX-ACC-05",
                "priority": "P3 – Medium",
                "description": "Use SSH key-based authentication for administrative access.",
            },
        ],
        "System Hardening": [
            {
                "id": "LNX-SYS-01",
                "priority": "P1 – Critical",
                "description": "Remove unnecessary packages, services, and daemons from the system.",
            },
            {
                "id": "LNX-SYS-02",
                "priority": "P1 – Critical",
                "description": "Set secure default file permissions and configure restrictive `umask` values.",
            },
            {
                "id": "LNX-SYS-03",
                "priority": "P2 – High",
                "description": "Restrict access to sensitive files such as `/etc/shadow` and `/etc/sudoers`.",
            },
            {
                "id": "LNX-SYS-04",
                "priority": "P2 – High",
                "description": "Enable and configure SELinux or AppArmor on supported systems.",
            },
            {
                "id": "LNX-SYS-05",
                "priority": "P3 – Medium",
                "description": "Use full-disk encryption on laptops and sensitive servers.",
            },
        ],
        "Network & Firewall": [
            {
                "id": "LNX-NET-01",
                "priority": "P1 – Critical",
                "description": "Enable a host-based firewall (e.g. `ufw`, `firewalld`, or `iptables`).",
            },
            {
                "id": "LNX-NET-02",
                "priority": "P1 – Critical",
                "description": "Deny incoming traffic by default and only allow required services.",
            },
            {
                "id": "LNX-NET-03",
                "priority": "P2 – High",
                "description": "Disable unused network services and close unnecessary listening ports.",
            },
            {
                "id": "LNX-NET-04",
                "priority": "P2 – High",
                "description": "Restrict SSH access to specific IP ranges or via VPN when possible.",
            },
            {
                "id": "LNX-NET-05",
                "priority": "P3 – Medium",
                "description": "Deploy tools such as fail2ban to block repeated brute-force attempts.",
            },
        ],
        "Updates & Patch Management": [
            {
                "id": "LNX-UPD-01",
                "priority": "P1 – Critical",
                "description": "Regularly apply security patches using the distribution's package manager.",
            },
            {
                "id": "LNX-UPD-02",
                "priority": "P1 – Critical",
                "description": "Subscribe to distribution security advisories and track critical vulnerabilities.",
            },
            {
                "id": "LNX-UPD-03",
                "priority": "P2 – High",
                "description": "Standardize on LTS versions for production systems where possible.",
            },
            {
                "id": "LNX-UPD-04",
                "priority": "P2 – High",
                "description": "Test patches on non-production systems before widespread deployment.",
            },
            {
                "id": "LNX-UPD-05",
                "priority": "P3 – Medium",
                "description": "Plan and document maintenance windows for patching and reboots.",
            },
        ],
        "Logging & Monitoring": [
            {
                "id": "LNX-LOG-01",
                "priority": "P1 – Critical",
                "description": "Enable and retain system logs using `rsyslog`, `journald`, or similar.",
            },
            {
                "id": "LNX-LOG-02",
                "priority": "P1 – Critical",
                "description": "Monitor authentication logs (e.g. `/var/log/auth.log`) for suspicious activity.",
            },
            {
                "id": "LNX-LOG-03",
                "priority": "P2 – High",
                "description": "Forward logs to a centralized log management or SIEM platform.",
            },
            {
                "id": "LNX-LOG-04",
                "priority": "P2 – High",
                "description": "Define alerting rules for critical events (authentication failures, service crashes, etc.).",
            },
            {
                "id": "LNX-LOG-05",
                "priority": "P3 – Medium",
                "description": "Implement monitoring tools (e.g. Prometheus, Zabbix) for availability and performance.",
            },
        ],
        "Backup & Recovery": [
            {
                "id": "LNX-BCK-01",
                "priority": "P1 – Critical",
                "description": "Implement automated backups for critical data and configuration files.",
            },
            {
                "id": "LNX-BCK-02",
                "priority": "P1 – Critical",
                "description": "Store backups on separate systems or storage with restricted access.",
            },
            {
                "id": "LNX-BCK-03",
                "priority": "P2 – High",
                "description": "Regularly test backup restoration and document the procedures.",
            },
            {
                "id": "LNX-BCK-04",
                "priority": "P2 – High",
                "description": "Use versioned backups to protect against accidental deletions and corruption.",
            },
            {
                "id": "LNX-BCK-05",
                "priority": "P3 – Medium",
                "description": "Encrypt backup data at rest and enforce strict access controls.",
            },
        ],
    },
    "webserver": {
        "Accounts & Authentication": [
            {
                "id": "WEB-ACC-01",
                "priority": "P1 – Critical",
                "description": "Use unique, strong credentials for all administrative interfaces.",
            },
            {
                "id": "WEB-ACC-02",
                "priority": "P1 – Critical",
                "description": "Restrict access to admin panels by IP range or VPN when possible.",
            },
            {
                "id": "WEB-ACC-03",
                "priority": "P2 – High",
                "description": "Use multi-factor authentication (MFA) on hosting, CMS, and admin consoles.",
            },
            {
                "id": "WEB-ACC-04",
                "priority": "P2 – High",
                "description": "Avoid default usernames (e.g. 'admin') for administrative accounts.",
            },
            {
                "id": "WEB-ACC-05",
                "priority": "P3 – Medium",
                "description": "Apply least-privilege principles to database and application accounts.",
            },
        ],
        "System & Application Hardening": [
            {
                "id": "WEB-SYS-01",
                "priority": "P1 – Critical",
                "description": "Keep the web server (e.g. Nginx, Apache) and OS fully patched.",
            },
            {
                "id": "WEB-SYS-02",
                "priority": "P1 – Critical",
                "description": "Remove default files, demo applications, and unused modules.",
            },
            {
                "id": "WEB-SYS-03",
                "priority": "P2 – High",
                "description": "Run web services under dedicated, unprivileged service accounts.",
            },
            {
                "id": "WEB-SYS-04",
                "priority": "P2 – High",
                "description": "Apply vendor-recommended hardening guides and security baselines.",
            },
            {
                "id": "WEB-SYS-05",
                "priority": "P3 – Medium",
                "description": "Avoid running unrelated services (mail, file sharing) on the same web server.",
            },
        ],
        "Network & TLS": [
            {
                "id": "WEB-TLS-01",
                "priority": "P1 – Critical",
                "description": "Enforce HTTPS for all web traffic and redirect HTTP to HTTPS.",
            },
            {
                "id": "WEB-TLS-02",
                "priority": "P1 – Critical",
                "description": "Disable obsolete protocols and weak ciphers in the TLS configuration.",
            },
            {
                "id": "WEB-TLS-03",
                "priority": "P2 – High",
                "description": "Implement HSTS (HTTP Strict Transport Security) with appropriate max-age.",
            },
            {
                "id": "WEB-TLS-04",
                "priority": "P2 – High",
                "description": "Use certificates from a trusted CA and automate renewals (e.g. Let's Encrypt).",
            },
            {
                "id": "WEB-TLS-05",
                "priority": "P3 – Medium",
                "description": "Restrict direct database and admin access from the internet using firewalls and segmentation.",
            },
        ],
        "Web Security Headers": [
            {
                "id": "WEB-HDR-01",
                "priority": "P1 – Critical",
                "description": "Set a strict Content-Security-Policy (CSP) to control allowed content sources.",
            },
            {
                "id": "WEB-HDR-02",
                "priority": "P2 – High",
                "description": "Use X-Frame-Options or CSP frame-ancestors to prevent clickjacking.",
            },
            {
                "id": "WEB-HDR-03",
                "priority": "P2 – High",
                "description": "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
            },
            {
                "id": "WEB-HDR-04",
                "priority": "P3 – Medium",
                "description": "Configure Referrer-Policy to limit referrer information leakage.",
            },
            {
                "id": "WEB-HDR-05",
                "priority": "P3 – Medium",
                "description": "Set secure cookies with Secure, HttpOnly, and SameSite attributes.",
            },
        ],
        "Application & Data Security": [
            {
                "id": "WEB-APP-01",
                "priority": "P1 – Critical",
                "description": "Validate and sanitize all user inputs on the server side.",
            },
            {
                "id": "WEB-APP-02",
                "priority": "P1 – Critical",
                "description": "Use prepared statements/parameterized queries for all database access.",
            },
            {
                "id": "WEB-APP-03",
                "priority": "P2 – High",
                "description": "Store passwords using strong, salted hashing algorithms (e.g. bcrypt, Argon2).",
            },
            {
                "id": "WEB-APP-04",
                "priority": "P2 – High",
                "description": "Restrict and validate file uploads (type, size) and scan them for malware where possible.",
            },
            {
                "id": "WEB-APP-05",
                "priority": "P3 – Medium",
                "description": "Block direct access to sensitive files, backups, and configuration directories.",
            },
        ],
        "Logging, Monitoring & Incident Response": [
            {
                "id": "WEB-LOG-01",
                "priority": "P1 – Critical",
                "description": "Enable detailed access and error logging on the web server.",
            },
            {
                "id": "WEB-LOG-02",
                "priority": "P1 – Critical",
                "description": "Forward logs to a centralized log management or SIEM solution.",
            },
            {
                "id": "WEB-LOG-03",
                "priority": "P2 – High",
                "description": "Monitor for anomalies such as brute-force attempts, scanning patterns, and unusual HTTP codes.",
            },
            {
                "id": "WEB-LOG-04",
                "priority": "P2 – High",
                "description": "Define and document an incident response plan for web application security events.",
            },
            {
                "id": "WEB-LOG-05",
                "priority": "P3 – Medium",
                "description": "Regularly review web application and infrastructure logs for signs of compromise.",
            },
        ],
        "Backup & Recovery": [
            {
                "id": "WEB-BCK-01",
                "priority": "P1 – Critical",
                "description": "Implement regular backups of web content, configuration, and databases.",
            },
            {
                "id": "WEB-BCK-02",
                "priority": "P1 – Critical",
                "description": "Store backups securely, offsite or in a separate environment from production.",
            },
            {
                "id": "WEB-BCK-03",
                "priority": "P2 – High",
                "description": "Regularly test restoration of both code and data.",
            },
            {
                "id": "WEB-BCK-04",
                "priority": "P2 – High",
                "description": "Version-control application code and configuration where possible.",
            },
            {
                "id": "WEB-BCK-05",
                "priority": "P3 – Medium",
                "description": "Document recovery procedures for the web server, database, and DNS components.",
            },
        ],
    },
}


def render_text(target: str) -> str:
    """Render best practices as plain text (governance style)."""
    sections = BEST_PRACTICES[target]
    title = f"Security Best Practices – {target}"
    lines: List[str] = [title, "=" * len(title), ""]

    for section_name, controls in sections.items():
        lines.append(section_name)
        lines.append("-" * len(section_name))
        for idx, ctrl in enumerate(controls, start=1):
            lines.append(
                f"{idx}. {ctrl['id']} [{ctrl['priority']}] {ctrl['description']}"
            )
        lines.append("")

    return "\n".join(lines)


def render_markdown(target: str) -> str:
    """Render best practices as Markdown (governance style)."""
    sections = BEST_PRACTICES[target]
    lines: List[str] = [f"# Security Best Practices – {target}", ""]

    for section_index, (section_name, controls) in enumerate(
        sections.items(), start=1
    ):
        lines.append(f"## {section_index}. {section_name}")
        lines.append("")
        for idx, ctrl in enumerate(controls, start=1):
            lines.append(
                f"{idx}. **{ctrl['id']}** `[{ctrl['priority']}]` {ctrl['description']}"
            )
        lines.append("")

    return "\n".join(lines)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate governance-style security best practices for Windows, Linux, or Web Server."
    )
    parser.add_argument(
        "--target",
        required=True,
        choices=BEST_PRACTICES.keys(),
        help="Target environment: windows, linux, webserver.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "markdown"],
        default="text",
        help="Output format: text (default) or markdown.",
    )
    parser.add_argument(
        "--output",
        help="Optional path to output file. If not set, prints to stdout.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    if args.format == "markdown":
        content = render_markdown(args.target)
    else:
        content = render_text(args.target)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Best practices for '{args.target}' written to {args.output}")
        except OSError as e:
            print(f"[!] Failed to write to {args.output}: {e}")
    else:
        print(content)


if __name__ == "__main__":
    main()
