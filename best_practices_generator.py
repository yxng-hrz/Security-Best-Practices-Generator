#!/usr/bin/env python3
"""
Security Best Practices Generator

Generates curated security recommendations for:
- Windows
- Linux
- Web Server

Usage examples:
    python best_practices_generator.py --target windows
    python best_practices_generator.py --target linux --format markdown
    python best_practices_generator.py --target webserver --format markdown --output webserver.md
"""

import argparse
from textwrap import indent


BEST_PRACTICES = {
    "windows": {
        "Accounts & Authentication": [
            "Enforce strong password policies (length, complexity, expiration).",
            "Enable account lockout policies after multiple failed login attempts.",
            "Use multi-factor authentication (MFA) for privileged accounts and remote access.",
            "Disable or rename the default Administrator account if possible.",
            "Regularly review local users and groups and remove unused accounts."
        ],
        "System Hardening": [
            "Remove or disable unused software and services.",
            "Restrict local administrator rights and use standard accounts for daily work.",
            "Enable BitLocker or another full-disk encryption solution on laptops.",
            "Use secure screen lock policies (short timeout, password required on resume).",
            "Harden PowerShell usage and logging for administrative operations."
        ],
        "Network & Firewall": [
            "Enable and configure Windows Defender Firewall with appropriate rules.",
            "Block inbound traffic by default and only allow required ports and applications.",
            "Disable legacy and insecure network protocols (e.g. SMBv1).",
            "Segment networks (e.g. workstations, servers, guests) using VLANs and ACLs.",
            "Use VPN with strong encryption for remote connections."
        ],
        "Updates & Patch Management": [
            "Enable automatic Windows Updates or use a central WSUS/SCCM solution.",
            "Regularly patch third-party applications (browsers, Java, PDF readers, etc.).",
            "Define a patch management process with testing and rollback plans.",
            "Track patch status and ensure critical updates are deployed quickly.",
            "Schedule maintenance windows to avoid business disruption."
        ],
        "Logging & Monitoring": [
            "Enable advanced audit policies (logon events, privilege use, object access).",
            "Send logs to a central log or SIEM solution for correlation and alerting.",
            "Monitor security events such as failed logons and privilege escalations.",
            "Regularly review antivirus logs and threat histories.",
            "Set up alerts for unusual activity (logon outside hours, multiple failures, etc.)."
        ],
        "Backup & Recovery": [
            "Implement regular backups of user data and critical system configuration.",
            "Test backup restoration procedures at least annually.",
            "Store backups offline or offsite to protect against ransomware.",
            "Document recovery procedures for common incident scenarios.",
            "Ensure that encryption keys and recovery keys are safely stored."
        ]
    },
    "linux": {
        "Accounts & Authentication": [
            "Enforce strong passwords using PAM (length, complexity, history).",
            "Disable direct root login via SSH (set `PermitRootLogin no`).",
            "Use `sudo` with least-privilege principles instead of direct root access.",
            "Lock or remove unused user accounts and default system accounts.",
            "Use SSH keys instead of passwords for administrative access."
        ],
        "System Hardening": [
            "Remove unnecessary packages, services, and daemons.",
            "Configure secure default file permissions and use restrictive umasks.",
            "Limit access to sensitive files such as `/etc/shadow` and `/etc/sudoers`.",
            "Enable and configure SELinux or AppArmor where appropriate.",
            "Use secure boot and disk encryption for laptops and sensitive servers."
        ],
        "Network & Firewall": [
            "Enable a host firewall (e.g. `ufw`, `firewalld`, or `iptables`).",
            "Deny incoming traffic by default and allow only required services.",
            "Disable unused network services and listening ports.",
            "Restrict SSH access by IP range or VPN when possible.",
            "Use fail2ban or similar tools to block repeated brute-force attempts."
        ],
        "Updates & Patch Management": [
            "Regularly update the system and security patches via package manager.",
            "Subscribe to distribution security advisories and plan patch cycles.",
            "Standardize on LTS versions for production systems.",
            "Reboot systems when necessary to apply kernel and critical updates.",
            "Test updates on non-production systems before large-scale deployment."
        ],
        "Logging & Monitoring": [
            "Enable and centralize system logs using `rsyslog`, `journald`, or similar.",
            "Monitor authentication logs (e.g. `/var/log/auth.log`) for suspicious activity.",
            "Use a monitoring stack (e.g. Prometheus, Zabbix, or similar) for availability.",
            "Configure alerts on critical events such as disk full, CPU spikes, or service failure.",
            "Rotate logs and ensure retention policies comply with regulation and needs."
        ],
        "Backup & Recovery": [
            "Automate regular backups of important data and configuration files.",
            "Store backups on separate, access-restricted systems or storage.",
            "Test restoration procedures and document them.",
            "Use versioned backups to protect against accidental deletion and corruption.",
            "Protect backup locations with encryption and strict access control."
        ]
    },
    "webserver": {
        "Accounts & Authentication": [
            "Use unique, strong credentials for all administrative interfaces.",
            "Restrict administrative panels to specific IP ranges or VPN access.",
            "Use multi-factor authentication (MFA) for hosting control panels and CMS admin accounts.",
            "Avoid using default usernames (e.g. 'admin', 'root') for web admin accounts.",
            "Ensure database and application users follow least-privilege principles."
        ],
        "System & Application Hardening": [
            "Keep the web server software (e.g. Nginx, Apache) up to date.",
            "Disable and remove default files, test pages, and unused modules.",
            "Run web services under dedicated, unprivileged service accounts.",
            "Apply secure configuration baselines (e.g. recommended vendor hardening guides).",
            "Avoid running other non-essential services on the same server."
        ],
        "Network & TLS": [
            "Enforce HTTPS for all web traffic and redirect HTTP to HTTPS.",
            "Use modern TLS configurations and disable weak ciphers and protocols.",
            "Implement HSTS (HTTP Strict Transport Security) with appropriate settings.",
            "Use a reputable certificate authority and automate certificate renewal (e.g. Let's Encrypt).",
            "Restrict direct database or admin access from the internet; use firewalls and network segmentation."
        ],
        "Web Security Headers": [
            "Set `Content-Security-Policy` (CSP) to limit sources of scripts and content.",
            "Use `X-Frame-Options` or `Content-Security-Policy` frame-ancestors to prevent clickjacking.",
            "Set `X-Content-Type-Options: nosniff` to prevent MIME-type sniffing.",
            "Use `Referrer-Policy` to control referrer information leakage.",
            "Set secure cookies with `Secure`, `HttpOnly`, and `SameSite` attributes."
        ],
        "Application & Data Security": [
            "Validate and sanitize all user inputs on the server-side.",
            "Use prepared statements / parameterized queries for all database access.",
            "Store passwords using strong hashing functions with salts (e.g. bcrypt, Argon2).",
            "Limit file upload types, size, and scan uploads for malware if possible.",
            "Restrict direct access to sensitive files, backups, and configuration files."
        ],
        "Logging, Monitoring & Incident Response": [
            "Enable and centralize access logs and error logs for the web server.",
            "Monitor for unusual patterns (e.g. repeated 404s, login failures, suspicious URLs).",
            "Integrate logs into a SIEM or log management system for correlation and alerts.",
            "Define an incident response plan for security events affecting the web application.",
            "Regularly review logs and security reports for signs of compromise."
        ],
        "Backup & Recovery": [
            "Schedule regular backups of web content, configuration, and databases.",
            "Store backups securely and preferably offsite or in a different environment.",
            "Test restoration of both code and data to ensure recoverability.",
            "Version-control configuration and application code when possible.",
            "Document recovery procedures for critical components (webserver, database, DNS)."
        ]
    }
}


def render_text(target: str) -> str:
    """Render best practices as plain text."""
    sections = BEST_PRACTICES[target]
    lines = [f"Security Best Practices – {target}"]
    lines.append("=" * len(lines[0]))
    lines.append("")

    for section_name, items in sections.items():
        lines.append(f"{section_name}")
        lines.append("-" * len(section_name))
        for item in items:
            lines.append(f"- {item}")
        lines.append("")

    return "\n".join(lines)


def render_markdown(target: str) -> str:
    """Render best practices as Markdown."""
    sections = BEST_PRACTICES[target]
    lines = [f"# Security Best Practices – {target}", ""]
    for index, (section_name, items) in enumerate(sections.items(), start=1):
        lines.append(f"## {index}. {section_name}")
        for item in items:
            lines.append(f"- {item}")
        lines.append("")

    return "\n".join(lines)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate security best practices for Windows, Linux, or Web Server."
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
