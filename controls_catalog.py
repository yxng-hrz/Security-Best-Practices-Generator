"""Control catalogue for the Security Best Practices Generator.

Each target contains domains; each domain contains controls with a stable ID,
a priority (P1/P2/P3) and an actionable description. Framework mappings are
maintained at domain level in DOMAIN_METADATA.
"""
from typing import Dict, List, TypedDict


class Control(TypedDict):
    id: str
    priority: str
    description: str


TARGET_LABELS: Dict[str, str] = {'windows': 'Windows workstations & servers',
 'linux': 'Linux servers & desktops',
 'webserver': 'Web servers & web applications',
 'cloud': 'Public cloud (AWS / Azure / GCP)',
 'active_directory': 'Active Directory'}

BEST_PRACTICES: Dict[str, Dict[str, List[Control]]] = {
    "windows": {
        "Accounts & Authentication": [
            {
                "id": "WIN-ACC-01",
                "priority": "P1 – Critical",
                "description": "Enforce strong password policies (length, complexity, history, expiration)."
            },
            {
                "id": "WIN-ACC-02",
                "priority": "P1 – Critical",
                "description": "Enable account lockout policies after multiple failed login attempts."
            },
            {
                "id": "WIN-ACC-03",
                "priority": "P2 – High",
                "description": "Use multi-factor authentication (MFA) for privileged and remote access."
            },
            {
                "id": "WIN-ACC-04",
                "priority": "P2 – High",
                "description": "Regularly review local users and groups and remove or disable unused accounts."
            },
            {
                "id": "WIN-ACC-05",
                "priority": "P3 – Medium",
                "description": "Rename or disable the default local Administrator account when possible."
            }
        ],
        "System Hardening": [
            {
                "id": "WIN-SYS-01",
                "priority": "P1 – Critical",
                "description": "Remove or disable unused software, services, and legacy components."
            },
            {
                "id": "WIN-SYS-02",
                "priority": "P1 – Critical",
                "description": "Restrict local administrator rights and use standard accounts for daily work."
            },
            {
                "id": "WIN-SYS-03",
                "priority": "P2 – High",
                "description": "Enable full-disk encryption (e.g. BitLocker) on laptops and sensitive workstations."
            },
            {
                "id": "WIN-SYS-04",
                "priority": "P2 – High",
                "description": "Configure automatic screen lock with a short inactivity timeout and password on resume."
            },
            {
                "id": "WIN-SYS-05",
                "priority": "P3 – Medium",
                "description": "Harden PowerShell usage and enable detailed PowerShell logging for administrative actions."
            }
        ],
        "Network & Firewall": [
            {
                "id": "WIN-NET-01",
                "priority": "P1 – Critical",
                "description": "Enable and configure Windows Defender Firewall with restrictive inbound rules."
            },
            {
                "id": "WIN-NET-02",
                "priority": "P1 – Critical",
                "description": "Block inbound traffic by default and only allow required ports and applications."
            },
            {
                "id": "WIN-NET-03",
                "priority": "P2 – High",
                "description": "Disable legacy and insecure network protocols (e.g. SMBv1)."
            },
            {
                "id": "WIN-NET-04",
                "priority": "P2 – High",
                "description": "Use VPN with strong encryption for remote access to internal resources."
            },
            {
                "id": "WIN-NET-05",
                "priority": "P3 – Medium",
                "description": "Segment networks (workstations, servers, guests) using VLANs and ACLs."
            }
        ],
        "Updates & Patch Management": [
            {
                "id": "WIN-UPD-01",
                "priority": "P1 – Critical",
                "description": "Enable automatic Windows Updates or manage updates centrally (e.g. WSUS/SCCM)."
            },
            {
                "id": "WIN-UPD-02",
                "priority": "P1 – Critical",
                "description": "Apply critical security patches in a timely manner on all workstations and servers."
            },
            {
                "id": "WIN-UPD-03",
                "priority": "P2 – High",
                "description": "Regularly patch third-party applications (browsers, Java, PDF readers, etc.)."
            },
            {
                "id": "WIN-UPD-04",
                "priority": "P2 – High",
                "description": "Define and document a patch management process including testing and rollback."
            },
            {
                "id": "WIN-UPD-05",
                "priority": "P3 – Medium",
                "description": "Schedule maintenance windows to limit business impact of updates and reboots."
            }
        ],
        "Logging & Monitoring": [
            {
                "id": "WIN-LOG-01",
                "priority": "P1 – Critical",
                "description": "Enable advanced audit policies (logon events, privilege use, object access)."
            },
            {
                "id": "WIN-LOG-02",
                "priority": "P1 – Critical",
                "description": "Forward security logs to a central logging or SIEM solution for correlation."
            },
            {
                "id": "WIN-LOG-03",
                "priority": "P2 – High",
                "description": "Monitor failed logons, privilege escalations, and suspicious account behavior."
            },
            {
                "id": "WIN-LOG-04",
                "priority": "P2 – High",
                "description": "Regularly review antivirus and endpoint protection logs for detected threats."
            },
            {
                "id": "WIN-LOG-05",
                "priority": "P3 – Medium",
                "description": "Define alert thresholds and incident handling procedures for key security events."
            }
        ],
        "Backup & Recovery": [
            {
                "id": "WIN-BCK-01",
                "priority": "P1 – Critical",
                "description": "Implement regular backups of critical data and system configurations."
            },
            {
                "id": "WIN-BCK-02",
                "priority": "P1 – Critical",
                "description": "Store backups in a separate location and protect them from direct access and ransomware."
            },
            {
                "id": "WIN-BCK-03",
                "priority": "P2 – High",
                "description": "Test backup restoration procedures regularly and document the results."
            },
            {
                "id": "WIN-BCK-04",
                "priority": "P2 – High",
                "description": "Ensure encryption keys and BitLocker recovery keys are securely stored."
            },
            {
                "id": "WIN-BCK-05",
                "priority": "P3 – Medium",
                "description": "Define RPO/RTO objectives and verify that backup frequency and retention meet them."
            }
        ]
    },
    "linux": {
        "Accounts & Authentication": [
            {
                "id": "LNX-ACC-01",
                "priority": "P1 – Critical",
                "description": "Enforce strong password policies using PAM (length, complexity, history)."
            },
            {
                "id": "LNX-ACC-02",
                "priority": "P1 – Critical",
                "description": "Disable direct root login over SSH (`PermitRootLogin no`)."
            },
            {
                "id": "LNX-ACC-03",
                "priority": "P2 – High",
                "description": "Use `sudo` with least-privilege configurations instead of direct root access."
            },
            {
                "id": "LNX-ACC-04",
                "priority": "P2 – High",
                "description": "Lock or remove unused user accounts and default system accounts."
            },
            {
                "id": "LNX-ACC-05",
                "priority": "P3 – Medium",
                "description": "Use SSH key-based authentication for administrative access."
            }
        ],
        "System Hardening": [
            {
                "id": "LNX-SYS-01",
                "priority": "P1 – Critical",
                "description": "Remove unnecessary packages, services, and daemons from the system."
            },
            {
                "id": "LNX-SYS-02",
                "priority": "P1 – Critical",
                "description": "Set secure default file permissions and configure restrictive `umask` values."
            },
            {
                "id": "LNX-SYS-03",
                "priority": "P2 – High",
                "description": "Restrict access to sensitive files such as `/etc/shadow` and `/etc/sudoers`."
            },
            {
                "id": "LNX-SYS-04",
                "priority": "P2 – High",
                "description": "Enable and configure SELinux or AppArmor on supported systems."
            },
            {
                "id": "LNX-SYS-05",
                "priority": "P3 – Medium",
                "description": "Use full-disk encryption on laptops and sensitive servers."
            }
        ],
        "Network & Firewall": [
            {
                "id": "LNX-NET-01",
                "priority": "P1 – Critical",
                "description": "Enable a host-based firewall (e.g. `ufw`, `firewalld`, or `iptables`)."
            },
            {
                "id": "LNX-NET-02",
                "priority": "P1 – Critical",
                "description": "Deny incoming traffic by default and only allow required services."
            },
            {
                "id": "LNX-NET-03",
                "priority": "P2 – High",
                "description": "Disable unused network services and close unnecessary listening ports."
            },
            {
                "id": "LNX-NET-04",
                "priority": "P2 – High",
                "description": "Restrict SSH access to specific IP ranges or via VPN when possible."
            },
            {
                "id": "LNX-NET-05",
                "priority": "P3 – Medium",
                "description": "Deploy tools such as fail2ban to block repeated brute-force attempts."
            }
        ],
        "Updates & Patch Management": [
            {
                "id": "LNX-UPD-01",
                "priority": "P1 – Critical",
                "description": "Regularly apply security patches using the distribution's package manager."
            },
            {
                "id": "LNX-UPD-02",
                "priority": "P1 – Critical",
                "description": "Subscribe to distribution security advisories and track critical vulnerabilities."
            },
            {
                "id": "LNX-UPD-03",
                "priority": "P2 – High",
                "description": "Standardize on LTS versions for production systems where possible."
            },
            {
                "id": "LNX-UPD-04",
                "priority": "P2 – High",
                "description": "Test patches on non-production systems before widespread deployment."
            },
            {
                "id": "LNX-UPD-05",
                "priority": "P3 – Medium",
                "description": "Plan and document maintenance windows for patching and reboots."
            }
        ],
        "Logging & Monitoring": [
            {
                "id": "LNX-LOG-01",
                "priority": "P1 – Critical",
                "description": "Enable and retain system logs using `rsyslog`, `journald`, or similar."
            },
            {
                "id": "LNX-LOG-02",
                "priority": "P1 – Critical",
                "description": "Monitor authentication logs (e.g. `/var/log/auth.log`) for suspicious activity."
            },
            {
                "id": "LNX-LOG-03",
                "priority": "P2 – High",
                "description": "Forward logs to a centralized log management or SIEM platform."
            },
            {
                "id": "LNX-LOG-04",
                "priority": "P2 – High",
                "description": "Define alerting rules for critical events (authentication failures, service crashes, etc.)."
            },
            {
                "id": "LNX-LOG-05",
                "priority": "P3 – Medium",
                "description": "Implement monitoring tools (e.g. Prometheus, Zabbix) for availability and performance."
            }
        ],
        "Backup & Recovery": [
            {
                "id": "LNX-BCK-01",
                "priority": "P1 – Critical",
                "description": "Implement automated backups for critical data and configuration files."
            },
            {
                "id": "LNX-BCK-02",
                "priority": "P1 – Critical",
                "description": "Store backups on separate systems or storage with restricted access."
            },
            {
                "id": "LNX-BCK-03",
                "priority": "P2 – High",
                "description": "Regularly test backup restoration and document the procedures."
            },
            {
                "id": "LNX-BCK-04",
                "priority": "P2 – High",
                "description": "Use versioned backups to protect against accidental deletions and corruption."
            },
            {
                "id": "LNX-BCK-05",
                "priority": "P3 – Medium",
                "description": "Encrypt backup data at rest and enforce strict access controls."
            }
        ]
    },
    "webserver": {
        "Accounts & Authentication": [
            {
                "id": "WEB-ACC-01",
                "priority": "P1 – Critical",
                "description": "Use unique, strong credentials for all administrative interfaces."
            },
            {
                "id": "WEB-ACC-02",
                "priority": "P1 – Critical",
                "description": "Restrict access to admin panels by IP range or VPN when possible."
            },
            {
                "id": "WEB-ACC-03",
                "priority": "P2 – High",
                "description": "Use multi-factor authentication (MFA) on hosting, CMS, and admin consoles."
            },
            {
                "id": "WEB-ACC-04",
                "priority": "P2 – High",
                "description": "Avoid default usernames (e.g. 'admin') for administrative accounts."
            },
            {
                "id": "WEB-ACC-05",
                "priority": "P3 – Medium",
                "description": "Apply least-privilege principles to database and application accounts."
            }
        ],
        "System & Application Hardening": [
            {
                "id": "WEB-SYS-01",
                "priority": "P1 – Critical",
                "description": "Keep the web server (e.g. Nginx, Apache) and OS fully patched."
            },
            {
                "id": "WEB-SYS-02",
                "priority": "P1 – Critical",
                "description": "Remove default files, demo applications, and unused modules."
            },
            {
                "id": "WEB-SYS-03",
                "priority": "P2 – High",
                "description": "Run web services under dedicated, unprivileged service accounts."
            },
            {
                "id": "WEB-SYS-04",
                "priority": "P2 – High",
                "description": "Apply vendor-recommended hardening guides and security baselines."
            },
            {
                "id": "WEB-SYS-05",
                "priority": "P3 – Medium",
                "description": "Avoid running unrelated services (mail, file sharing) on the same web server."
            }
        ],
        "Network & TLS": [
            {
                "id": "WEB-TLS-01",
                "priority": "P1 – Critical",
                "description": "Enforce HTTPS for all web traffic and redirect HTTP to HTTPS."
            },
            {
                "id": "WEB-TLS-02",
                "priority": "P1 – Critical",
                "description": "Disable obsolete protocols and weak ciphers in the TLS configuration."
            },
            {
                "id": "WEB-TLS-03",
                "priority": "P2 – High",
                "description": "Implement HSTS (HTTP Strict Transport Security) with appropriate max-age."
            },
            {
                "id": "WEB-TLS-04",
                "priority": "P2 – High",
                "description": "Use certificates from a trusted CA and automate renewals (e.g. Let's Encrypt)."
            },
            {
                "id": "WEB-TLS-05",
                "priority": "P3 – Medium",
                "description": "Restrict direct database and admin access from the internet using firewalls and segmentation."
            }
        ],
        "Web Security Headers": [
            {
                "id": "WEB-HDR-01",
                "priority": "P1 – Critical",
                "description": "Set a strict Content-Security-Policy (CSP) to control allowed content sources."
            },
            {
                "id": "WEB-HDR-02",
                "priority": "P2 – High",
                "description": "Use X-Frame-Options or CSP frame-ancestors to prevent clickjacking."
            },
            {
                "id": "WEB-HDR-03",
                "priority": "P2 – High",
                "description": "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing."
            },
            {
                "id": "WEB-HDR-04",
                "priority": "P3 – Medium",
                "description": "Configure Referrer-Policy to limit referrer information leakage."
            },
            {
                "id": "WEB-HDR-05",
                "priority": "P3 – Medium",
                "description": "Set secure cookies with Secure, HttpOnly, and SameSite attributes."
            }
        ],
        "Application & Data Security": [
            {
                "id": "WEB-APP-01",
                "priority": "P1 – Critical",
                "description": "Validate and sanitize all user inputs on the server side."
            },
            {
                "id": "WEB-APP-02",
                "priority": "P1 – Critical",
                "description": "Use prepared statements/parameterized queries for all database access."
            },
            {
                "id": "WEB-APP-03",
                "priority": "P2 – High",
                "description": "Store passwords using strong, salted hashing algorithms (e.g. bcrypt, Argon2)."
            },
            {
                "id": "WEB-APP-04",
                "priority": "P2 – High",
                "description": "Restrict and validate file uploads (type, size) and scan them for malware where possible."
            },
            {
                "id": "WEB-APP-05",
                "priority": "P3 – Medium",
                "description": "Block direct access to sensitive files, backups, and configuration directories."
            }
        ],
        "Logging, Monitoring & Incident Response": [
            {
                "id": "WEB-LOG-01",
                "priority": "P1 – Critical",
                "description": "Enable detailed access and error logging on the web server."
            },
            {
                "id": "WEB-LOG-02",
                "priority": "P1 – Critical",
                "description": "Forward logs to a centralized log management or SIEM solution."
            },
            {
                "id": "WEB-LOG-03",
                "priority": "P2 – High",
                "description": "Monitor for anomalies such as brute-force attempts, scanning patterns, and unusual HTTP codes."
            },
            {
                "id": "WEB-LOG-04",
                "priority": "P2 – High",
                "description": "Define and document an incident response plan for web application security events."
            },
            {
                "id": "WEB-LOG-05",
                "priority": "P3 – Medium",
                "description": "Regularly review web application and infrastructure logs for signs of compromise."
            }
        ],
        "Backup & Recovery": [
            {
                "id": "WEB-BCK-01",
                "priority": "P1 – Critical",
                "description": "Implement regular backups of web content, configuration, and databases."
            },
            {
                "id": "WEB-BCK-02",
                "priority": "P1 – Critical",
                "description": "Store backups securely, offsite or in a separate environment from production."
            },
            {
                "id": "WEB-BCK-03",
                "priority": "P2 – High",
                "description": "Regularly test restoration of both code and data."
            },
            {
                "id": "WEB-BCK-04",
                "priority": "P2 – High",
                "description": "Version-control application code and configuration where possible."
            },
            {
                "id": "WEB-BCK-05",
                "priority": "P3 – Medium",
                "description": "Document recovery procedures for the web server, database, and DNS components."
            }
        ]
    },
    "cloud": {
        "Identity & Access Management": [
            {
                "id": "CLD-IAM-01",
                "priority": "P1 – Critical",
                "description": "Enforce phishing-resistant MFA for every console user, and always for root / global administrator accounts."
            },
            {
                "id": "CLD-IAM-02",
                "priority": "P1 – Critical",
                "description": "Lock down root and break-glass accounts: no access keys, hardware MFA, sealed credentials and alerting on any use."
            },
            {
                "id": "CLD-IAM-03",
                "priority": "P2 – High",
                "description": "Apply least privilege with role-based access; forbid wildcard actions and resources on production roles."
            },
            {
                "id": "CLD-IAM-04",
                "priority": "P2 – High",
                "description": "Replace long-lived access keys with workload identities and short-lived federated credentials."
            },
            {
                "id": "CLD-IAM-05",
                "priority": "P3 – Medium",
                "description": "Review cloud roles and permissions quarterly and remove unused permissions and identities."
            }
        ],
        "Network & Exposure": [
            {
                "id": "CLD-NET-01",
                "priority": "P1 – Critical",
                "description": "Never expose management ports (SSH, RDP, database ports) directly to the internet; use a bastion or zero-trust access."
            },
            {
                "id": "CLD-NET-02",
                "priority": "P1 – Critical",
                "description": "Block public access to object storage at organization level; allow exceptions only through documented approval."
            },
            {
                "id": "CLD-NET-03",
                "priority": "P2 – High",
                "description": "Segment workloads in dedicated VPCs/VNets with default-deny security groups and explicit flows."
            },
            {
                "id": "CLD-NET-04",
                "priority": "P2 – High",
                "description": "Use private endpoints for managed services (databases, storage, key vaults) instead of public endpoints."
            },
            {
                "id": "CLD-NET-05",
                "priority": "P3 – Medium",
                "description": "Protect internet-facing applications with a WAF and DDoS protection service."
            }
        ],
        "Logging & Threat Detection": [
            {
                "id": "CLD-LOG-01",
                "priority": "P1 – Critical",
                "description": "Enable control-plane audit logging in every account, subscription and region, stored immutably."
            },
            {
                "id": "CLD-LOG-02",
                "priority": "P1 – Critical",
                "description": "Centralize security logs in a dedicated, access-restricted security account or workspace."
            },
            {
                "id": "CLD-LOG-03",
                "priority": "P2 – High",
                "description": "Enable the provider's native threat-detection services and route findings to the SOC / SIEM."
            },
            {
                "id": "CLD-LOG-04",
                "priority": "P2 – High",
                "description": "Alert on high-risk events: root usage, policy changes, disabled logging, new public exposure."
            },
            {
                "id": "CLD-LOG-05",
                "priority": "P3 – Medium",
                "description": "Define log retention aligned with regulatory and forensic requirements (e.g. NIS2, DORA)."
            }
        ],
        "Data Protection & Resilience": [
            {
                "id": "CLD-DAT-01",
                "priority": "P1 – Critical",
                "description": "Encrypt sensitive data at rest and enforce TLS 1.2+ for all data in transit."
            },
            {
                "id": "CLD-DAT-02",
                "priority": "P1 – Critical",
                "description": "Keep backups of critical workloads in a separate account with immutability (object lock / vault lock)."
            },
            {
                "id": "CLD-DAT-03",
                "priority": "P2 – High",
                "description": "Use customer-managed keys with rotation and separation of duties for regulated data."
            },
            {
                "id": "CLD-DAT-04",
                "priority": "P2 – High",
                "description": "Test restoration and regional failover of critical services against documented RTO/RPO."
            },
            {
                "id": "CLD-DAT-05",
                "priority": "P3 – Medium",
                "description": "Tag resources with data classification so that controls can be applied by sensitivity."
            }
        ],
        "Cloud Governance & Posture": [
            {
                "id": "CLD-GOV-01",
                "priority": "P1 – Critical",
                "description": "Apply organization-level guardrails (policies / SCPs) that prevent disabling logging or using unapproved regions."
            },
            {
                "id": "CLD-GOV-02",
                "priority": "P2 – High",
                "description": "Run continuous posture management (CSPM) against CIS Benchmarks and track deviations to closure."
            },
            {
                "id": "CLD-GOV-03",
                "priority": "P2 – High",
                "description": "Deploy infrastructure as code with security scanning in CI/CD; block manual changes in production."
            },
            {
                "id": "CLD-GOV-04",
                "priority": "P3 – Medium",
                "description": "Tag every resource with owner, environment, cost centre and business criticality."
            },
            {
                "id": "CLD-GOV-05",
                "priority": "P3 – Medium",
                "description": "Document an exit strategy and concentration-risk assessment for critical cloud providers."
            }
        ]
    },
    "active_directory": {
        "Tiering & Privileged Access": [
            {
                "id": "AD-PRV-01",
                "priority": "P1 – Critical",
                "description": "Implement an administrative tiering model (Tier 0 / 1 / 2) and prevent Tier 0 credentials from touching lower tiers."
            },
            {
                "id": "AD-PRV-02",
                "priority": "P1 – Critical",
                "description": "Reduce Domain Admins, Enterprise Admins and Schema Admins to a minimal, named membership with no daily use."
            },
            {
                "id": "AD-PRV-03",
                "priority": "P1 – Critical",
                "description": "Administer Tier 0 only from dedicated privileged access workstations (PAW)."
            },
            {
                "id": "AD-PRV-04",
                "priority": "P2 – High",
                "description": "Place privileged accounts in Protected Users and mark them 'sensitive and cannot be delegated'."
            },
            {
                "id": "AD-PRV-05",
                "priority": "P3 – Medium",
                "description": "Grant privileged group membership just-in-time with automatic expiry."
            }
        ],
        "Credential Protection": [
            {
                "id": "AD-CRD-01",
                "priority": "P1 – Critical",
                "description": "Deploy Windows LAPS so that every machine has a unique, rotated local administrator password."
            },
            {
                "id": "AD-CRD-02",
                "priority": "P1 – Critical",
                "description": "Rotate the krbtgt account password (twice) periodically and immediately after a suspected compromise."
            },
            {
                "id": "AD-CRD-03",
                "priority": "P2 – High",
                "description": "Enable Credential Guard and LSA protection on workstations and servers."
            },
            {
                "id": "AD-CRD-04",
                "priority": "P2 – High",
                "description": "Disable LM and NTLMv1, audit NTLM usage and progressively restrict NTLM."
            },
            {
                "id": "AD-CRD-05",
                "priority": "P3 – Medium",
                "description": "Apply fine-grained password policies with stronger requirements for privileged and service accounts."
            }
        ],
        "Service Accounts & Kerberos": [
            {
                "id": "AD-SVC-01",
                "priority": "P1 – Critical",
                "description": "Use group Managed Service Accounts (gMSA) wherever the application supports them."
            },
            {
                "id": "AD-SVC-02",
                "priority": "P1 – Critical",
                "description": "Give accounts with an SPN long random passwords (25+ characters) to defeat Kerberoasting."
            },
            {
                "id": "AD-SVC-03",
                "priority": "P2 – High",
                "description": "Enforce AES encryption for Kerberos and remove RC4 where compatibility allows."
            },
            {
                "id": "AD-SVC-04",
                "priority": "P2 – High",
                "description": "Remove unconstrained delegation; use constrained or resource-based constrained delegation instead."
            },
            {
                "id": "AD-SVC-05",
                "priority": "P3 – Medium",
                "description": "Maintain an inventory of service accounts with a named owner and recertification date."
            }
        ],
        "Directory Hygiene & Configuration": [
            {
                "id": "AD-HYG-01",
                "priority": "P1 – Critical",
                "description": "Disable and then remove inactive user and computer accounts on a defined schedule."
            },
            {
                "id": "AD-HYG-02",
                "priority": "P1 – Critical",
                "description": "Patch domain controllers promptly and keep them dedicated (no additional roles or software)."
            },
            {
                "id": "AD-HYG-03",
                "priority": "P2 – High",
                "description": "Analyse attack paths and dangerous ACLs on sensitive objects (AdminSDHolder, domain root, GPOs)."
            },
            {
                "id": "AD-HYG-04",
                "priority": "P2 – High",
                "description": "Ensure no credentials are stored in Group Policy Preferences or scripts in SYSVOL."
            },
            {
                "id": "AD-HYG-05",
                "priority": "P3 – Medium",
                "description": "Raise domain and forest functional levels to benefit from current security features."
            }
        ],
        "Monitoring & Forest Recovery": [
            {
                "id": "AD-MON-01",
                "priority": "P1 – Critical",
                "description": "Forward domain controller security logs to the SIEM with adequate audit policy coverage."
            },
            {
                "id": "AD-MON-02",
                "priority": "P1 – Critical",
                "description": "Alert on any change to privileged groups, GPOs linked to domain controllers and AdminSDHolder."
            },
            {
                "id": "AD-MON-03",
                "priority": "P2 – High",
                "description": "Detect DCSync, Kerberoasting, AS-REP roasting and forged-ticket indicators."
            },
            {
                "id": "AD-MON-04",
                "priority": "P2 – High",
                "description": "Keep offline, tested backups and a documented procedure for full AD forest recovery."
            },
            {
                "id": "AD-MON-05",
                "priority": "P3 – Medium",
                "description": "Run a periodic AD security assessment and track the resulting score over time."
            }
        ]
    }
}


class DomainMeta(TypedDict):
    iso27001: List[str]
    cis_v8: List[str]
    nist_csf: List[str]
    owner: str


# Framework references at domain level. ISO/IEC 27001:2022 Annex A, CIS Controls v8
# (top-level control numbers) and NIST CSF 2.0 functions. Indicative, not a certification mapping.
DOMAIN_METADATA: Dict[str, DomainMeta] = {
    "Accounts & Authentication": {"iso27001": ["A.5.15", "A.5.17", "A.8.5"], "cis_v8": ["5", "6"], "nist_csf": ["PR"], "owner": "IAM / IT Operations"},
    "Identity & Access Management": {"iso27001": ["A.5.15", "A.5.18", "A.8.2", "A.8.5"], "cis_v8": ["5", "6"], "nist_csf": ["PR"], "owner": "Cloud Platform / IAM"},
    "Tiering & Privileged Access": {"iso27001": ["A.8.2", "A.5.15"], "cis_v8": ["5", "6"], "nist_csf": ["PR"], "owner": "Identity / Tier 0 administrators"},
    "Credential Protection": {"iso27001": ["A.5.17", "A.8.5"], "cis_v8": ["5", "6"], "nist_csf": ["PR"], "owner": "Identity / Endpoint team"},
    "Service Accounts & Kerberos": {"iso27001": ["A.5.16", "A.5.17", "A.8.2"], "cis_v8": ["5"], "nist_csf": ["PR"], "owner": "Identity team"},
    "System Hardening": {"iso27001": ["A.8.9", "A.8.19", "A.8.7"], "cis_v8": ["4", "10"], "nist_csf": ["PR"], "owner": "IT Operations"},
    "System & Application Hardening": {"iso27001": ["A.8.9", "A.8.26"], "cis_v8": ["4", "16"], "nist_csf": ["PR"], "owner": "Web Operations / AppSec"},
    "Directory Hygiene & Configuration": {"iso27001": ["A.8.9", "A.5.18", "A.8.8"], "cis_v8": ["4", "5", "7"], "nist_csf": ["PR", "ID"], "owner": "Identity team"},
    "Network & Firewall": {"iso27001": ["A.8.20", "A.8.22"], "cis_v8": ["4", "12", "13"], "nist_csf": ["PR"], "owner": "Network team"},
    "Network & TLS": {"iso27001": ["A.8.20", "A.8.24"], "cis_v8": ["3", "12"], "nist_csf": ["PR"], "owner": "Network / Web Operations"},
    "Network & Exposure": {"iso27001": ["A.8.20", "A.8.22"], "cis_v8": ["4", "12", "13"], "nist_csf": ["PR"], "owner": "Cloud Platform / Network"},
    "Web Security Headers": {"iso27001": ["A.8.26", "A.8.28"], "cis_v8": ["16"], "nist_csf": ["PR"], "owner": "AppSec / Development"},
    "Application & Data Security": {"iso27001": ["A.8.26", "A.8.28", "A.8.12"], "cis_v8": ["3", "16"], "nist_csf": ["PR"], "owner": "AppSec / Development"},
    "Data Protection & Resilience": {"iso27001": ["A.8.24", "A.8.13", "A.5.30"], "cis_v8": ["3", "11"], "nist_csf": ["PR", "RC"], "owner": "Cloud Platform / Data owners"},
    "Updates & Patch Management": {"iso27001": ["A.8.8", "A.8.19"], "cis_v8": ["7"], "nist_csf": ["ID", "PR"], "owner": "IT Operations"},
    "Logging & Monitoring": {"iso27001": ["A.8.15", "A.8.16"], "cis_v8": ["8", "13"], "nist_csf": ["DE"], "owner": "SOC / SecOps"},
    "Logging & Threat Detection": {"iso27001": ["A.8.15", "A.8.16", "A.5.23"], "cis_v8": ["8", "13"], "nist_csf": ["DE"], "owner": "SOC / Cloud Security"},
    "Logging, Monitoring & Incident Response": {"iso27001": ["A.8.15", "A.8.16", "A.5.24"], "cis_v8": ["8", "17"], "nist_csf": ["DE", "RS"], "owner": "SOC / SecOps"},
    "Monitoring & Forest Recovery": {"iso27001": ["A.8.15", "A.8.16", "A.8.13", "A.5.30"], "cis_v8": ["8", "11", "17"], "nist_csf": ["DE", "RC"], "owner": "SOC / Identity team"},
    "Backup & Recovery": {"iso27001": ["A.8.13", "A.5.30"], "cis_v8": ["11"], "nist_csf": ["RC"], "owner": "IT Operations / BCP"},
    "Cloud Governance & Posture": {"iso27001": ["A.5.23", "A.8.9", "A.5.19"], "cis_v8": ["1", "4", "15"], "nist_csf": ["GV", "ID"], "owner": "Cloud CoE / CISO"},
}

ISO27001_TITLES: Dict[str, str] = {
    "A.5.15": "Access control", "A.5.16": "Identity management", "A.5.17": "Authentication information",
    "A.5.18": "Access rights", "A.5.19": "Information security in supplier relationships",
    "A.5.23": "Information security for use of cloud services", "A.5.24": "Incident management planning and preparation",
    "A.5.30": "ICT readiness for business continuity", "A.8.2": "Privileged access rights",
    "A.8.5": "Secure authentication", "A.8.7": "Protection against malware",
    "A.8.8": "Management of technical vulnerabilities", "A.8.9": "Configuration management",
    "A.8.12": "Data leakage prevention", "A.8.13": "Information backup", "A.8.15": "Logging",
    "A.8.16": "Monitoring activities", "A.8.19": "Installation of software on operational systems",
    "A.8.20": "Networks security", "A.8.22": "Segregation of networks", "A.8.24": "Use of cryptography",
    "A.8.26": "Application security requirements", "A.8.28": "Secure coding",
}

NIST_CSF_FUNCTIONS: Dict[str, str] = {
    "GV": "Govern", "ID": "Identify", "PR": "Protect", "DE": "Detect", "RS": "Respond", "RC": "Recover",
}
