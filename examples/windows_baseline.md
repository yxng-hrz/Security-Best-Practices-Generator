# Security Baseline – Windows workstations & servers

**Organization:** ACME Corp  
**Generated:** 2026-11-16 — Security Best Practices Generator v2.0.0  
**Controls:** 30 (P1: 12, P2: 12, P3: 6)

> Priorities: **P1** = must-have baseline, **P2** = short-term, **P3** = improvement. Framework references are indicative (domain level).

## 1. Accounts & Authentication

*Owner: IAM / IT Operations — ISO 27001 A.5.15, A.5.17, A.8.5 | CIS v8 5, 6 | NIST CSF PR*

1. **WIN-ACC-01** `[P1 – Critical]` Enforce strong password policies (length, complexity, history, expiration).
2. **WIN-ACC-02** `[P1 – Critical]` Enable account lockout policies after multiple failed login attempts.
3. **WIN-ACC-03** `[P2 – High]` Use multi-factor authentication (MFA) for privileged and remote access.
4. **WIN-ACC-04** `[P2 – High]` Regularly review local users and groups and remove or disable unused accounts.
5. **WIN-ACC-05** `[P3 – Medium]` Rename or disable the default local Administrator account when possible.

## 2. System Hardening

*Owner: IT Operations — ISO 27001 A.8.9, A.8.19, A.8.7 | CIS v8 4, 10 | NIST CSF PR*

1. **WIN-SYS-01** `[P1 – Critical]` Remove or disable unused software, services, and legacy components.
2. **WIN-SYS-02** `[P1 – Critical]` Restrict local administrator rights and use standard accounts for daily work.
3. **WIN-SYS-03** `[P2 – High]` Enable full-disk encryption (e.g. BitLocker) on laptops and sensitive workstations.
4. **WIN-SYS-04** `[P2 – High]` Configure automatic screen lock with a short inactivity timeout and password on resume.
5. **WIN-SYS-05** `[P3 – Medium]` Harden PowerShell usage and enable detailed PowerShell logging for administrative actions.

## 3. Network & Firewall

*Owner: Network team — ISO 27001 A.8.20, A.8.22 | CIS v8 4, 12, 13 | NIST CSF PR*

1. **WIN-NET-01** `[P1 – Critical]` Enable and configure Windows Defender Firewall with restrictive inbound rules.
2. **WIN-NET-02** `[P1 – Critical]` Block inbound traffic by default and only allow required ports and applications.
3. **WIN-NET-03** `[P2 – High]` Disable legacy and insecure network protocols (e.g. SMBv1).
4. **WIN-NET-04** `[P2 – High]` Use VPN with strong encryption for remote access to internal resources.
5. **WIN-NET-05** `[P3 – Medium]` Segment networks (workstations, servers, guests) using VLANs and ACLs.

## 4. Updates & Patch Management

*Owner: IT Operations — ISO 27001 A.8.8, A.8.19 | CIS v8 7 | NIST CSF ID, PR*

1. **WIN-UPD-01** `[P1 – Critical]` Enable automatic Windows Updates or manage updates centrally (e.g. WSUS/SCCM).
2. **WIN-UPD-02** `[P1 – Critical]` Apply critical security patches in a timely manner on all workstations and servers.
3. **WIN-UPD-03** `[P2 – High]` Regularly patch third-party applications (browsers, Java, PDF readers, etc.).
4. **WIN-UPD-04** `[P2 – High]` Define and document a patch management process including testing and rollback.
5. **WIN-UPD-05** `[P3 – Medium]` Schedule maintenance windows to limit business impact of updates and reboots.

## 5. Logging & Monitoring

*Owner: SOC / SecOps — ISO 27001 A.8.15, A.8.16 | CIS v8 8, 13 | NIST CSF DE*

1. **WIN-LOG-01** `[P1 – Critical]` Enable advanced audit policies (logon events, privilege use, object access).
2. **WIN-LOG-02** `[P1 – Critical]` Forward security logs to a central logging or SIEM solution for correlation.
3. **WIN-LOG-03** `[P2 – High]` Monitor failed logons, privilege escalations, and suspicious account behavior.
4. **WIN-LOG-04** `[P2 – High]` Regularly review antivirus and endpoint protection logs for detected threats.
5. **WIN-LOG-05** `[P3 – Medium]` Define alert thresholds and incident handling procedures for key security events.

## 6. Backup & Recovery

*Owner: IT Operations / BCP — ISO 27001 A.8.13, A.5.30 | CIS v8 11 | NIST CSF RC*

1. **WIN-BCK-01** `[P1 – Critical]` Implement regular backups of critical data and system configurations.
2. **WIN-BCK-02** `[P1 – Critical]` Store backups in a separate location and protect them from direct access and ransomware.
3. **WIN-BCK-03** `[P2 – High]` Test backup restoration procedures regularly and document the results.
4. **WIN-BCK-04** `[P2 – High]` Ensure encryption keys and BitLocker recovery keys are securely stored.
5. **WIN-BCK-05** `[P3 – Medium]` Define RPO/RTO objectives and verify that backup frequency and retention meet them.
