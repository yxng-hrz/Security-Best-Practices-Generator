# Security Baseline – Active Directory

**Organization:** n/a  
**Generated:** 2026-11-16 — Security Best Practices Generator v2.0.0  
**Controls:** 25 (P1: 11, P2: 9, P3: 5)

## 1. Tiering & Privileged Access

*Owner: Identity / Tier 0 administrators — ISO 27001 A.8.2, A.5.15 | CIS v8 5, 6 | NIST CSF PR*

- [ ] **AD-PRV-01** `P1` Implement an administrative tiering model (Tier 0 / 1 / 2) and prevent Tier 0 credentials from touching lower tiers.
- [ ] **AD-PRV-02** `P1` Reduce Domain Admins, Enterprise Admins and Schema Admins to a minimal, named membership with no daily use.
- [ ] **AD-PRV-03** `P1` Administer Tier 0 only from dedicated privileged access workstations (PAW).
- [ ] **AD-PRV-04** `P2` Place privileged accounts in Protected Users and mark them 'sensitive and cannot be delegated'.
- [ ] **AD-PRV-05** `P3` Grant privileged group membership just-in-time with automatic expiry.

## 2. Credential Protection

*Owner: Identity / Endpoint team — ISO 27001 A.5.17, A.8.5 | CIS v8 5, 6 | NIST CSF PR*

- [ ] **AD-CRD-01** `P1` Deploy Windows LAPS so that every machine has a unique, rotated local administrator password.
- [ ] **AD-CRD-02** `P1` Rotate the krbtgt account password (twice) periodically and immediately after a suspected compromise.
- [ ] **AD-CRD-03** `P2` Enable Credential Guard and LSA protection on workstations and servers.
- [ ] **AD-CRD-04** `P2` Disable LM and NTLMv1, audit NTLM usage and progressively restrict NTLM.
- [ ] **AD-CRD-05** `P3` Apply fine-grained password policies with stronger requirements for privileged and service accounts.

## 3. Service Accounts & Kerberos

*Owner: Identity team — ISO 27001 A.5.16, A.5.17, A.8.2 | CIS v8 5 | NIST CSF PR*

- [ ] **AD-SVC-01** `P1` Use group Managed Service Accounts (gMSA) wherever the application supports them.
- [ ] **AD-SVC-02** `P1` Give accounts with an SPN long random passwords (25+ characters) to defeat Kerberoasting.
- [ ] **AD-SVC-03** `P2` Enforce AES encryption for Kerberos and remove RC4 where compatibility allows.
- [ ] **AD-SVC-04** `P2` Remove unconstrained delegation; use constrained or resource-based constrained delegation instead.
- [ ] **AD-SVC-05** `P3` Maintain an inventory of service accounts with a named owner and recertification date.

## 4. Directory Hygiene & Configuration

*Owner: Identity team — ISO 27001 A.8.9, A.5.18, A.8.8 | CIS v8 4, 5, 7 | NIST CSF PR, ID*

- [ ] **AD-HYG-01** `P1` Disable and then remove inactive user and computer accounts on a defined schedule.
- [ ] **AD-HYG-02** `P1` Patch domain controllers promptly and keep them dedicated (no additional roles or software).
- [ ] **AD-HYG-03** `P2` Analyse attack paths and dangerous ACLs on sensitive objects (AdminSDHolder, domain root, GPOs).
- [ ] **AD-HYG-04** `P2` Ensure no credentials are stored in Group Policy Preferences or scripts in SYSVOL.
- [ ] **AD-HYG-05** `P3` Raise domain and forest functional levels to benefit from current security features.

## 5. Monitoring & Forest Recovery

*Owner: SOC / Identity team — ISO 27001 A.8.15, A.8.16, A.8.13, A.5.30 | CIS v8 8, 11, 17 | NIST CSF DE, RC*

- [ ] **AD-MON-01** `P1` Forward domain controller security logs to the SIEM with adequate audit policy coverage.
- [ ] **AD-MON-02** `P1` Alert on any change to privileged groups, GPOs linked to domain controllers and AdminSDHolder.
- [ ] **AD-MON-03** `P2` Detect DCSync, Kerberoasting, AS-REP roasting and forged-ticket indicators.
- [ ] **AD-MON-04** `P2` Keep offline, tested backups and a documented procedure for full AD forest recovery.
- [ ] **AD-MON-05** `P3` Run a periodic AD security assessment and track the resulting score over time.
