# Security Maturity Assessment — ACME Corp

**Scope:** Active Directory  
**Date:** 2026-11-16  
**Assessed by:** RSSI - ACME Corp  

## 1. Executive summary

- **Overall score:** 53% — maturity **2 - Developing**
- **Critical gaps (P1 not implemented):** 3
- **Status:** implemented 8, partial 8, not implemented 8, not applicable 1
- **Weakest domains:** Service Accounts & Kerberos (36%), Tiering & Privileged Access (46%), Monitoring & Forest Recovery (50%)

## 2. Maturity by domain

| Domain | Owner | Score | Maturity | Gaps |
|---|---|---:|---|---:|
| Service Accounts & Kerberos | Identity team | 36% | 1 - Initial | 4 |
| Tiering & Privileged Access | Identity / Tier 0 administrators | 46% | 2 - Developing | 4 |
| Monitoring & Forest Recovery | SOC / Identity team | 50% | 2 - Developing | 4 |
| Credential Protection | Identity / Endpoint team | 54% | 2 - Developing | 3 |
| Directory Hygiene & Configuration | Identity team | 80% | 4 - Managed | 1 |

## 3. NIST CSF 2.0 view

| Function | Score |
|---|---:|
| ID - Identify | 80% |
| PR - Protect | 53% |
| DE - Detect | 50% |
| RC - Recover | 50% |

## 4. ISO/IEC 27001:2022 Annex A — weakest controls

| Control | Title | Score |
|---|---|---:|
| A.5.16 | Identity management | 36% |
| A.8.2 | Privileged access rights | 41% |
| A.5.17 | Authentication information | 46% |
| A.5.15 | Access control | 46% |
| A.5.30 | ICT readiness for business continuity | 50% |
| A.8.13 | Information backup | 50% |
| A.8.15 | Logging | 50% |
| A.8.16 | Monitoring activities | 50% |

## 5. Remediation roadmap

### 0-30 days (6)

- [ ] **AD-CRD-02** — Rotate the krbtgt account password (twice) periodically and immediately after a suspected compromise. — _owner: Identity / Endpoint team_
- [ ] **AD-PRV-03** — Administer Tier 0 only from dedicated privileged access workstations (PAW). — _owner: Identity / Tier 0 administrators_
- [ ] **AD-SVC-02** — Give accounts with an SPN long random passwords (25+ characters) to defeat Kerberoasting. — _owner: Identity team_
- [ ] **AD-MON-02** — Alert on any change to privileged groups, GPOs linked to domain controllers and AdminSDHolder. *(partial)* — _owner: SOC / Identity team_
- [ ] **AD-PRV-01** — Implement an administrative tiering model (Tier 0 / 1 / 2) and prevent Tier 0 credentials from touching lower tiers. *(partial)* — _owner: Identity / Tier 0 administrators_
- [ ] **AD-SVC-01** — Use group Managed Service Accounts (gMSA) wherever the application supports them. *(partial)* — _owner: Identity team_

### 31-90 days (7)

- [ ] **AD-HYG-03** — Analyse attack paths and dangerous ACLs on sensitive objects (AdminSDHolder, domain root, GPOs). — _owner: Identity team_
- [ ] **AD-MON-03** — Detect DCSync, Kerberoasting, AS-REP roasting and forged-ticket indicators. — _owner: SOC / Identity team_
- [ ] **AD-SVC-04** — Remove unconstrained delegation; use constrained or resource-based constrained delegation instead. — _owner: Identity team_
- [ ] **AD-CRD-03** — Enable Credential Guard and LSA protection on workstations and servers. *(partial)* — _owner: Identity / Endpoint team_
- [ ] **AD-CRD-04** — Disable LM and NTLMv1, audit NTLM usage and progressively restrict NTLM. *(partial)* — _owner: Identity / Endpoint team_
- [ ] **AD-MON-04** — Keep offline, tested backups and a documented procedure for full AD forest recovery. *(partial)* — _owner: SOC / Identity team_
- [ ] **AD-PRV-04** — Place privileged accounts in Protected Users and mark them 'sensitive and cannot be delegated'. *(partial)* — _owner: Identity / Tier 0 administrators_

### 91-180 days (3)

- [ ] **AD-MON-05** — Run a periodic AD security assessment and track the resulting score over time. — _owner: SOC / Identity team_
- [ ] **AD-PRV-05** — Grant privileged group membership just-in-time with automatic expiry. — _owner: Identity / Tier 0 administrators_
- [ ] **AD-SVC-05** — Maintain an inventory of service accounts with a named owner and recertification date. *(partial)* — _owner: Identity team_

---
_Score = priority-weighted coverage (P1×3, P2×2, P3×1; partial = 50%). Indicative self-assessment, not an audit opinion._
