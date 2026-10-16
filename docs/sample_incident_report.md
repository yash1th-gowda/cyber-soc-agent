# Incident Report: INC-92DADA

**Possible Multi-Stage Incident: Valid Account (Possible Compromise) -> PowerShell Execution -> Privilege Escalation -> External Connection**

- **Severity:** CRITICAL
- **Confidence:** 84%
- **Risk Score:** 92/100
- **Status:** investigating
- **Generated:** 2026-10-07T18:10:30.777249+00:00

## Executive Summary
Possible Multi-Stage Incident: Valid Account (Possible Compromise) -> PowerShell Execution -> Privilege Escalation -> External Connection. Involves account(s) admin01; source IP(s) 10.0.5.20, 185.220.101.45; host(s) WS-104. Detections triggered: POSSIBLE_CREDENTIAL_COMPROMISE, PRIVILEGE_ESCALATION, SUSPICIOUS_EXTERNAL_CONNECTION, SUSPICIOUS_POWERSHELL. Based on 9 correlated event(s) across 5 alert(s).

## Affected Entities
- **source_ip:** 10.0.5.20, 185.220.101.45
- **username:** admin01
- **hostname:** WS-104

## Timeline
- `2026-10-01T03:11:00` Failed authentication for admin01 (evidence: `cc_evt_001`)
- `2026-10-01T03:11:40` Failed authentication for admin01 (evidence: `cc_evt_002`)
- `2026-10-01T03:12:20` Failed authentication for admin01 (evidence: `cc_evt_003`)
- `2026-10-01T03:13:00` Failed authentication for admin01 (evidence: `cc_evt_004`)
- `2026-10-01T03:14:00` Successful authentication for admin01 (evidence: `cc_evt_005`)
- `2026-10-01T03:15:00` PowerShell process created with encoded command (evidence: `cc_evt_006`)
- `2026-10-01T03:16:00` admin01 added to local Administrators group (evidence: `cc_evt_007`)
- `2026-10-01T03:18:00` Outbound connection from WS-104 to 91.219.237.14 (evidence: `cc_evt_008`)
- `2026-10-01T03:19:00` Large outbound transfer from WS-104 to 91.219.237.14 (evidence: `cc_evt_009`)

## Attack Chain
Valid Account (Possible Compromise) -> PowerShell Execution -> Privilege Escalation -> External Connection

## MITRE ATT&CK Mapping
| Technique | Name | Status | Confidence | Evidence |
|---|---|---|---|---|
| T1078 | Valid Accounts | confirmed | 0.88 | cc_evt_001, cc_evt_002, cc_evt_003, cc_evt_004, cc_evt_005 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | confirmed | 0.75 | cc_evt_006 |
| T1098 | Account Manipulation | confirmed | 0.80 | cc_evt_007 |
| T1041 | Exfiltration Over C2 Channel | confirmed | 0.95 | cc_evt_006, cc_evt_008, cc_evt_009 |

## Evidence
cc_evt_001, cc_evt_002, cc_evt_003, cc_evt_004, cc_evt_005, cc_evt_006, cc_evt_007, cc_evt_008, cc_evt_009

## AI Investigation
**Attack sequence:**

Attack chain: Valid Account (Possible Compromise) -> PowerShell Execution -> Privilege Escalation -> External Connection

Timeline:
2026-10-01T03:11:00  Failed authentication for admin01 (evidence: cc_evt_001)
2026-10-01T03:11:40  Failed authentication for admin01 (evidence: cc_evt_002)
2026-10-01T03:12:20  Failed authentication for admin01 (evidence: cc_evt_003)
2026-10-01T03:13:00  Failed authentication for admin01 (evidence: cc_evt_004)
2026-10-01T03:14:00  Successful authentication for admin01 (evidence: cc_evt_005)
2026-10-01T03:15:00  PowerShell process created with encoded command (evidence: cc_evt_006)
2026-10-01T03:16:00  admin01 added to local Administrators group (evidence: cc_evt_007)
2026-10-01T03:18:00  Outbound connection from WS-104 to 91.219.237.14 (evidence: cc_evt_008)
2026-10-01T03:19:00  Large outbound transfer from WS-104 to 91.219.237.14 (evidence: cc_evt_009)

**Severity explanation:** Severity is 'critical' with confidence 0.84, derived from the highest-severity contributing rule and 9 corroborating event(s). MITRE ATT&CK techniques: T1078 (confirmed), T1059.001 (confirmed), T1098 (confirmed), T1041 (confirmed).

**Alternative explanation (could this be benign?):** This pattern could also be legitimate -- e.g. a user retrying a forgotten password, or an administrator running PowerShell / accessing several hosts during maintenance. The evidence does not by itself rule this out; confirm with the account owner or a change record before any containment.

**Missing evidence / uncertainty:**
- No specific evidence gaps identified beyond standard analyst verification.

**Recommended next investigation steps:**
- Review the full event evidence list before taking action.
- Confirm with account owner(s) admin01 whether the activity was authorized.
- Pull endpoint telemetry for host(s) WS-104.
- Check reputation/geolocation of source IP(s) 10.0.5.20, 185.220.101.45.
- Check whether these entities appear in any other open incident.

## Recommended Actions
| Priority | Action | Reason | Evidence |
|---|---|---|---|
| P1 | Temporarily disable the affected account pending verification | Triggered by rule POSSIBLE_CREDENTIAL_COMPROMISE (possible_credential_compromise). | cc_evt_001, cc_evt_002, cc_evt_003, cc_evt_004, cc_evt_005 |
| P1 | Revoke active sessions for the affected account | Triggered by rule POSSIBLE_CREDENTIAL_COMPROMISE (possible_credential_compromise). | cc_evt_001, cc_evt_002, cc_evt_003, cc_evt_004, cc_evt_005 |
| P1 | Review and, if unauthorized, revert the privileged group membership change | Triggered by rule PRIVILEGE_ESCALATION (privilege_escalation). | cc_evt_007 |
| P1 | Block the destination IP/domain at the firewall | Triggered by rule SUSPICIOUS_EXTERNAL_CONNECTION (suspicious_external_connection). | cc_evt_008, cc_evt_006 |
| P2 | Force credential rotation for the affected account | Triggered by rule POSSIBLE_CREDENTIAL_COMPROMISE (possible_credential_compromise). | cc_evt_001, cc_evt_002, cc_evt_003, cc_evt_004, cc_evt_005 |
| P2 | Terminate the suspicious process if still running | Triggered by rule SUSPICIOUS_POWERSHELL (suspicious_powershell_execution). | cc_evt_006 |
| P2 | Audit recent privileged-group changes for the affected domain/host | Triggered by rule PRIVILEGE_ESCALATION (privilege_escalation). | cc_evt_007 |
| P2 | Review outbound proxy logs for additional connections to the same destination | Triggered by rule SUSPICIOUS_EXTERNAL_CONNECTION (suspicious_external_connection). | cc_evt_008, cc_evt_006 |
| P3 | Review PowerShell execution policy / enable constrained language mode | Triggered by rule SUSPICIOUS_POWERSHELL (suspicious_powershell_execution). | cc_evt_006 |

## Response Simulation
- **DISABLE_USER** on `admin01` -- status: simulated, decided by analyst_final. SIMULATED: account(s) admin01 flagged as disabled. No real identity-provider change performed.

---
_Generated by CYBER-SOC AGENT. AI narrative sections are evidence-grounded summaries of the structured data above, not independent findings. All response actions are SIMULATED._