# MITRE ATT&CK mapping (cross-incident)

Standalone copy of table 4.3 from the [Month 1 Assessment Report](../reports/INC-2026-003_Findings_Report.md), mapping observed techniques across INC-2026-001, INC-2026-002, and INC-2026-003. Framework: MITRE ATT&CK Enterprise v15.

A mark in an incident column means the technique was observed in that incident's evidence. The recurrence of certain techniques across incidents is one of the signals supporting single-actor attribution (see the recurrence note below).

| Tactic | Technique | ID | INC-001 | INC-002 | INC-003 |
|---|---|---|:--:|:--:|:--:|
| Reconnaissance | Active Scanning: Vulnerability Scanning | T1595.002 | x | x | |
| Initial Access | Exploit Public-Facing Application | T1190 | x | | |
| Initial Access | External Remote Services | T1133 | x | x | |
| Initial Access | Valid Accounts: Local Accounts | T1078.003 | x | x | |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | x | | |
| Persistence | Create Account: Local Account | T1136.001 | | x | x |
| Persistence | Scheduled Task/Job: Cron | T1053.003 | | x | x |
| Persistence | Systemd Service (suspected) | T1543.002 | x | | |
| Privilege Escalation | Abuse Elevation Control: Setuid and Setgid | T1548.001 | | x | |
| Privilege Escalation | Abuse Elevation Control: Sudo and Sudo Caching | T1548.003 | x (suspected) | | x |
| Credential Access | Unsecured Credentials: Private Keys | T1552.004 | | x | x |
| Credential Access | Credentials In Files | T1552.001 | | | x |
| Credential Access | OS Credential Dumping: /etc/passwd and /etc/shadow | T1003.008 | | x | |
| Credential Access | Brute Force / Password Guessing | T1110, T1110.001 | x | x | |
| Discovery | File and Directory Discovery | T1083 | x | x | x |
| Discovery | System and Network Discovery (multiple) | see note | x | x | |
| Lateral Movement | Remote Services: SSH | T1021.004 | | | x |
| Command and Control | Application Layer Protocol: Web | T1071.001 | x | | x |
| Command and Control | Protocol Tunneling (Tor) | T1572 | | x | |
| Command and Control | Web Service / Scheduled Transfer | T1102, T1029 | x | | |

> **Discovery note.** The "System and Network Discovery (multiple)" row consolidates several closely related techniques observed across the incidents: System Owner/User Discovery (T1033), System Information Discovery (T1082), Account Discovery: Local Account (T1087.001), System Network Configuration Discovery (T1016), System Network Connections Discovery (T1049), Network Service Discovery (T1046), and Process Discovery (T1057). They are grouped here for readability and listed individually in the source incident reports.

> **Recurrence note.** Three technique families recur across incidents and support single-actor attribution: Unsecured Credentials: Private Keys (T1552.004) in INC-002 and INC-003, Abuse of Sudo (T1548.003) suspected in INC-001 and confirmed in INC-003, and cron-based web C2 (T1053.003 with T1071.001) in INC-002 and INC-003.
