# Investigation Journal: INC-2026-003

## Month 1 Assessment (forensic only)

---

**Analyst :** Johan-Emmanuel Hatchi (BeCode SOC trainee)
**Organization :** BeCode Corp
**Client :** NexaCorp Industries (fictional)
**Engagement :** INC-2026-003 (Month 1 Assessment, covering INC-2026-001 + INC-2026-002 + INC-2026-003)
**Related incidents :** INC-2026-001 (Liege services server) and INC-2026-002 (Brussels application server), same threat actor
**Reviewing authority :** Sarah Chen, Senior SOC Analyst
**Prepared for :** Marc Wauters, IT Infrastructure Manager
**Engagement reference :** BCC-2026 | INC-2026-003
**Classification :** Internal - Not for distribution

---

## 1. Lab Context

This investigation took place in the BeCode Corp SOC training environment, a controlled lab built around a fictitious client called NexaCorp Industries. All hosts, accounts, IP addresses, and credentials referenced in this journal belong to the lab and have no production analogue.

| Host | IP | Role |
|---|---|---|
| bru-app-01 | 192.168.10.20 | Brussels application server, compromised in INC-2026-002, used here as the pivot source |
| lge-files-01 | 192.168.10.30 | Liege file server, target of INC-2026-003 |
| mon-01 | 192.168.10.200 | Monitoring and backup agent, source of legitimate svc_backup activity |
| m.dubois-ws | 192.168.10.105 | Liege sysadmin workstation |

Reviewing authority for the assessment: Sarah Chen, Senior SOC Analyst (BeCode Corp). Engagement reference: BCC-2026 | INC-2026-003.

---

## 2. Incident Framing

INC-2026-003 is the third and final incident of the NexaCorp Month 1 Assessment. The client narrative (delivered Monday morning by Marc Wauters, IT Infrastructure Manager) reported suspicious activity on lge-files-01 over the weekend: an inbound SSH login from the Brussels application server, a new local account, a scheduled task that fires every five minutes, and an outbound connection that was still active when the alert was raised.

The investigation scope was the attack window of Sunday 24 May 2026, 12:31 to 13:05 CEST. The Month 1 Assessment deliverable consolidates INC-2026-001, INC-2026-002, and INC-2026-003 into a single coherent kill chain rather than three separate reports. The briefing from Sarah Chen broke the investigation into seven sub-missions to be worked in order.

Deadline: Friday 29 May, 18:00 CEST, submission to s.chen@becode-corp.be.

---

## 3. Evidence Inventory

The evidence bundle was 258 KB compressed, small enough to read by hand without grep heuristics. Seven sources were provided.

| File | Host | Native TZ | Content |
|---|---|---|---|
| bru-app-01/auth.log | bru-app-01 | CEST | SSH and PAM authentication, full day May 24 |
| lge-files-01/sshd_journal.log | lge-files-01 | CEST | SSH daemon connections, full day |
| lge-files-01/sudo_journal.log | lge-files-01 | CEST | All sudo commands |
| lge-files-01/audit_filtered.log | lge-files-01 | CEST | auditd execution log, attack window plus discovery |
| lge-files-01/audit.log | lge-files-01 | CEST | Full unfiltered auditd reference |
| lge-files-01/syslog | lge-files-01 | CEST | System log including cron activity |
| pcap/lab03_capture.pcap | network bridge | UTC | Packet capture, attack window plus persistence |

**Limits of the bundle.**

- No complete inter-host network bridge captures beyond the attack window.
- No live memory acquisition, no filesystem dumps.
- The packet capture covers only the attack and persistence window, not the surrounding day.
- INC-2026-003 is an assessment lab, forensic-only. There is no Phase 2 live detection-validation phase for this incident, so no Wazuh rule.level data is available to anchor severity ratings on rule firing levels (unlike INC-2026-002).

---

## 4. Investigation Plan - Status

The seven sub-missions defined by Sarah Chen in BRIEFING_02_mission.md:

| Step | Sub-mission | Status |
|---|---|---|
| 1 | Identify the lateral movement (entry point, account, method) | Done |
| 2 | Build the on-host timeline post-pivot | Done |
| 3 | Identify the privilege-escalation vector | Done |
| 4 | Identify the persistence mechanisms | Done |
| 5 | Connect the three incidents into a single kill chain | Done |
| 6 | Produce the executive summary (board-level, no jargon) | Done |
| 7 | Produce the three-horizon recommendations | Done |

---

## 5. Working Hypotheses - Status

This section records the working hypotheses considered during the investigation, including the ones that were wrong and corrected. The point is not to look infallible but to make the reasoning auditable.

### H1. Baseline vs anomaly on svc_backup SSH activity

**Status: confirmed.**

Reading sshd_journal.log produced a clear baseline for svc_backup: always sourced from 192.168.10.200 (mon-01), always presenting key fingerprint `SHA256:mHj4kL9pWqNv2rXsZt7uYa3oBc1dEf5gHi6jKl8mNo0`, on a regular schedule (07:14, 10:00, 11:00, 13:25, 16:25 and so on). The connection at 12:39:54 CEST used the same account and the same authentication method (public key) but originated from 192.168.10.20 (bru-app-01) and presented fingerprint `SHA256:Cx3hNuyZt0jgbq25UKWg3kcSA0L9dfgL3OeCHXlJQg4`, neither matching the legitimate baseline nor falling in the regular cadence. This was the pivot.

### H2. The attacker generated a new SSH key pair at 12:37

**Status: rejected (false trail).**

Initial reading of the auth.log on bru-app-01 noticed `ssh-keygen -y -f /home/svc_api/.ssh/id_rsa` at 12:37:03 and tentatively interpreted this as a fresh key-pair generation. Two arguments killed this hypothesis. First, `ssh-keygen -y -f` derives the public key from an existing private key; it does not generate a new pair. Second, even if a new pair had been generated at 12:37, its public key would not have been present in any authorized_keys file anywhere, and therefore could not have opened the svc_backup session at 12:39:54. The attacker reused a stolen private key, then derived the matching public key to verify the match before pivoting. Theft and reuse, not generation.

### H3. The svc_api private key opens a svc_backup session because of cross-account key reuse

**Status: confirmed.**

The sequence on bru-app-01 between 12:35:44 and 12:38:29 reads as a deliberate verification of this hypothesis by the attacker themselves: locate the key material (`find -name id_rsa -o -name authorized_keys`), read the svc_api private key (`cat /home/svc_api/.ssh/id_rsa`), read svc_backup's authorized_keys to confirm which public keys it accepts (`cat /home/svc_backup/.ssh/authorized_keys`), derive the public key from the stolen private key (`ssh-keygen -y -f`), and only then stage the key for reuse (`cp .../id_rsa /tmp/.cache`). The attacker did not guess. They verified the match before attempting the pivot. The structural root cause is that the public key corresponding to svc_api's private key was authorised in svc_backup's authorized_keys on lge-files-01: a single key pair reused across two service accounts.

### H4. Containment via honeypot deployment and global Tor blocking

**Status: rejected (scope creep, sur-engineering).**

When the question of immediate containment came up, an initial reflex was to propose a honeypot to observe the attacker's continued activity and a global block on Tor exit nodes at the perimeter. Both were rejected.

A honeypot is a project, not an emergency containment measure, and would have taken weeks of design and integration that the active C2 channel did not afford. A global Tor blocklist is operationally unmaintainable for a small IT team without a dedicated SOC: exit nodes rotate continuously, the list runs into thousands of addresses, and the volume of false positives would degrade legitimate traffic without preventing the attacker from switching to a commodity VPS. Tor was the transport of the operator, not the intrusion vector itself.

Correction adopted: surgical containment, all actions performed together so they reinforce each other. Block 34.251.89.142 outbound at the perimeter firewall. Delete `/etc/cron.d/system-update` and `/tmp/.update.log`. Delete the sysupdate account with `userdel -r`. Revoke the compromised public key from svc_backup's authorized_keys on lge-files-01. The point of doing all four at once is that any one of them left in place lets the attacker return within five minutes through one of the others.

### H5. Attribution: opportunistic versus targeted

**Status: refined, then confirmed as targeted with an explicit anti-objection clause.**

The first formulation was "opportunistic-then-targeted": initial access in INC-2026-001 was likely opportunistic (the FTP backdoor on the Liege services server is a known vulnerable build, scanned constantly by the internet), and the subsequent operation became targeted once the attacker was inside. The natural objection from a reviewer is that auth.log on bru-app-01 also shows dozens of automated Tor scans from unrelated ranges (89.248.x, 193.32.x, 45.142.x and so on) that look identical to opportunistic noise.

The verdict was sharpened to targeted, with an explicit clause in the executive summary distinguishing the background noise of the internet from the actual attacker's mode of operation. The actual attacker used valid internal credentials rather than guessing passwords, deliberately chained one server to the next in a logical sequence, took specific steps to keep their access hidden and durable, and went straight for sensitive configuration files and stored credentials once inside, rather than acting at random. None of that is opportunistic behaviour. The opportunistic scans visible in auth.log belong to a separate population.

### H6. Packet-capture timestamps versus host-log timestamps

**Status: refined and confirmed via cross-source validation.**

Filtering the pcap for traffic to 34.251.89.142 produced four beacons at 10:45:01, 10:50:01, 10:55:01, 11:00:01. This was inconsistent: the cron file was written to disk at 12:41:00 CEST, so beacons before that time should not exist. Three hypotheses were on the table.

1. Timezone offset in tshark display: the pcap is recorded in UTC while host logs are in CEST (UTC+2). 10:45 UTC would then be 12:45 CEST, which matches the cron `*/5` first tick after creation at 12:41.
2. The C2 was already active before INC-2026-003 (prior infection).
3. Lab artefact.

Hypothesis 1 was tested directly rather than assumed: `tshark -r lab03_capture.pcap -Y "ip.dst == 34.251.89.142 && http" -t ud -T fields -e frame.time` returned frames stamped "May 24, 2026 10:45:01.110000000 UTC". The pcap is natively in UTC. Conversion to CEST gives 12:45, 12:50, 12:55, 13:00, exactly four beacons aligned with a `*/5` cron created at 12:41. Cross-source validation: the host syslog, in CEST, shows the same cron execution at 12:45, confirming the same event from an independent source. The report explicitly documents both the native UTC values and the converted CEST values, and the timezone convention is stated up front and again in the appendix.

---

## 6. Findings Log

| Ref | Finding | Severity | Evidence anchors | MITRE ATT&CK |
|---|---|---|---|---|
| 3.1 | Lateral movement via reused service-account SSH key | HIGH | sshd_journal.log 12:39:54 (PID 5235), auth.log bru-app-01 12:35:44 to 12:38:29 | T1552.004, T1021.004, T1078 |
| 3.2 | Privilege escalation via sudo NOPASSWD on python3 (GTFOBins) | CRITICAL | audit_filtered.log 12:40:28 and 12:40:51 (auid=1000 svc_backup, euid=0 root, key=lab03_exec) | T1548.003 |
| 3.3 M1 | Backdoor local account sysupdate (sudo group) | HIGH | sudo_journal.log and audit_filtered.log, 12:40:51 | T1136.001 |
| 3.3 M2 | Cron-based C2 beacon to 34.251.89.142 (active at reporting) | CRITICAL | sudo_journal.log 12:41:00, /etc/cron.d/system-update, pcap beacons 12:45-13:00 CEST | T1053.003, T1071.001 |

**Severity rating note.** Severities are analyst-rated, not CVSS-derived. INC-2026-003 has no live detection-validation phase, so no Wazuh rule.level input is available. Ratings rely on operational impact, MITRE technique category, and current threat state (active versus neutralised). The cron C2 (3.3 M2) is rated CRITICAL rather than HIGH because, unlike the cron persistence in INC-2026-002 whose payload could not be observed, here the payload is fully visible, the beacon was confirmed live in the packet capture, and the channel was still active at the time of reporting.

---

## 7. IOCs

All indicators below belong to the BeCode SOC training lab (NexaCorp scenario, fictitious). They have no production analogue and must not be ingested into real-world threat intelligence feeds.

| Indicator | Type | Context |
|---|---|---|
| 34.251.89.142 | IPv4 | C2 server contacted by the cron beacon |
| 185.220.101.62 | IPv4 | Tor exit node, it_support login source on bru-app-01 |
| 185.220.101.47 | IPv4 | Tor exit node, related scanning activity |
| /etc/cron.d/system-update | File path | Malicious cron persistence on lge-files-01 |
| /tmp/.update.log | File path | Local beacon marker on lge-files-01 |
| /tmp/.cache | File path | Staged stolen private key on bru-app-01 |
| sysupdate | Account | Backdoor local account on lge-files-01, sudo group |
| [REDACTED-lab-credential] | Credential | Password set on the sysupdate account |
| SHA256:Cx3hNuyZt0jgbq25UKWg3kcSA0L9dfgL3OeCHXlJQg4 | SSH key fingerprint | Stolen svc_api key reused to authenticate as svc_backup |
| GET /update?h=lge-files-01 | HTTP request | Beacon pattern to the C2 server |

---

## 8. Consolidated Timeline

All times in CEST. Packet-capture values include the native UTC value in parentheses for traceability.

| Time (CEST) | Host | Event |
|---|---|---|
| 12:31:08 | bru-app-01 | it_support logs in by password from 185.220.101.62 (Tor exit node) |
| 12:31:22 | bru-app-01 | sudo /bin/bash opens an interactive root shell |
| 12:35:44 | bru-app-01 | find /home /root -name id_rsa -o -name authorized_keys |
| 12:36:19 | bru-app-01 | cat /home/svc_api/.ssh/id_rsa (private key theft) |
| 12:36:51 | bru-app-01 | cat /home/svc_backup/.ssh/authorized_keys (match verification) |
| 12:37:03 | bru-app-01 | ssh-keygen -y -f /home/svc_api/.ssh/id_rsa (pubkey derivation) |
| 12:38:29 | bru-app-01 | cp /home/svc_api/.ssh/id_rsa /tmp/.cache (staging) |
| 12:39:54 | lge-files-01 | SSH publickey accepted for svc_backup from 192.168.10.20, key Cx3hNuyZt0... (pivot, PID 5235) |
| 12:40:08 | lge-files-01 | sudo id |
| 12:40:17 | lge-files-01 | sudo cat /etc/sudoers (enumerate sudo rights) |
| 12:40:28 | lge-files-01 | first sudo python3 (auid=1000, euid=0, key=lab03_exec, escalation signature) |
| 12:40:51 | lge-files-01 | sudo python3 -c '...useradd sysupdate...' (backdoor account, sudo group) |
| 12:41:00 | lge-files-01 | sudo python3 -c '...write /etc/cron.d/system-update...' (C2 cron) |
| 12:43:17 to 12:48:55 | lge-files-01 | Data reconnaissance: `ls /data`, `cat nexacorp-sync.conf`, `find *.conf *.env *.key`, `cat db-credentials.env` |
| 12:45:01 (10:45:01 UTC) | network | First C2 beacon: GET /update?h=lge-files-01 to 34.251.89.142:80 |
| 12:50:01 (10:50:01 UTC) | network | Second beacon |
| 12:55:01 (10:55:01 UTC) | network | Third beacon |
| 13:00:01 (11:00:01 UTC) | network | Fourth beacon |
| 14:31:58 | lge-files-01 | Sysadmin m.dubois starts internal discovery (cat /etc/passwd) |
| 14:33:12 | lge-files-01 | m.dubois reads /etc/cron.d/system-update |
| 14:36:47 | lge-files-01 | m.dubois confirms the sysupdate backdoor account |

Interactive attack ended around 12:49. Sysadmin first noticed the compromise at 14:31, roughly one hour and forty minutes later, while the C2 beacon was still firing. No real-time detection.

---

## 9. Cross-Incident Analysis

### The kill chain in three sentences

- **INC-2026-001.** The attacker gained initial entry through a backdoor in the FTP service on the Liege services server.
- **INC-2026-002.** The attacker pivoted to the Brussels application server (bru-app-01), escalated to root through a SUID misconfiguration, read the shadow file, created the it_support backdoor account, and harvested SSH private keys from service accounts.
- **INC-2026-003.** Using one of those stolen keys (svc_api), the attacker reached a second Liege server, the file server (lge-files-01), this time without exploiting any flaw at all, escalated to root through a sudo NOPASSWD rule on python3, and installed two persistence mechanisms (the sysupdate backdoor account and a cron-based C2 beacon to 34.251.89.142).

### The artefact that links the incidents

The svc_api SSH private key (`/home/svc_api/.ssh/id_rsa`). Stolen on bru-app-01 during the INC-2026-002 follow-on activity, staged in `/tmp/.cache`, and reused to authenticate the INC-2026-003 pivot as svc_backup on lge-files-01. A single file is the physical bridge between the two incidents, traceable from theft to reuse.

### Attribution to a single actor

Three recurring technique families anchor the single-actor attribution and are explicitly called out in the report's ATT&CK recurrence note:

- Unsecured Credentials: Private Keys (T1552.004), present in INC-2026-002 and INC-2026-003.
- Abuse Elevation Control: Sudo and Sudo Caching (T1548.003), suspected in INC-2026-001 and confirmed in INC-2026-003.
- Cron-based web Command and Control (T1053.003 with T1071.001), present in INC-2026-002 and INC-2026-003.

Operational fingerprints reinforce the pattern: connections from the 185.220.101.x range (Tor exit nodes), reuse of valid service-account credentials, abuse of privilege-escalation misconfigurations (SUID then sudo), and cron-based HTTP persistence. The fingerprints recur, and the random Tor scans visible in auth.log do not look anything like this attacker's behaviour.

---

## 10. Open Questions and Followups

These items were not in scope or could not be answered from the evidence bundle alone. They are listed here so the next analyst, or NexaCorp's own team after handoff, can pick them up.

- **C2 payload semantics.** The cron beacon sends `GET /update?h=lge-files-01` every five minutes. The body of the server's response (if any) was not captured beyond the four observed beacons. What does the attacker's infrastructure do with that hostname-tagged ping? Pure presence check, command channel, or staged second-stage download? Unknown without longer capture or access to the C2 server.

- **Other hosts affected by cross-account key reuse.** The svc_api public key was authorised on svc_backup of lge-files-01. The full audit of every authorized_keys file across NexaCorp's fleet was not in the scope of this engagement. Other hosts may carry the same misconfiguration and offer additional pivot targets to anyone holding the svc_api private key.

- **Backup integrity of /data.** The attacker had root and read access to `/data/config/db-credentials.env` and to backup configuration files. Whether they exfiltrated any of this content over the C2 channel during the four observed beacons is undetermined from the bundle.

- **Earlier dwell time on bru-app-01 between INC-2026-002 and INC-2026-003.** The it_support backdoor account was created in INC-2026-002 and was never cleaned up. Between the end of INC-2026-002 and the start of INC-2026-003 on 24 May, did the attacker maintain quiet access, and through which sessions? Not reconstructible from the May 24 logs alone.

- **Wazuh detection coverage.** Out of scope for this incident (assessment lab, forensic-only). If NexaCorp deploys HIDS and NIDS as recommended (R5), a Phase 2 detection-engineering exercise on the INC-2026-003 evidence would be the natural followup: build the rules that would have fired on account creation, write to /etc/cron.d, sudo by service accounts, and outbound beacons to unknown external addresses.

---

## 11. Operational Notes (BeCode internal)

Methodological points that proved load-bearing during this investigation and are worth carrying into future missions.

- **Timezone discipline.** Always check the native timezone of each evidence source before correlating timestamps. Host logs were in CEST, the packet capture in UTC. The mismatch initially produced an apparent impossibility (beacons before the cron was created). The resolution was empirical (`tshark -t ud`) rather than assumed. The convention adopted for the report (CEST narrative, native UTC shown alongside, explicit timezone note in the front matter and in the appendix) avoids the same trap for any reader.

- **Cross-source corroboration.** Host evidence and network evidence corroborated each other independently. The cron creation in sudo_journal.log at 12:41:00 CEST and the first beacon in the pcap at 10:45:01 UTC (= 12:45:01 CEST) are independent sources pointing at the same event. The same cron tick is visible in lge-files-01 syslog at 12:45 CEST. Three sources, one event, three different log streams. This is what makes a forensic chain solid.

- **Audit log signatures.** The `auid` field in auditd preserves the login UID across sudo, while `euid` reflects the effective UID after escalation. The divergence between `auid=1000` (svc_backup) and `euid=0` (root), tagged `key=lab03_exec`, at 12:40:28 and 12:40:51 is the structural signature of the privilege escalation. Worth reading systematically before reaching for narrative reconstructions.

- **GTFOBins as a category of misconfiguration.** Granting sudo NOPASSWD on an interpreter or a shell-spawning binary (python, perl, awk, find, vim and similar) is not "this account can run python", it is "this account can run anything as root". The misconfiguration is structural and exists independently of any attacker. Worth flagging on sight in any future sudoers audit.

- **Baseline-versus-anomaly approach.** The pivot at 12:39:54 was identifiable in a log of ten successful SSH connections in the day because the legitimate svc_backup activity had a stable fingerprint (source 192.168.10.200, key `mHj4kL9p...`, hourly cadence). Establishing the baseline first made the anomaly visible by inspection. Without the baseline, the anomalous connection would have looked like just another legitimate svc_backup line.

---

## 12. References

- BeCode Brussels Blue & Red Team bootcamp Mission 03 briefings: BRIEFING_01_context, BRIEFING_02_mission, BRIEFING_03_tools (BeCode IP, not redistributed in this repository)
- Final assessment deliverable: [`reports/INC-2026-003_Findings_Report.pdf`](../reports/INC-2026-003_Findings_Report.pdf) (26 pages, submitted 29 May 2026 to s.chen@becode-corp.be)
- NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide
- NIST SP 800-86, Integrating Forensic Techniques into Incident Response
- SANS PICERL incident-response process
- [MITRE ATT&CK Enterprise v15](https://attack.mitre.org/)
- [GTFOBins](https://gtfobins.github.io/) (sudo escape catalogue, applicable to the 3.2 finding)
- INC-2026-001 (initial entry, same threat actor): https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001
- INC-2026-002 (source of the stolen key and the it_support backdoor): https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002

---

*End of Month 1 Assessment journal.*
