# Month 1 Security Assessment Report

**Prepared for:** NexaCorp Industries - Board briefing, end of Month 1
**Prepared by:** Johan-Emmanuel Hatchi, SOC Analyst L1, BeCode Corp
**Reference:** BCC-2026 / Month 1 Assessment (INC-2026-001 to INC-2026-003)
**Date:** 28 May 2026
**Classification:** Confidential, do not distribute outside BeCode Corp

> Audience note : this report is written for management. Technical evidence is kept in the per-incident reports; the body translates the findings into business impact.

---

## 1. Executive summary

Over the first month of monitoring, NexaCorp's Linux server estate was the target of **three connected security incidents (INC-2026-001 to INC-2026-003)**. They are not three separate events : they are one adversary, operating through the Tor anonymity network, progressively moving from one internal server to the next by reusing stolen access rather than breaking in again each time.

**Key numbers for the month:**

- **3 internal Linux servers compromised** to root level (Liege services server, Brussels application server, Liege file server).
- **2 backdoor accounts** created (`it_support`, `sysupdate`).
- **2 persistence mechanisms** installed (a cron-based callback on two hosts).
- **1 pre-existing implant** (a MITRE Caldera command-and-control agent) found already running on the first server, indicating a compromise that predates the monitoring window.
- **SSH keys reused across service accounts**, which is what let the attacker pivot from one server to another without any new exploit.

**Is a GDPR notification required? Not on the basis of these three incidents.** Month 1 was an infrastructure compromise (server access, SSH keys, password hashes). No exfiltration of identifiable employee personal data was confirmed in this period. Credential exposure is nonetheless serious and feeds later incidents. (This contrasts with the Month 2 assessment, where a confirmed personal-data exfiltration does trigger a GDPR obligation.)

**The single most important point.** The attacker rarely needed to "hack" their way forward. They moved through the estate because **internal trust was too flat** : the same SSH key opened more than one account, a legacy service carried a 15-year-old backdoor, and there was no egress control to stop a compromised server from calling out. Each server was treated as trusted by the next. Closing the individual holes is necessary but not sufficient ; the trust model itself must be tightened.

**Recommended immediate actions:**

1. Rotate every SSH key and stop reusing one key across multiple accounts or hosts.
2. Remove the two backdoor accounts and the persistence cron jobs, and quarantine the first server (it carries a separate, pre-existing implant).
3. Decommission the legacy vulnerable service on the first server.
4. Add egress filtering and network segmentation so a compromised host cannot freely reach others or the internet.

---

## 2. Findings of the month

### Finding 01 - Linux infrastructure compromise (INC-2026-001)
- **Risk rating: Critical**
- **Technique:** exploitation of a 15-year-old backdoor in an outdated file-transfer service (vsftpd 2.3.4, CVE-2011-2523) on the Liege services server.
- **Component:** internal server 192.168.10.10 (legacy Linux build).
- **Impact:** unauthenticated root access for about 20 seconds (reconnaissance only). Separately, and of greater concern, the same server was **already running a hidden command-and-control implant** (MITRE Caldera) beaconing to an external system every minute - the "unusual outbound connection" the IT team had flagged. The original infection predates the evidence.
- **Business impact:** full administrator exposure of a server, plus evidence of an earlier, unexplained compromise still active on it.

### Finding 02 - Privilege escalation and persistence (INC-2026-002)
- **Risk rating: Critical**
- **Technique:** initial access using a stolen SSH key over Tor, then privilege escalation to root via a misconfigured system binary (SUID on `/usr/bin/find`).
- **Exploitation path:** the attacker logged in to the Brussels application server (`bru-app-01`) as the service account `svc_api`, escalated to root, dumped password hashes, and systematically harvested SSH keys from user home directories.
- **Persistence established:** a backdoor administrator account (`it_support`) and a cron-based callback. This is the foothold that enables the third incident.
- **Business impact:** durable root control of the application server and theft of the keys that unlock the rest of the estate.

### Finding 03 - Lateral movement and persistence (INC-2026-003)
- **Risk rating: High**
- **Technique:** lateral movement using a reused service-account SSH key, with no new exploit.
- **Exploitation path:** from the Brussels server, the attacker reused a stolen key to authenticate to the Liege file server (`lge-files-01`) as `svc_backup` - the system could not tell the intruder from a legitimate internal service. They obtained root and installed a backdoor account (`sysupdate`) and a cron job that beacons to an external server every five minutes.
- **Business impact:** a third server under attacker control with self-restoring persistence, reached purely by abusing internal trust.

---

## 3. Attack chain narrative : one adversary, three servers

The three incidents are a single, connected progression by the same actor, anonymised through Tor:

1. **INC-2026-001 (Liege services server).** The attacker exploits a legacy backdoored service to get root, and the server is found to already host a separate, pre-existing command-and-control implant.
2. **INC-2026-002 (Brussels application server).** Using a stolen SSH key over Tor, the attacker logs in as a service account, escalates to root through a misconfigured binary, dumps credentials, and **harvests SSH keys**. They plant a backdoor account and persistence.
3. **INC-2026-003 (Liege file server).** With one of the harvested keys, the attacker simply **logs in** to a third server as a trusted service account - no exploit needed - takes root, and installs another backdoor and a cron callback.

**The connecting thread is reused trust : stolen SSH keys and a backdoor account.** The attacker exploited a flaw only once (the legacy service) ; every subsequent move relied on credentials and keys that NexaCorp's own systems trusted. A compromise of one host became a compromise of the next because the trust between them was not constrained.

---

## 4. Risk matrix

| Finding | Impact | Likelihood | Risk rating |
|---|---|---|---|
| Finding 01 - Infrastructure compromise + pre-existing C2 | Very High | High | Critical |
| Finding 02 - Privilege escalation, key harvest, persistence | Very High | High | Critical |
| Finding 03 - Lateral movement and persistence | High | High | High |

(A 5x5 visual matrix is provided in the per-incident reports; the table above is the board-level summary.)

---

## 5. Recommendations (prioritised)

**Immediate (this week):**

1. **Rotate all SSH keys and end key reuse.** No single key should authorise more than one account or host. This is the root cause of the lateral movement in Finding 03.
2. **Remove the backdoor accounts (`it_support`, `sysupdate`) and the persistence cron jobs**, and audit all three hosts for any other unauthorized account or scheduled task.
3. **Quarantine the Liege services server** : it carries a separate, pre-existing C2 implant. Acquire disk and memory images before cleanup.

**Short term (this month):**

4. **Decommission the legacy vulnerable service** (vsftpd 2.3.4) and inventory the estate for other end-of-life software (Finding 01).
5. **Fix privilege-escalation exposure** : remove the SUID bit from `/usr/bin/find` and audit for other SUID misconfigurations (Finding 02).
6. **Implement egress filtering** so a compromised host cannot beacon out to the internet, which would have surfaced both the Caldera implant and the cron callbacks.

**Strategic (this quarter):**

7. **Segment the network and constrain host-to-host trust** so that compromise of one server does not grant access to others.
8. **Add behaviour-based detection** for first-time-sudo, new account creation, new cron entries, and service-account logins from unexpected sources.
9. **Change the incident-closure process** : an incident is not closed until the attacker's established access (accounts, keys, cron jobs, implants) is removed and verified, not only the exploited flaw patched.

---

## 6. Appendix (technical)

**Indicators of compromise (campaign):**

- Attacker source 172.16.50.10 (INC-2026-001) and Tor exit nodes in 185.220.101.0/24 and related blocks (INC-2026-002, 003).
- Pre-existing Caldera C2 endpoint 10.40.0.200:8888 (INC-2026-001).
- External C2 endpoint 34.251.89.142 (INC-2026-003 cron beacon, `/update?h=lge-files-01`).
- Backdoor accounts : `it_support` (bru-app-01), `sysupdate` (lge-files-01).
- Persistence : cron callbacks on bru-app-01 and `/etc/cron.d/system-update` on lge-files-01.
- Reused service-account SSH key (svc_api key accepted for svc_backup on lge-files-01).
- Privilege escalation : SUID `/usr/bin/find` (mode 0104755) on bru-app-01.

**Source material.** Per-incident technical detail, exact timestamps, payloads and evidence references are in the individual reports INC-2026-001, INC-2026-002 and INC-2026-003. Raw evidence is retained by BeCode Corp and is not redistributed.
