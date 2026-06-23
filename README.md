# NexaCorp DFIR: INC-2026-003 - Lateral Movement and Persistence

Forensic assessment of a lateral-movement and persistence incident on NexaCorp's Liege file server (`lge-files-01`). On 24 May 2026 an attacker already established on the Brussels application server (`bru-app-01`, from INC-2026-002) pivoted to `lge-files-01` with no new exploit : using a stolen `svc_api` SSH key that was also authorised for the `svc_backup` account, they logged in as `svc_backup`, escalated to root through a `sudo NOPASSWD` rule on the Python interpreter, and installed two persistence mechanisms : a backdoor administrator account (`sysupdate`) and a cron job beaconing to an external server every five minutes, still active at reporting. Conducted as a solo engagement during the BeCode Brussels Blue & Red Team bootcamp (Mission 03), as the continuation of [INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001) and [INC-2026-002](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002). This repository also carries the consolidated **Month 1 Assessment Report** (INC-2026-001 to 003).

[![ci](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-003/actions/workflows/ci.yml/badge.svg)](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-003/actions/workflows/ci.yml)
[![Methodology](https://img.shields.io/badge/methodology-NIST%20SP%20800--61r2-blue.svg)](#methodology)
[![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Scope](https://img.shields.io/badge/scope-forensic--only-orange.svg)](#engagement-context)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Johan--Emmanuel%20Hatchi-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/johan-emmanuel-hatchi/)

This repository documents a SOC analyst engagement carried out as part of the BeCode Cybersecurity Bootcamp (promotion 2025-2026). It is an assessment lab : a forensic investigation and report, with no detection-rule (Phase 2) deliverable. It is the third incident in the NexaCorp DFIR series and the Month 1 capstone.

## Contents

- [Operational notice](#operational-notice)
- [At a glance](#at-a-glance)
- [Engagement context](#engagement-context)
- [Executive summary](#executive-summary)
- [Kill chain summary](#kill-chain-summary)
- [How to read this repository](#how-to-read-this-repository)
- [Methodology](#methodology)
- [Detection engineering](#detection-engineering)
- [Repository layout](#repository-layout)
- [Reproducibility](#reproducibility)
- [Known limits](#known-limits)
- [NexaCorp DFIR series](#nexacorp-dfir-series)
- [Acknowledgments](#acknowledgments)
- [About](#about)
- [License](#license)

---

## Operational notice

This is a training engagement against fictitious infrastructure. NexaCorp Industries is a fictional client used as the scenario for the BeCode Brussels bootcamp. The hosts `bru-app-01` and `lge-files-01` are isolated lab VMs. No real organization, network, or human was attacked.

All IP addresses, hostnames, accounts and key fingerprints referenced here (`34.251.89.142`, `185.220.101.62`, `lge-files-01`, `bru-app-01`, `svc_backup`, `svc_api`, `sysupdate`, and similar) are lab-local artifacts, not real-world threat intelligence. Do not feed them to a production SIEM as IOCs.

Publication authorized by the BeCode lab coach (Thomas B.) on 2026-05-17 for portfolio use. The full confidentiality statement appears in the findings report.

---

## At a glance

| Field | Value |
|---|---|
| Reference | INC-2026-003 |
| Affected host | lge-files-01 (NexaCorp Liege file server, 192.168.10.30) |
| Pivot source | bru-app-01 (192.168.10.20, compromised in INC-2026-002) |
| Root cause | SSH key reuse across service accounts (one key authorised svc_api and svc_backup) |
| Outcome | Root on a third server, backdoor account + active C2 cron (no confirmed data exfiltration) |
| Date reported | 2026-05-25 |
| Delivered | 2026-05-29 |
| Phases | Phase 1 assessment only (forensic, no detection-engineering phase) |
| Related incidents | INC-2026-001, INC-2026-002 (same campaign) |

| Investigation output | Value |
|---|---|
| Findings | 3 (2 Critical, 1 High) |
| Lateral movement | reused svc_api key accepted for svc_backup (fingerprint SHA256:Cx3hNuyZ...) |
| Privilege escalation | sudo NOPASSWD on /usr/bin/python3 (GTFOBins) |
| Persistence | backdoor account sysupdate + cron /etc/cron.d/system-update |
| C2 | 34.251.89.142 (HTTP /update?h=lge-files-01), 4 beacons captured |
| Evidence sources | auth.log, sshd_journal.log, sudo_journal.log, audit_filtered.log, audit.log, syslog, pcap |

---

## Engagement context

**Scenario (fictional).** NexaCorp Industries reported a third incident in three weeks. After INC-2026-001 (FTP backdoor on the Liege services server) and INC-2026-002 (pivot to the Brussels application server, SUID escalation, backdoor account, SSH key harvest), new evidence showed the attacker had reached the Liege file server `lge-files-01` and installed persistence, one element of which was still running when the incident was reported. Reported by Marc Wauters (IT Infrastructure Manager) on 2026-05-25 ; reviewing authority Sarah Chen, Senior SOC Analyst.

**Scope.** Forensic analysis of the evidence bundle only. This is an assessment lab : there is no Phase 2 live detection-validation phase. The attack window investigated is Sunday 2026-05-24, 12:31 to 13:05 CEST.

**Capstone.** The engagement also consolidates the month's three incidents (INC-2026-001 to 003) into the [Month 1 Assessment Report](reports/Month1_Assessment_Report.md) for management.

**Educational context.** Delivered during the BeCode Brussels Blue & Red Team bootcamp (November 2025 to September 2026) as Mission 03.

---

## Executive summary

On 24 May 2026, an attacker already established on `bru-app-01` (from INC-2026-002) pivoted to the Liege file server `lge-files-01` with no new exploit. Using a stolen `svc_api` SSH private key that was also authorised for the `svc_backup` account, the attacker logged in as `svc_backup`, escalated to root through a `sudo NOPASSWD` rule on the Python interpreter, and installed two persistence mechanisms : a backdoor administrator account (`sysupdate`) and a cron job beaconing to `34.251.89.142` every five minutes. The beacon was still active at the time of reporting.

The root cause is SSH key reuse across service accounts : a single private key opened a different account on a different host. This is the third incident of the Month 1 campaign ; for how it connects to INC-2026-001 and INC-2026-002 as one continuous operation, see the Month 1 Assessment Report.

---

## Kill chain summary

1. **Preparation (bru-app-01).** The `it_support` backdoor (from INC-2026-002) locates the `svc_api` private key, confirms it is authorised for `svc_backup`, and stages it (12:35-12:38 CEST).
2. **Lateral movement (12:39:54).** The reused key authenticates to `lge-files-01` as `svc_backup` from `bru-app-01` ; the key fingerprint does not match the legitimate svc_backup baseline.
3. **Privilege escalation (12:40).** `sudo NOPASSWD` on `/usr/bin/python3` is abused to run commands as root (audit shows auid=1000, euid=0).
4. **Persistence (12:40-12:41).** Backdoor account `sysupdate` (added to sudo) and cron `/etc/cron.d/system-update` beaconing to `34.251.89.142` every five minutes ; four beacons captured.

---

## How to read this repository

| If you are a... | Start here | Time |
|---|---|---|
| **Recruiter or hiring manager** | This README + the [report](reports/INC-2026-003_Findings_Report.md) executive summary | 5 min |
| **Management / board** | The [Month 1 Assessment Report](reports/Month1_Assessment_Report.md) (non-technical, business impact, the three incidents as one story) | 10 min |
| **SOC analyst evaluating fit** | [Report](reports/INC-2026-003_Findings_Report.md) technical analysis + [`evidence-summary/ioc-summary.md`](evidence-summary/ioc-summary.md) | 20 min |
| **DFIR practitioner** | Full [report](reports/INC-2026-003_Findings_Report.md) + [`methodology/attack-timeline.md`](methodology/attack-timeline.md) + [`methodology/three-incident-kill-chain.md`](methodology/three-incident-kill-chain.md) + [`notes/journal.md`](notes/journal.md) | 30 min |
| **Anyone who wants to grep, cite, or diff** | [Markdown source of the report](reports/INC-2026-003_Findings_Report.md) | as needed |

---

## Methodology

The engagement follows standard incident-response frameworks:

- **NIST SP 800-61r2** (incident handling) and **NIST SP 800-86** (forensic techniques).
- **SANS PICERL** : the Identification stage is the core of this forensic assessment.
- **MITRE ATT&CK Enterprise v15** : every finding is mapped (see [`methodology/attck-mapping.md`](methodology/attck-mapping.md)).
- Weakness classification : CWE-522 (key reuse), CWE-250/269 (sudo misconfiguration), CWE-732 (cron drop-in).

**Evidence and timestamps.** Host logs are CEST (UTC+02:00) ; the packet capture is native UTC. Both are shown where the capture is cited.

---

## Detection engineering

**Not applicable for this engagement.** This is an assessment lab with no Phase 2 : no detection rules were authored. The intrusion is nonetheless detectable behaviorally, and the report recommends these monitoring controls : a service-account SSH login from an unexpected source or with a non-baseline key fingerprint ; creation of a new local account added to `sudo` ; a new drop-in in `/etc/cron.d/` ; and outbound connections from a server to an unrecognized external host.

---

## Repository layout

```
NexaCorp-DFIR-INC-2026-003/
├── README.md                      This file
├── LICENSE
├── .gitignore
├── .markdownlint.json
├── .github/
│   └── workflows/
│       └── ci.yml                 markdownlint + typography validation
├── reports/
│   ├── INC-2026-003_Findings_Report.pdf   Incident findings report
│   ├── INC-2026-003_Findings_Report.md    Markdown source of the report
│   ├── Month1_Assessment_Report.pdf       Month 1 capstone (INC-2026-001 to 003), board audience
│   └── Month1_Assessment_Report.md        Markdown source of the Month 1 report
├── evidence-summary/
│   └── ioc-summary.md             Indicators of compromise
├── methodology/
│   ├── attack-timeline.md         Incident timeline (CEST and UTC)
│   ├── attck-mapping.md           MITRE ATT&CK mapping table
│   └── three-incident-kill-chain.md   Cross-incident kill chain (INC-2026-001 to 003)
└── notes/
    └── journal.md                 Investigation journal
```

This is an assessment lab, so there is no `detection/` directory.

---

## Reproducibility

The evidence bundle is BeCode lab property and is not redistributed. With your own copy, the core findings are reproducible from the logs and capture (the pivot in `sshd_journal.log`, the escalation in `audit_filtered.log`, the persistence in `sudo_journal.log`, and the four C2 beacons to 34.251.89.142 in the packet capture).

---

## Known limits

- **Forensic-only.** No live detection phase for this incident ; the report proposes behavioural detection but does not ship validated rules.
- **Scope is the captured window.** The assessment covers the 24 May evidence ; activity outside that window is out of scope.
- **Cross-incident framing.** The connection to INC-2026-001 and 002 is presented in the Month 1 Assessment Report ; this findings report is scoped to the lge-files-01 incident.

---

## NexaCorp DFIR series

- [INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001): Linux infrastructure compromise (vsftpd backdoor, Caldera C2)
- [INC-2026-002](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002): privilege escalation and persistence (Tor SSH, SUID, backdoor account)
- **INC-2026-003**: this repository (lateral movement and persistence; Month 1 capstone)
- [INC-2026-004](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-004): SQL injection (web portal)
- [INC-2026-005](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-005): OS command injection and web shell (web portal)
- [INC-2026-006](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-006): stored XSS and session hijacking (NexaPortal)
- [INC-2026-007](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-007): IDOR and broken access control (NexaPortal; Month 2 capstone)

---

## Acknowledgments

- **Thomas B.** (BeCode lab coach): scenario design and publication authorization for portfolio use.
- **MITRE** for the ATT&CK knowledge base used to map every finding.

---

## About

Solo DFIR engagement delivered during the [BeCode Brussels](https://becode.org) Blue & Red Team bootcamp (November 2025 to September 2026), Mission 03.

Author: **[Johan-Emmanuel Hatchi](https://github.com/Jhatchi)** ([LinkedIn](https://www.linkedin.com/in/johan-emmanuel-hatchi/)).

Open to cybersecurity internship opportunities starting September 2026 in Belgium. Looking for SOC / DFIR / detection engineering roles where this kind of end-to-end work (log and capture forensics, lateral-movement analysis, formal client reporting) is in scope.

---

## License

[MIT](LICENSE), 2026 Johan-Emmanuel Hatchi.

The report text and methodology notes are released under MIT: free to copy, adapt, and reuse with attribution. The evidence bundle, lab infrastructure, and original engagement briefings remain BeCode Brussels property and are not redistributed.
