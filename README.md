# NexaCorp DFIR Engagement (INC-2026-003) - Month 1 Assessment

Cross-incident forensic assessment of a three-week intrusion at NexaCorp Industries, reconstructed as one continuous attacker operation across three internal Linux servers. This repository consolidates **INC-2026-001, INC-2026-002, and INC-2026-003 into a single Month 1 Assessment narrative**, not three separate reports. Conducted as a solo engagement during the BeCode Brussels Blue & Red Team bootcamp (Mission 03), as the direct continuation of [INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001) and [INC-2026-002](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002).

[![ci](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-003/actions/workflows/ci.yml/badge.svg)](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-003/actions/workflows/ci.yml)
[![Methodology](https://img.shields.io/badge/methodology-NIST%20SP%20800--61r2-blue.svg)](#methodology)
[![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Scope](https://img.shields.io/badge/scope-forensic--only-orange.svg)](#engagement-context)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Johan--Emmanuel%20Hatchi-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/johan-emmanuel-hatchi/)

## ⚠ Operational notice

**This is a lab engagement against fictitious infrastructure.** NexaCorp Industries is a fictional client used as the scenario for BeCode Brussels Mission 03. The hosts `bru-app-01` and `lge-files-01` are isolated lab VMs provisioned for the exercise. No real organization, network, or human was attacked.

All IP addresses, hostnames, account names, key fingerprints, and indicators of compromise published in this report (`34.251.89.142`, `185.220.101.62`, `lge-files-01`, `bru-app-01`, `svc_backup`, `svc_api`, `sysupdate`, Tor exit-node ranges quoted as IOCs, etc.) are **lab-local artifacts**, not real-world threat intelligence. Do not feed them to a production SIEM as IOCs.

**Publication authorized** by BeCode lab coach (Thomas B.) on 2026-05-17 for portfolio use of delivered BeCode missions. The full confidentiality statement appears in the findings report.

## At a glance

| Engagement metadata | Value |
|---|---|
| Reference | `BCC-2026 / INC-2026-003` |
| Deliverable | Month 1 Assessment Report (INC-2026-001 + INC-2026-002 + INC-2026-003) |
| Related incidents | [`INC-2026-001`](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001) and [`INC-2026-002`](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002) (same threat actor) |
| Later missions | [`INC-2026-004`](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-004) (SQL injection on bru-web-01), [`INC-2026-005`](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-005) (OS command injection and web shell), and [`INC-2026-006`](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-006) (stored XSS and session hijacking) |
| Scope | Forensic analysis of the evidence bundle (assessment lab, no live phase) |
| Delivered | 2026-05-29 |
| Status | Complete and submitted |

| Investigation output | Value |
|---|---|
| Report length | 26 pages |
| INC-2026-003 findings | **4** (2 CRITICAL, 2 HIGH) |
| Severity model | Analyst-rated (impact + technique category + threat state), no CVSS, no Wazuh rule.level input |
| Incidents reconstructed | 3, as one continuous kill chain |
| Evidence sources analyzed | auth.log, sshd_journal.log, sudo_journal.log, audit_filtered.log, audit.log, syslog, pcap |
| Cross-source corroboration | Host logs (CEST) cross-checked against packet capture (native UTC) |

## Engagement context

**Scenario (fictional).** NexaCorp Industries reported a third security incident in three weeks. After INC-2026-001 (FTP backdoor on the Liege services server) and INC-2026-002 (pivot to the Brussels application server `bru-app-01`, SUID escalation, backdoor account, SSH key harvest), new evidence showed the attacker had reached a second Liege server, the file server `lge-files-01`, and installed persistence, one element of which was still running when the incident was reported on the Monday morning.

**Mandate.** Marc Wauters (IT Infrastructure Manager) required a Month 1 Assessment Report telling the full story as one continuous attacker operation, for presentation to his board. The reviewing authority for the engagement was Sarah Chen, Senior SOC Analyst. The briefing split the work into seven sub-missions (lateral movement, on-host timeline, privilege escalation, persistence, cross-incident kill chain, executive summary, recommendations), consolidated into a single deliverable rather than three separate reports.

**Scope.** Forensic analysis of the evidence bundle only. Unlike INC-2026-002, there is no Phase 2 live detection-validation phase: this is an assessment lab. The attack window investigated is Sunday 2026-05-24, 12:31 to 13:05 CEST.

**Educational context.** Delivered during the **BeCode Brussels Blue & Red Team bootcamp (November 2025 to September 2026)** as Mission 03. Investigation conducted on the BeCode SOC training workstation, accessed remotely via SSH over Tailscale VPN.

## Executive summary

Over a three-week period in May 2026, a single external attacker progressed from no access whatsoever to full control of two of NexaCorp's internal servers. This was not three unrelated incidents. It was one continuous, deliberate operation, where each stage built directly on the one before it.

The attacker first gained entry through a hidden flaw in a file-transfer service on the Liege services server (INC-2026-001). From that foothold they pivoted to the Brussels application server, took root, and harvested the internal SSH keys belonging to several automated service accounts (INC-2026-002). One of those stolen keys is what connects the second incident to the third: using it, the attacker reached the Liege file server `lge-files-01` (INC-2026-003) without exploiting any flaw at all, simply presenting a legitimate key the system could not distinguish from a trusted service. Once inside, they again obtained root, then installed two means of staying in: a hidden administrator account and a small automated program that quietly contacts an outside server every five minutes.

That automated program is the most urgent concern. It was still running when the incident was reported, meaning an external party had a standing line of communication into NexaCorp's network with access to the Liege file server and its business data. The risk is live, not historical.

The nature of the operation points clearly to a targeted effort: valid internal credentials rather than guessing, a deliberate server-to-server chain, patient steps to stay hidden and durable, and direct targeting of configuration files and stored credentials once inside. This is not the behaviour of an opportunist who stumbled in.

## The three-incident kill chain in three sentences

- **INC-2026-001:** The attacker gained initial entry through a backdoor in the FTP service on the Liege services server.
- **INC-2026-002:** The attacker pivoted to the Brussels application server (`bru-app-01`), escalated to root via a SUID misconfiguration, read the shadow file, created the `it_support` backdoor account, and harvested SSH private keys from service accounts.
- **INC-2026-003:** Using one of those stolen keys (`svc_api`), the attacker returned to the Liege file server (`lge-files-01`) over SSH, escalated to root via a `sudo NOPASSWD` rule on python3, and installed two persistence mechanisms, one of which (a cron-based C2 beacon to 34.251.89.142) was still running at the time of reporting.

The single artefact linking INC-2026-002 to INC-2026-003 is the `svc_api` SSH private key, stolen on `bru-app-01` and reused to authenticate the pivot to `lge-files-01`. See [`methodology/three-incident-kill-chain.md`](methodology/three-incident-kill-chain.md) for the full narrative and [`methodology/attck-mapping.md`](methodology/attck-mapping.md) for the cross-incident ATT&CK matrix.

## INC-2026-003 findings summary

| ID | Severity | Title | Primary MITRE technique |
|---|---|---|---|
| **3.1** | 🟠 HIGH | Lateral movement via reused service-account SSH key | T1552.004, T1021.004, T1078 |
| **3.2** | 🔴 CRITICAL | Privilege escalation via sudo NOPASSWD on python3 (GTFOBins) | T1548.003 |
| **3.3-M1** | 🟠 HIGH | Backdoor local account `sysupdate` (sudo group) | T1136.001 |
| **3.3-M2** | 🔴 CRITICAL | Cron-based C2 beacon to 34.251.89.142 (active at reporting) | T1053.003, T1071.001 |

**Severity distribution:** 2 CRITICAL / 2 HIGH

**Severity model.** Severities are analyst-rated, not CVSS-derived and not Wazuh rule.level-derived. Each rating is a contextual judgement based on three signals: operational impact on NexaCorp, the MITRE ATT&CK technique category, and the current threat state (active versus neutralised). INC-2026-003 is an assessment lab with forensic evidence only, so no live detection-validation telemetry was available. No CVSS vector is computed, because CVSS scores discoverable vulnerabilities, not forensic findings in a post-compromise context.

The cron C2 beacon (3.3-M2) is the most urgent finding: the packet capture confirms four outbound beacons during the attack window, and the channel was still live when the incident was reported, meaning data exfiltration was possible.

## What's different from M02

This engagement is deliberately scoped differently from [INC-2026-002](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002). The distinction matters for an honest read of the work:

| Dimension | INC-2026-002 | INC-2026-003 (this repo) |
|---|---|---|
| Deliverable type | Standalone Mission Findings report | Month 1 Assessment consolidating three incidents |
| Scope | Phase 1 offline forensics **+ Phase 2 live Caldera emulation in Wazuh** | Forensic analysis of the evidence bundle only, **no Phase 2 live phase** |
| Severity basis | Mixed, including Wazuh rule.level signals from live detection | **Analyst-rated only** (impact + technique + threat state), no Wazuh-derived input |
| Detection deliverables | 4 Wazuh rules + auditd config in `detection/` | **None.** No detection-engineering artefacts are in scope for an assessment lab |
| Primary technical theme | SUID privilege escalation + detection tuning | Lateral movement via reused SSH key + standing C2 |

Because this is an assessment lab, there is **no `detection-engineering/` directory, no Wazuh rules, and no auditd configuration** in this repository. That is intentional, not an omission.

## How to read this repository

| If you are a... | Start here | Time |
|---|---|---|
| **Recruiter or hiring manager** | This README + the [PDF](reports/INC-2026-003_Findings_Report.pdf) executive summary | 5 min |
| **SOC analyst evaluating fit** | [PDF](reports/INC-2026-003_Findings_Report.pdf) sections 3 (Findings) and 4 (Kill chain) + [`evidence-summary/ioc-summary.md`](evidence-summary/ioc-summary.md) | 20 min |
| **DFIR practitioner** | Full [PDF](reports/INC-2026-003_Findings_Report.pdf) + [`methodology/attack-timeline.md`](methodology/attack-timeline.md) + [`notes/journal.md`](notes/journal.md) for the investigation trail | 45 min |
| **Anyone who wants to grep, cite, or diff** | [`reports/INC-2026-003_Findings_Report.md`](reports/INC-2026-003_Findings_Report.md) (Markdown source of the report) | as needed |

**Canonical deliverable:** the PDF in [`reports/`](reports/). The [Markdown source](reports/INC-2026-003_Findings_Report.md) is the same content, kept in the repo for searchability and version control.

## Repository layout

```text
NexaCorp-DFIR-INC-2026-003/
├── README.md                                          (this file)
├── LICENSE                                            (MIT)
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml                                     markdownlint + typography validation
├── reports/
│   ├── INC-2026-003_Findings_Report.pdf                canonical 26-page deliverable
│   └── INC-2026-003_Findings_Report.md                 same content, Markdown source
├── methodology/
│   ├── three-incident-kill-chain.md                   cross-incident narrative
│   ├── attack-timeline.md                             minute-by-minute INC-2026-003 timeline
│   └── attck-mapping.md                               standalone cross-incident ATT&CK matrix
├── evidence-summary/
│   └── ioc-summary.md                                 IOCs in SIEM-ingestible format
└── notes/
    └── journal.md                                     analyst investigation notebook
```

**Note on repository structure.** Unlike INC-2026-001 and INC-2026-002, which include a `detection/` folder with a deployed ruleset (Suricata for M01, Wazuh for M02), INC-2026-003 is a forensic-only assessment without a Phase 2 live detection-validation phase. The `methodology/` and `evidence-summary/` folders contain the equivalent analytical outputs for this scope: cross-incident kill chain, attack timeline, ATT&CK mapping, and consolidated IOC summary.

## Methodology

The engagement follows the same industry-standard frameworks as the prior two missions, applied to a forensic-only assessment:

- **NIST SP 800-61r2** (Computer Security Incident Handling Guide): provides the Detection & Analysis structure. This assessment maps to the Detection & Analysis and Post-Incident Activity phases; there is no live Containment/Eradication execution.
- **SANS PICERL**: the Identification stage is the core of the work (log correlation, hypothesis-driven reconstruction). Containment, eradication, and recovery are documented as prioritised recommendations, not executed.
- **MITRE ATT&CK Enterprise v15**: every finding is mapped to one or more techniques, and the cross-incident matrix in [`methodology/attck-mapping.md`](methodology/attck-mapping.md) shows which techniques recur across the three incidents and support single-actor attribution.

### Evidence and timezone handling

Host logs are native CEST (UTC+2); the packet capture is native UTC. All packet-capture times in the report are converted to CEST for narrative consistency, with the native UTC value shown alongside. This was verified, not assumed: `tshark -t ud` confirmed the capture frames carry UTC timestamps, cross-checked against the CEST cron execution in syslog for independent corroboration.

## Tools used

This section is deliberately shorter than the INC-2026-001 and INC-2026-002 equivalents: INC-2026-003 is a forensic-only assessment of a small evidence bundle (258 KB), with no live phase, so the toolset is minimal.

**Packet capture**

- [`tshark`](https://www.wireshark.org/docs/man-pages/tshark.html) (CLI only, no GUI):
  - `tshark -r lab03_capture.pcap -Y "ip.dst == 34.251.89.142" -t ad` to extract the C2 beacons
  - `tshark -r lab03_capture.pcap -Y "ip.dst == 34.251.89.142 && http" -t ud -T fields -e frame.time` to verify the native UTC timezone of the capture

**Log analysis**

- Manual reading plus a basic Unix toolchain (`grep`, `cat`, `wc -l`). The bundle was small enough to read by hand, so no `awk`/`sort`/`uniq` pipelines were required.
- auditd: raw reading of the pre-filtered `audit_filtered.log` provided in the bundle. No `ausearch` or `auditctl` were used.

**Environment**

- `bash` on the BeCode SOC training workstation.
- VS Code and Markdown for notes and report authoring.

No other tooling was used: no `jq`, no custom Python, no timeline framework (plaso/log2timeline), and no Wazuh or Caldera, since INC-2026-003 has no Phase 2 live detection phase.

## Reproducibility

The evidence bundle is BeCode lab property and is not redistributed. Every claim in the report is traceable to a specific log source and timestamp, documented in section 6 of the report and in [`methodology/attack-timeline.md`](methodology/attack-timeline.md), so anyone with their own copy of the bundle can reproduce the analysis.

### Reproduce key findings (log analysis)

Requires the evidence bundle (`auth.log` on bru-app-01; `sshd_journal.log`, `sudo_journal.log`, `audit_filtered.log` on lge-files-01; `pcap/lab03_capture.pcap`):

```bash
# Finding 3.1: pivot via stolen SSH key
# (anomalous publickey from bru-app-01, not the legitimate mon-01 source)
grep "Accepted publickey" lge-files-01/sshd_journal.log | grep -v "192.168.10.200"

# Finding 3.2: privilege escalation signature
# (auid=1000 svc_backup, euid=0 root, key=lab03_exec)
grep 'key="lab03_exec"' lge-files-01/audit_filtered.log

# Finding 3.3-M1: backdoor local account creation
grep -E "useradd|sysupdate" lge-files-01/sudo_journal.log

# Finding 3.3-M2: cron C2 persistence
grep "system-update" lge-files-01/sudo_journal.log

# Network corroboration: C2 beacons in the PCAP
tshark -r pcap/lab03_capture.pcap -Y "ip.dst == 34.251.89.142" -t ad

# Native UTC timezone verification of the PCAP
tshark -r pcap/lab03_capture.pcap -Y "ip.dst == 34.251.89.142 && http" \
  -t ud -T fields -e frame.time

# Attacker preparation on bru-app-01 (key theft sequence)
grep -E "it_support|ssh-keygen|/home/svc_api/.ssh" bru-app-01/auth.log
```

## Known limits

- **Forensic-only scope.** This is an assessment lab with no Phase 2 live detection-validation phase. Severities are analyst-rated (impact, technique category, threat state), not CVSS-derived and not Wazuh rule.level-derived. No live telemetry was available to anchor the ratings on rule firing levels, unlike INC-2026-002.
- **Evidence bundle not redistributed.** The bundle is BeCode lab property. Claims are reproducible by anyone holding their own copy, but the raw logs and packet capture are not published here.
- **Packet capture window.** The capture covers only the attack and persistence window, not the surrounding day. There is no memory acquisition and no filesystem image.
- **C2 payload semantics undetermined.** The beacon sends `GET /update?h=lge-files-01` every five minutes, but the server response (if any) was not captured beyond the four observed beacons. Whether the channel is a presence check, a command channel, or a second-stage download cannot be settled from the bundle.
- **Exfiltration undetermined.** The attacker had root and read access to `/data/config/db-credentials.env` and backup configuration. Whether any of this content left over the C2 channel is not provable from the available evidence.
- **Fleet-wide key reuse not audited.** The svc_api public key was authorised on svc_backup of lge-files-01. A full audit of every `authorized_keys` file across NexaCorp's hosts was out of scope; other hosts may carry the same misconfiguration.
- **Dwell time between incidents.** The `it_support` backdoor on bru-app-01 was never cleaned up after INC-2026-002. Whether the attacker maintained quiet access between the two incidents is not reconstructible from the 24 May logs alone.
- **Lab addressing note.** The IP addressing scheme used in the INC-2026-003 evidence bundle (192.168.10.0/24) differs from the scheme used in earlier mission bundles (notably INC-2026-002, which used 10.10.10.0/24). This reflects independent lab provisioning per mission and does not affect the continuity of the cross-incident narrative: the same logical host bru-app-01 is involved in both incidents, regardless of its lab-assigned IP.

## License

[MIT](LICENSE), 2026 Johan-Emmanuel Hatchi.

The report text and the methodology notes are released under MIT: free to copy, adapt, and reuse with attribution. The evidence bundle, lab infrastructure, and original engagement briefings remain BeCode Brussels property and are not redistributed.

## Acknowledgments

- **Thomas B.** (BeCode lab coach): scenario design, evidence bundle preparation, publication authorization for portfolio use (2026-05-17).
- **MITRE** for the ATT&CK knowledge base used to map every finding.

## About

Solo DFIR assessment delivered during the [BeCode Brussels](https://becode.org) Blue & Red Team bootcamp (November 2025 to September 2026), Mission 03, submitted 2026-05-29.

Author: **Johan-Emmanuel Hatchi**, French national based in Brussels, cybersecurity student at BeCode Brussels (Nov 2025 to Sep 2026), active internship search for September 2026.

[GitHub](https://github.com/Jhatchi) - [LinkedIn](https://www.linkedin.com/in/johan-emmanuel-hatchi/)

Open to cybersecurity internship opportunities starting September 2026 in Belgium. Looking for SOC L1/L2, DFIR junior, or detection engineering roles where this kind of end-to-end work (offline forensics, attacker timeline reconstruction, cross-incident kill chain analysis, formal client reporting) is in scope.
