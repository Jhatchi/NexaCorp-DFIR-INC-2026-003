# Indicators of Compromise: INC-2026-003

Key indicators of compromise extracted from section 6.2 of the [Month 1 Assessment Report](../reports/INC-2026-003_Findings_Report.md), presented in a format suitable for ingestion into a SIEM or threat-intel platform.

> **Lab notice.** INC-2026-003 is a fictitious BeCode lab scenario against isolated infrastructure. Every value below is a lab-local artefact, not real-world threat intelligence. Do not feed these indicators to a production SIEM as live IOCs. The Tor exit nodes referenced are public infrastructure used in the scenario storytelling and are not associated with any real campaign.

## Network indicators

| Type | Value | Context |
|---|---|---|
| IPv4 | 34.251.89.142 | C2 server contacted by the cron beacon |
| IPv4 | 185.220.101.62 | Tor exit node, it_support login source |
| IPv4 | 185.220.101.47 | Tor exit node, related scanning activity |
| HTTP request | `GET /update?h=lge-files-01` | Beacon pattern to the C2 server (port 80) |

## Host indicators

| Type | Value | Context |
|---|---|---|
| File path | `/etc/cron.d/system-update` | Malicious cron persistence |
| File path | `/tmp/.update.log` | Local beacon marker |
| File path | `/tmp/.cache` | Staged stolen private key on bru-app-01 |
| Account | `sysupdate` | Backdoor local account, sudo group |
| Credential | `[REDACTED-lab-credential]` | Password set on the sysupdate account |
| SSH key fingerprint | `SHA256:Cx3hNuyZt0jgbq25UKWg3kcSA0L9dfgL3OeCHXlJQg4` | Stolen svc_api key used for the pivot |

## Detection and containment quick reference

- Block 34.251.89.142 outbound at the perimeter firewall to sever the C2 channel.
- Alert on file creation under `/etc/cron.d/` and on `sudo` use of interpreters (`python3`, `perl`, `awk`) by service accounts.
- Alert on SSH publickey logins for service accounts originating from unexpected internal hosts or presenting an unexpected key fingerprint.
- Hunt for the `sysupdate` account in `/etc/passwd`, `/etc/shadow`, and `/etc/group`.

Full containment and eradication steps are in section 5 of the [report](../reports/INC-2026-003_Findings_Report.md).
