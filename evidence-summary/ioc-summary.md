# Indicators of compromise (INC-2026-003)

Key indicators of compromise extracted from section 6.2 of the [Month 1 Assessment Report](../reports/INC-2026-003_Findings_Report.md), presented in a format suitable for ingestion into a SIEM or threat-intel platform.

> **Lab notice.** INC-2026-003 is a fictitious BeCode lab scenario against isolated infrastructure. Every value below is a lab-local artefact, not real-world threat intelligence. Do not feed these indicators to a production SIEM as live IOCs. The Tor exit nodes referenced are public infrastructure used in the scenario storytelling and are not associated with any real campaign.

## Network indicators

| Indicator | Type | Context |
|---|---|---|
| 34.251.89.142 | IPv4 | C2 server contacted by the cron beacon |
| 185.220.101.62 | IPv4 | Tor exit node, it_support login source |
| 185.220.101.47 | IPv4 | Tor exit node, related scanning activity |
| `GET /update?h=lge-files-01` | HTTP request | Beacon pattern to the C2 server (port 80) |

## Host indicators

| Indicator | Type | Context |
|---|---|---|
| `/etc/cron.d/system-update` | File path | Malicious cron persistence |
| `/tmp/.update.log` | File path | Local beacon marker |
| `/tmp/.cache` | File path | Staged stolen private key on bru-app-01 |
| `sysupdate` | Account | Backdoor local account, sudo group |
| `Backd00r!` | Credential | Password set on the sysupdate account |
| `SHA256:Cx3hNuyZt0jgbq25UKWg3kcSA0L9dfgL3OeCHXlJQg4` | SSH key fingerprint | Stolen svc_api key used for the pivot |

## Detection and containment quick reference

- Block 34.251.89.142 outbound at the perimeter firewall to sever the C2 channel.
- Alert on file creation under `/etc/cron.d/` and on `sudo` use of interpreters (`python3`, `perl`, `awk`) by service accounts.
- Alert on SSH publickey logins for service accounts originating from unexpected internal hosts or presenting an unexpected key fingerprint.
- Hunt for the `sysupdate` account in `/etc/passwd`, `/etc/shadow`, and `/etc/group`.

Full containment and eradication steps are in section 5 of the [report](../reports/INC-2026-003_Findings_Report.md).
