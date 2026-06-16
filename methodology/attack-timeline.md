# Attack Timeline: INC-2026-003

Standalone detailed timeline for INC-2026-003, expanding section 2 of the [Month 1 Assessment Report](../reports/INC-2026-003_Findings_Report.md).

Attack window: Sunday May 24, 2026, 12:31 to 13:05 CEST. All times are CEST unless marked. The network packet capture is recorded natively in UTC; where cited, both the native UTC value and the converted CEST value are shown.

## 1. Attacker preparation on bru-app-01

| Time (CEST) | Source | Event |
|---|---|---|
| 12:31:08 | bru-app-01 auth.log | `it_support` logs in by password from 185.220.101.62 (Tor exit node). Backdoor account from INC-2026-002. |
| 12:31:22 | bru-app-01 auth.log | `sudo /bin/bash` opens an interactive root shell. |
| 12:35:44 | bru-app-01 auth.log | `find /home /root -name id_rsa -o -name authorized_keys`. Locates SSH key material. |
| 12:36:19 | bru-app-01 auth.log | `cat /home/svc_api/.ssh/id_rsa`. Reads the svc_api private key. |
| 12:36:51 | bru-app-01 auth.log | `cat /home/svc_backup/.ssh/authorized_keys`. Confirms which key authorises svc_backup. |
| 12:37:03 | bru-app-01 auth.log | `ssh-keygen -y -f /home/svc_api/.ssh/id_rsa`. Derives the public key to confirm the match. |
| 12:38:29 | bru-app-01 auth.log | `cp /home/svc_api/.ssh/id_rsa /tmp/.cache`. Stages the stolen key for reuse. |

## 2. Pivot to lge-files-01

| Time (CEST) | Source | Event |
|---|---|---|
| 12:39:54 | lge-files-01 sshd_journal.log | Accepted publickey for `svc_backup` from 192.168.10.20 (bru-app-01), key fingerprint `SHA256:Cx3hNuyZt0jgbq25UKWg3kcSA0L9dfgL3OeCHXlJQg4`. This is the svc_api key, not the legitimate svc_backup key. PID 5235. |

## 3. Actions after landing on lge-files-01

| Time (CEST) | Source | Event |
|---|---|---|
| 12:40:08 | sudo_journal.log | `sudo id`. Confirms privileges. |
| 12:40:17 | sudo_journal.log | `sudo cat /etc/sudoers`. Enumerates available sudo rights. |
| 12:40:28 | audit_filtered.log | First `sudo python3` execution. auid=1000 (svc_backup), euid=0 (root). key=`lab03_exec`. |
| 12:40:51 | sudo_journal.log / audit_filtered.log | `sudo python3 -c '...useradd -m -s /bin/bash sysupdate && chpasswd && usermod -aG sudo sysupdate'`. Creates backdoor account. |
| 12:41:00 | sudo_journal.log / audit_filtered.log | `sudo python3 -c '...write /etc/cron.d/system-update...'`. Installs C2 cron job. |
| 12:43:17 | sudo_journal.log | `sudo ls -la /data`. Begins data reconnaissance. |
| 12:43:44 | sudo_journal.log | `sudo ls -la /data/backups`. |
| 12:44:22 | sudo_journal.log | `sudo ls /data/config`. |
| 12:45:09 | sudo_journal.log | `sudo cat /data/config/nexacorp-sync.conf`. Reads sync configuration. |
| 12:47:31 | sudo_journal.log | `sudo find /data -name "*.conf" -o -name "*.env" -o -name "*.key"`. Hunts for secrets. |
| 12:48:55 | sudo_journal.log | `sudo cat /data/config/db-credentials.env`. Reads stored database credentials. |

## 4. Automated C2 activity

| Time | Source | Event |
|---|---|---|
| 12:45:01 CEST (10:45:01 UTC) | pcap | First C2 beacon. `GET /update?h=lge-files-01` to 34.251.89.142 on port 80. |
| 12:50:01 CEST (10:50:01 UTC) | pcap | Second beacon. |
| 12:55:01 CEST (10:55:01 UTC) | pcap | Third beacon. |
| 13:00:01 CEST (11:00:01 UTC) | pcap | Fourth beacon. |

The cron job was written at 12:41:00 and uses a `*/5` schedule. The first beacon at 12:45 confirms the job fired on its first scheduled tick. The network capture corroborates the host evidence from an independent source.

## 5. Detection by NexaCorp

| Time (CEST) | Source | Event |
|---|---|---|
| 14:31:58 | sudo_journal.log | Sysadmin `m.dubois` runs `cat /etc/passwd`. Start of internal discovery. |
| 14:32:44 | sudo_journal.log | `ls -la /etc/cron.d/`. |
| 14:33:12 | sudo_journal.log | `cat /etc/cron.d/system-update`. Reads the malicious cron file. |
| 14:34:05 | sudo_journal.log | `last -n 20`. |
| 14:35:28 | sudo_journal.log | `ss -tunp`. Reviews active connections. |
| 14:36:47 | sudo_journal.log | `grep sysupdate /etc/passwd /etc/shadow /etc/group`. Confirms the backdoor account. |

The interactive attack ended around 12:49. The sysadmin first noticed the compromise at 14:31, roughly one hour and forty minutes after the attacker's hands-on session closed and while the C2 beacon was still firing. There was no real-time detection.
