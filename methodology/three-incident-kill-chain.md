# Three-incident kill chain (INC-2026-001 to INC-2026-003)

This note is the standalone kill chain narrative that underpins section 4 of the [Month 1 Assessment Report](../reports/INC-2026-003_Findings_Report.md). It explains how three incidents reported across three weeks at NexaCorp Industries form a single, continuous operation by one external attacker.

## The chain in three sentences

- **INC-2026-001:** The attacker gained initial entry through a backdoor in the FTP service on the Liege services server.
- **INC-2026-002:** The attacker pivoted to the Brussels application server (`bru-app-01`), escalated to root through a SUID misconfiguration, read the shadow file, created the `it_support` backdoor account, and harvested SSH private keys from service accounts.
- **INC-2026-003:** Using one of those stolen keys (`svc_api`), the attacker returned to `lge-files-01` over SSH, escalated to root through a `sudo NOPASSWD` rule on python3, and installed two persistence mechanisms (the `sysupdate` backdoor account and a cron-based C2 beacon to 34.251.89.142).

## The connecting questions

1. **Where did the attacker first gain access?** Through the backdoor in the FTP service on the Liege services server (INC-2026-001).
2. **What did INC-2026-002 provide that enabled INC-2026-003?** Root control of `bru-app-01`, the `it_support` backdoor account, and harvested SSH private keys from service accounts.
3. **What artefact links the two incidents?** The `svc_api` SSH private key (`/home/svc_api/.ssh/id_rsa`), stolen on `bru-app-01` during the INC-2026-002 follow-on activity and reused to authenticate the pivot in INC-2026-003.
4. **What connects all three incidents to the same actor?** A consistent operating pattern: use of Tor exit nodes in the 185.220.101.x range, reuse of valid service-account credentials, abuse of privilege-escalation misconfigurations (SUID then sudo), and cron-based HTTP persistence. The same technique fingerprints recur across incidents.
5. **When was external command-and-control established?** At 12:41:00 CEST on May 24, when the cron beacon was written. Before that moment the attacker operated interactively over SSH; the cron job marks the transition to an automated, standing C2 channel, with the first beacon confirmed at 12:45 CEST.

## Why this is one operation, not three coincidences

Each incident consumed the output of the previous one. INC-2026-001 gave the attacker a foothold and the opportunity to harvest material. INC-2026-002 produced the specific asset (the `svc_api` private key) that made INC-2026-003 possible without exploiting any new vulnerability. In INC-2026-003 the attacker did not break in; they presented a legitimate key that a misconfigured `authorized_keys` file accepted, then escalated through a second misconfiguration and established standing C2.

The behavioural signature is consistent throughout: valid credentials over guessing, deliberate host-to-host chaining in a logical sequence, and patient steps to remain hidden and durable. This is targeted activity by an actor who understood the environment, not opportunistic background noise.

See [`attack-timeline.md`](attack-timeline.md) for the minute-by-minute INC-2026-003 sequence and [`attck-mapping.md`](attck-mapping.md) for the cross-incident MITRE ATT&CK matrix.
