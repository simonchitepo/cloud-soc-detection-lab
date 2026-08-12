# Week 1 Review - First Detection Notes

## What was built
- Repo scaffolded and pushed to GitHub
- SIEM lab options documented (Wazuh via Docker, or local scripted lab)
- Baseline Windows Security/System logs collected
- Simulated: failed logins (auth-failures.csv), port scan (portscan.csv),
  suspicious process creation (process-events.csv)

## Early observations (fill these in as you look at the CSVs)
- auth-failures.csv: one source IP (203.0.113.55) generating repeated
  4625 failures against 'administrator' in a short window - classic
  brute-force shape.
- portscan.csv: same source IP hitting a sequential/varied set of
  ports on one host in a short time - classic scan shape.
- process-events.csv: certutil + encoded PowerShell = living-off-the-
  land techniques worth alerting on regardless of parent process.

## Next up (Week 2)
Turn these observations into actual detection logic (Mon/Tue), map
them to MITRE ATT&CK (Wed), then write incident reports (Thu/Fri).
