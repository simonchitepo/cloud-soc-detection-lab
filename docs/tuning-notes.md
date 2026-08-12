# Detection Tuning Notes

## Detect-BruteForce.ps1
- False positive risk: legitimate users mistyping passwords repeatedly,
  shared service accounts with expired credentials still in use.
- Tuning ideas:
  - Exclude known internal IP ranges from the 'attacker' bucket, or
    lower severity (not suppress) for internal sources.
  - Require a mix of usernames tried (spray) OR high volume against
    one account (guessing) rather than one flat threshold.
  - Correlate with a later successful logon from the same IP - raise
    severity sharply if one exists (possible successful compromise).

## Detect-SuspiciousProcess.ps1
- False positive risk: legitimate IT/security tooling uses certutil,
  admins occasionally run encoded PowerShell for legitimate remote
  management (e.g. some RMM tools).
- Tuning ideas:
  - Maintain an allowlist of known internal automation hashes/paths.
  - Weight severity by combination of signals rather than any single
    match (e.g. encoded command line ALONE = low, encoded command
    line + unusual parent = high).
  - Add a time-of-day / off-hours factor - same activity at 3am is
    more suspicious than during business hours.

## General
- Every rule in this lab is intentionally simple/threshold-based -
  good for demonstrating detection logic, but a production SIEM
  rule would also incorporate baselining and enrichment (asset
  criticality, user risk score, threat intel feeds).
