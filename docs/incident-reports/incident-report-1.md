# Incident Report 1 - Brute Force Attempt

**Date:** 2026-08-12
**Analyst:** Simon
**Severity:** Medium/High (fill in based on alert output)

## 1. Summary
Repeated failed authentication attempts (Event ID 4625) were observed
from source IP 203.0.113.55 against the 'administrator' account,
consistent with an automated brute-force attempt.

## 2. Detection
Triggered by `detections\Detect-BruteForce.ps1`.
- Failed attempts: <fill in from brute-force-alerts.csv>
- Time window: <fill in>
- Target account(s): <fill in>

## 3. MITRE ATT&CK Mapping
T1110 - Brute Force (Credential Access)

## 4. Analysis
<Describe what the pattern indicates - single-stage credential
guessing vs. spray across multiple accounts, whether the source IP
has any other activity in the log set (cross-reference portscan.csv),
whether the account was ever successfully authenticated.>

## 5. Containment / Response Actions
- Block/rate-limit source IP at the firewall
- Force password reset if any related account shows a later success
- Enable/verify account lockout policy
- Add source IP to a watchlist

## 6. Recommendations
- Alert threshold tuning (see docs/tuning-notes.md)
- Consider geo-IP or reputation enrichment on SourceIp
