# Incident Report 2 - Suspicious Process Execution

**Date:** 2026-08-12
**Analyst:** Simon
**Severity:** High (fill in based on alert output)

## 1. Summary
A process creation event showed an encoded PowerShell command and/or
LOLBin (certutil) usage consistent with a payload download and
execution attempt.

## 2. Detection
Triggered by `detections\Detect-SuspiciousProcess.ps1`.
- Image / ParentImage: <fill in from process-alerts.csv>
- Command line: <fill in>
- Reasons flagged: <fill in>

## 3. MITRE ATT&CK Mapping
T1059 - Command and Scripting Interpreter
T1105 - Ingress Tool Transfer

## 4. Triage
1. Confirm process is not a known-good admin/automation task
2. Check parent process legitimacy (was Office really the parent?)
3. Check for network connections from the flagged process/host
4. Check for follow-on process creation (child processes spawned)

## 5. Containment
- Isolate host from network if confirmed malicious
- Kill the flagged process/process tree
- Collect memory/process artifacts before remediation if feasible
- Block the download URL/domain observed in the command line

## 6. Recommendations
- Restrict script execution policy / enable AMSI logging
- Alert on certutil/mshta/regsvr32 network activity org-wide
