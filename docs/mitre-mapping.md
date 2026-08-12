# MITRE ATT&CK Mapping

| Detection                  | Technique ID | Technique Name                        | Tactic              |
|-----------------------------|--------------|----------------------------------------|----------------------|
| Detect-BruteForce.ps1       | T1110        | Brute Force                            | Credential Access    |
| Detect-SuspiciousProcess.ps1| T1059        | Command and Scripting Interpreter      | Execution            |
| Detect-SuspiciousProcess.ps1| T1105        | Ingress Tool Transfer                  | Command and Control  |
| Simulate-PortScan.ps1       | T1046        | Network Service Discovery              | Discovery            |

Reference: https://attack.mitre.org/

## Notes
- Brute-force detection maps cleanly to a single technique (T1110) because
  the behaviour (repeated failed auths) is unambiguous.
- The process detection rule covers two techniques because 'suspicious
  process creation' is really a detection *category* - LOLBin abuse
  (download via certutil) is closer to T1105, encoded PowerShell
  execution is T1059.
- Port scanning (T1046) wasn't turned into an automated detection rule
  in this build - documented here as a gap/possible future addition:
  detect >N distinct ports touched by one source IP in a short window.
