# Cloud SOC Detection Lab (Project 3)

A hands-on SOC lab: simulate attacker behaviour on a local machine,
collect the resulting log/event data, write detection logic against
it, map detections to MITRE ATT&CK, and produce incident reports -
the full SOC analyst workflow end to end.

## Structure
- `simulations/` - scripts that generate synthetic attacker activity/log data
- `detections/` - scripts that parse the logs and flag malicious patterns
- `logs/` - raw and sample log data (git-ignored by default)
- `docs/` - MITRE mapping, incident reports, tuning notes, weekly reviews
- `lab-setup/` - notes on the SIEM lab (Wazuh/Elastic/Sentinel)

## Build log
See `docs/weekly-reviews/` for progress notes and
`PROJECT3-EXPLAINED.md` for a full walkthrough of every step.
