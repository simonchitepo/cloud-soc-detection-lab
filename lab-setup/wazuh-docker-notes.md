# SIEM Lab Notes

## Option 1 - Wazuh via Docker (recommended if Docker Desktop is installed)
Docs: https://documentation.wazuh.com/current/deployment-options/docker/index.html

Commands (run in PowerShell, Docker Desktop must be running):
    git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
    cd wazuh-docker/single-node
    docker compose -f generate-indexer-certs.yml run --rm generator
    docker compose up -d

Wazuh dashboard: https://localhost:443  (default user: admin)

## Option 2 - No Docker available
This lab still works without a full SIEM install. We generate log
data locally (simulations/) and write our own detection scripts
(detections/) against it in PowerShell - this mirrors exactly what
a SIEM detection rule does, just without the infrastructure
overhead. If you later stand up Wazuh/Elastic, you can re-ingest
the same log files as a follow-up project.

## Decision for this build
Recording which option you actually used and why goes here once
you've decided - e.g. "Used Option 2 due to hardware constraints,
Wazuh install documented for future iteration."
