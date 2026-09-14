# Sigma Detection Rule Project — Brute Force Logon Detection (Wazuh)

## What this project is

A hands-on detection engineering project: write a vendor-neutral Sigma rule for a real attack behaviour, convert it to a working detection in a SIEM, deploy it, prove it actually fires, then tune out false positives.

This isn't a simulated "textbook" detection — it's built off a **real behaviour I've personally observed**: repeated failed logon attempts (Windows Event ID 4625) hitting an internet-exposed VM I previously ran on Azure.

## Why Wazuh instead of a cloud SIEM

This project originally targeted Microsoft Sentinel, since that's the SIEM I've used in my other labs. I switched to **Wazuh** (free, self-hosted, runs locally via Docker) for this specific project so it:
- Costs nothing to run or leave set up
- Is fully reproducible by anyone cloning this repo — no cloud account or workspace required
- Still demonstrates the same core skill: writing Sigma, converting it, proving it fires, tuning it

## Status: Infrastructure up and running ✅

Currently working through this build in stages. Progress so far:

- [x] Docker Desktop installed and running (Mac, Apple Silicon)
- [x] Wazuh single-node stack deployed via Docker Compose (manager, indexer, dashboard)
- [x] Resolved a chain of SSL/certificate issues in the Docker Compose cert generation process (see notes below — this ate more time than expected, but taught me a lot about how Wazuh's manager/indexer/dashboard trust each other)
- [x] Dashboard accessible and logged in (`https://localhost`)
- [x] Manager API connection confirmed **Online** in the dashboard's Server APIs page

**Next up:**
- [ ] Install a Wazuh agent (on host or lab VM) to generate real log data
- [ ] Write the Sigma rule for repeated 4625 failed logons
- [ ] Convert the rule to Wazuh's format using `sigma-cli`
- [ ] Deploy it, trigger the behaviour, and screenshot the alert firing
- [ ] Tune out false positives and document the reasoning

## Notable troubleshooting (the unglamorous part)

Getting the Wazuh Docker stack stable took real debugging, not just following a tutorial:

- **Missing `vm.max_map_count`** — OpenSearch (which the Wazuh indexer runs on) needs a higher memory-mapped area limit than Docker's Mac VM ships with by default.
- **Cert generation on Apple Silicon** — `justincormack/nsenter1` (a common fix for the above) doesn't run properly on ARM; swapped to an Alpine + `nsenter` one-liner instead.
- **Directories instead of files** — Docker will silently create empty directories at any bind-mount path that doesn't exist yet, rather than erroring. This happened repeatedly during cert generation (`root-ca.pem`, `root-ca-manager.pem`, and others were briefly directories instead of files), which caused the indexer, dashboard, and eventually the manager to crash-loop with `EACCES` or `is a directory` errors.
- **`root-ca-manager.pem`/`.key`** — the single-node cert generator fails to produce these two files due to a permissions quirk, but the manager's Filebeat config still expects them to exist. Fixed by copying the root CA cert/key into place under the expected filename.

Documenting this because "why did the container keep crash-looping" is exactly the kind of debugging a Detection Engineer / SOC role expects — reading logs, isolating a root cause, and not just restarting things and hoping.

## Tech stack

- Wazuh 4.9.2 (manager, indexer, dashboard) — Docker Compose, single-node
- Sigma / sigma-cli for vendor-neutral detection rule authoring
- Docker Desktop on macOS (Apple Silicon, running images under amd64 emulation)

## Author

Shino Shamit — [github.com/shinoshamit25-afk](https://github.com/shinoshamit25-afk) · [shinoshamit.online](https://shinoshamit.online)
