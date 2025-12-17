# Suricata Lab

Simple local lab to monitor container traffic with Suricata and visualize alerts in Grafana via Loki/Promtail.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Docker Compose Network                    │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐ │
│  │     Loki     │   │   Promtail   │   │ Backend + IDS    │ │
│  │  (Port 3100) │   │ (Log Forward)│   │ Nginx:8080/80    │ │
│  └──────────────┘   └──────────────┘   │ Suricata sidecar │ │
│                                        │ writes ./logs    │ │
│                                        └──────────────────┘ │
│         │                     ▲                  │          │
│         │ push queries        │ tails logs       │          │
│         ▼                     │                  ▼          │
│  ┌──────────────┐             │           ./logs (eve,fast) │
│  │   Grafana    │             │                             │
│  │  (Port 3000) │ ◀───────────┘    query Loki               │
│  └──────────────┘                                           │
└─────────────────────────────────────────────────────────────┘

Host → http://localhost:8080 → Backend (Nginx) — observed by Suricata (shares backend netns)
```

## Features

- Nginx backend (HTTP on localhost:8080)
- Suricata as sidecar (sniffs backend `eth0` via `network_mode: service:backend`)
- Custom Suricata rules (`test.rules`)
- Logs persisted under `logs/` (`eve.json`, `fast.log`, `stats.log`, `suricata.log`)
- Loki + Promtail for log aggregation
- Grafana (auto-provisioned Loki datasource and a basic Suricata dashboard)
- Node.js script to trigger sample alerts

## Prerequisites

- Docker and Docker Compose
- Node.js (for the test script)

## Quick Start

```bash
cd suricata-lab
docker compose down -v && docker compose up -d
```

Generate test traffic:

```bash
node scripts/trigger_rules.js
```

View raw logs:

```bash
tail -n 100 logs/fast.log
grep -n '"event_type":"alert"' logs/eve.json | tail -n 20
```

Open Grafana:

- URL: http://localhost:3000
- User/Pass: admin / admin
- Dashboard: Suricata → Suricata Overview

## Testing (scripts/trigger_rules.js)

- Generic GET (sid 100001)
- SQLi
  - Tautology "' or 1=1" (sid 100010)
  - UNION SELECT via "unionselect 1,2,3" (sid 100011)
- XSS
  - <script> tag (sid 100020)
  - javascript: URI (sid 100021)
- Command Injection (CMDi)
  - `;curl http://example.com` (sid 100030)
  - `;wget http://example.com/file` (sid 100031)
  - `&&` operator (sid 100032)
- LFI
  - `../../etc/passwd` traversal (sid 100040)
- Admin Endpoint
  - `/admin` access (sid 100050)
- Scanner User-Agents
  - sqlmap, Nikto, nmap, gobuster, dirbuster (sid 100060–100064)
- Rate Threshold
  - ≥20 requests/min burst (sid 100070)
- Anomaly
  - Long URI > 2048 chars (sid 100080)

## Repository Layout

- `docker-compose.yml` — all services
- `test.rules` — Suricata rules (HTTP, SQLi, XSS, CMDi, LFI, admin, scanners, threshold, long URI)
- `logs/` — Suricata outputs (mounted into the Suricata container)
- `scripts/trigger_rules.js` — Node script to simulate HTTP attacks/behaviors
- `site/` — Static content served by Nginx (port 8080)
- `loki-config.yml` — Loki config (filesystem storage; WAL under `/loki/wal`)
- `promtail-config.yml` — Promtail config (scrapes `eve.json`, `fast.log`)
- `grafana/provisioning/` — Auto-provision Loki datasource and dashboards
- `grafana/dashboards/suricata-overview.json` — Basic dashboard

## Rules Summary (test.rules)

- Baseline: TCP dst port 80 (sid 100000)
- HTTP Generic: GET request (sid 100001)
- SQLi: tautology "' or 1=1" (sid 100010), UNION SELECT (sid 100011)
- XSS: `<script>` (sid 100020), `javascript:` (sid 100021)
- CMDi: `;curl` (sid 100030), `;wget` (sid 100031), `&&` (sid 100032)
- LFI/RFI: traversal to `/etc/passwd` (sid 100040)
- Admin: access to `/admin` (sid 100050)
- Recon/Scanners: sqlmap, nikto, nmap, gobuster, dirbuster UAs (sid 100060–100064)
- Threshold: ≥20 req/min burst (sid 100070)
- Anomaly: long URI > 2048 chars (sid 100080)

## Cleaning Up

```bash
docker compose down -v
```
