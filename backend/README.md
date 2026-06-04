# Web Vuln Console – Backend

Node.js backend scanner API. Runs on **Termux (Android)** or any **Linux VPS**.

## Quick Start (Termux)

```bash
pkg update && pkg upgrade
pkg install git nodejs
git clone https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console.git
cd web-vuln-console/backend
npm install
node server.js
```

The API will be live at `http://127.0.0.1:8787`.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8787` | HTTP port |
| `DATA_DIR` | `./data` | Where jobs/results are stored |
| `MAX_CONCURRENT_JOBS` | `1` | Parallel jobs (keep at 1 for phone) |
| `MAX_PARALLEL_TARGETS_PER_JOB` | `3` | Parallel targets per scan |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/scans` | Create scan job |
| GET | `/api/scans` | List jobs (optionally `?projectId=`) |
| GET | `/api/scans/:id` | Get job status |
| GET | `/api/scans/:id/results` | Get findings + logs |
| POST | `/api/scans/:id/cancel` | Cancel a queued/running job |
| GET | `/api/scans/:id/report.html` | Download HTML report |
| GET | `/api/scans/:id/report.md` | Download Markdown report |
| GET | `/api/dorks?domain=` | Generate dork links for a domain |

## AUTHORIZED USE ONLY

This tool is for **authorized security testing** of systems you own or have written permission to test.
