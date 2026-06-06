# web-vuln-console

Modular web vulnerability scanner console — env/config/backup/git exposure, SQLi, XSS, path traversal, CVE fingerprints, cPanel/WHM IP sweep, Laravel .env hunter, policy engine, dork generator, HTML/Markdown reports.

**Stack:** Node.js + Express backend · SQLite (better-sqlite3) · Vanilla JS SPA frontend · Termux / VPS compatible  
**Engine:** `src/core/engine.js` v1.7.0 · 16 ModuleDefs · 6 scan phases  
**Port:** `7777` default

---

## ✅ Completed Work — Commit Log

### Session: June 6 2026

| # | Commit | What landed |
|---|--------|-------------|
| 1 | [`0cbbfe9`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/0cbbfe9e1159b3bc301183b48cfaf1eb400dcd4a) | **TODO-04 · File 1/2** — `backend/utils/cidrExpand.js` (CIDR/dash-range/IP/hostname expander, 1024-host cap) + `src/core/checks/cPanelWhm.js` (CVE-2026-41940 scanner, 6 ports × 7 paths, header+body fingerprint, version extraction, RCE annotation) |
| 2 | [`c2bc56f`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/c2bc56fdb8b6d8f7c514dc83c202c44fea9fcf11) | **TODO-04 · File 2/2** — `engine.js` v1.5.0 Phase 1d wired + `moduleRegistry.js` `exposure.cve.cpanel_whm` ModuleDef added |
| 3 | [`28af739`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/28af7395dc8e7145067b2129499b3d1e548790db) | **TODO-05 · File 1/3** — `src/core/checks/laravelEnv.js` (520 lines — 56 probe paths across 7 categories, 50+ secret patterns, APP\_KEY entropy + RCE analysis, cloud DB risk scoring, Laravel fingerprinting, debug mode detection, composer.lock recon, severity escalation matrix) |
| 4 | [`c7c94ff`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/c7c94ffe0e2e82fc75951bc5d8694a23d01b0dde) | **TODO-05 · File 2/3** — `moduleRegistry.js` `exposure.cve.laravel_env_hunt` ModuleDef added (CVE-2024-55556 / CVE-2025-70841, 4 CWE tags, full configSchema) |
| 5 | [`015ea73`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/015ea739d082ba15a648008ead5625b5c1ae3166) | **TODO-05 · File 3/3** — `engine.js` v1.7.0 Phase 1f `runLaravelEnvHunt` wired |

### Pre-session (previously completed)

| Module | File | Status |
|--------|------|--------|
| `tls.headers.basic` | `src/core/checks/tlsHeaders.js` | ✅ Done |
| `cookie.session.flags` | `src/core/checks/cookieSession.js` | ✅ Done |
| `exposure.js.secrets` | `src/core/checks/jsSecretScan.js` | ✅ Done |
| `exposure.sourcemap` | `src/core/checks/sourceMapDetect.js` | ✅ Done |
| `cve.fingerprints` | `src/core/checks/cveFingerprints.js` | ✅ Done |
| Full backend API (22 routes) | `backend/server.js` | ✅ Done |
| SQLite DB layer | `backend/db.js` | ✅ Done |
| Dork engine | `backend/dorkEngine.js` | ✅ Done |
| Report generator | `backend/reportGenerator.js` | ✅ Done |
| Frontend SPA shell | `frontend/app.js` + `index.html` + `style.css` | ✅ Done |
| Findings list view | `src/ui/views/findingsListView.js` | ✅ Done |
| Job console view | `src/ui/views/jobConsoleView.js` | ✅ Done |
| Project list view | `src/ui/views/projectListView.js` | ✅ Done |

---

## 📦 Current Module Registry — 16 ModuleDefs

| ID | Name | Class | Severity | Phase |
|----|------|-------|----------|-------|
| `exposure.env.direct` | Direct .env Exposure | passive | critical | 1 |
| `exposure.env.variants` | .env Variant Exposure | passive | critical | 1 |
| `exposure.backup.db_dumps` | Database Backup Files | passive | critical | 1 |
| `exposure.backup.archives` | Archive Backup Files | passive | high | 1 |
| `misconfig.dirlisting.generic` | Directory Listing Detection | passive | medium | 1 |
| `vcs.git.exposed` | Exposed .git Repository | passive | high | 1 |
| `debug.stacktraces` | Verbose Error & Stack Trace Detection | passive | medium | 1 |
| `exposure.js.secrets` | JavaScript Asset Secret Scanner | passive | critical | 2.5a |
| `exposure.sourcemap` | JavaScript Source Map Exposure | passive | critical | 2.5b |
| `cookie.session.flags` | Cookie & Session Security Checks | passive | high | 1c |
| `exposure.cve.cpanel_whm` | cPanel & WHM Panel Exposure (CVE-2026-41940) | passive | critical | 1d |
| `exposure.cve.laravel_env_hunt` | Laravel .env Exposure & Secret Extraction | passive | critical | 1f |
| `cve.fingerprints` | CVE Fingerprint Checks (2025–2026) | passive | high | 1e |
| `injection.sqli.basic` | Basic SQL Injection Probes | active | high | 3 |
| `injection.xss.reflected_basic` | Reflected XSS Probes | active | medium | 3 |
| `injection.path_traversal.basic` | Path Traversal / Local File Read | active | critical | 3 |

---

## 🛠️ Engine Phase Map (v1.7.0)

```
Phase 1    runPassiveExposureChecks()
             ├─ exposure.env.direct
             ├─ exposure.env.variants
             ├─ exposure.backup.db_dumps
             ├─ exposure.backup.archives
             ├─ misconfig.dirlisting.generic
             ├─ vcs.git.exposed
             └─ debug.stacktraces

Phase 1b   runTlsHeaderChecks()        tls.headers.basic
Phase 1c   runCookieSessionChecks()    cookie.session.flags
Phase 1d   runCPanelWhmScan()          exposure.cve.cpanel_whm
Phase 1e   runCveFingerprints()        cve.fingerprints
Phase 1f   runLaravelEnvHunt()         exposure.cve.laravel_env_hunt

Phase 2    crawlTargetAndBuildSiteModel()   maxDepth:2  maxPages:30

Phase 2.5a runJsSecretScan()           exposure.js.secrets
Phase 2.5b runSourceMapDetect()        exposure.sourcemap

Phase 3    runActiveInjectionChecks()
             ├─ injection.sqli.basic
             ├─ injection.xss.reflected_basic
             └─ injection.path_traversal.basic
```

---

## 📋 TODO List — Ordered by Priority

### 🟢 TIER 1 — New Engine Check Files (zero breakage risk)

- [x] **TODO-01** `src/core/checks/cookieSession.js` — Cookie security checker (HttpOnly, Secure, SameSite, entropy)
- [x] **TODO-02** `src/core/checks/jsSecretScan.js` — JS asset secret scanner
- [x] **TODO-03** `src/core/checks/sourceMapDetect.js` — Source map exposure detector
- [x] **TODO-04** `src/core/checks/cPanelWhm.js` + `backend/utils/cidrExpand.js` — cPanel/WHM CVE-2026-41940 IP range scanner
- [x] **TODO-05** `src/core/checks/laravelEnv.js` — Advanced Laravel .env hunter (56 paths, 50+ secrets, APP\_KEY RCE analysis)

### 🟡 TIER 2 — CVE Pattern Checks

- [ ] **TODO-06** Additional CVE passive checks — edit `engine.js` + `moduleRegistry.js`
  - `checkPhpinfo()` — `/phpinfo.php`, `/info.php`, `/debug`, `/_profiler`
  - `checkSvnHg()` — `/.svn/entries`, `/.hg/manifest`
  - `checkViteBypass()` — `/@fs/` path bypass, open dev server (CVE-2025-46565)
  - `checkMauticEnv()` — Mautic `.env` web-reachable (CVE-2024-47056)
  - `checkMoodleListing()` — Moodle `r.php` dir listing (CVE-2025-62396)
  - `checkCloudBuckets()` — S3 / Azure open bucket probe
  - `checkWordPressDebug()` — `/wp-config.php.bak`, `debug.log` in `/wp-content/`

### 🟠 TIER 3 — Injection.js Additions

- [ ] **TODO-07** `src/core/injection.js` additions
  - `runCommandInjection()` — OS command injection via form params
  - `runSstiChecks()` — template injection `{{7*7}}` etc.
  - `runFileUploadDetect()` — detect upload forms, probe `.php`/`.jsp` extensions
  - New ModuleDefs: `injection.cmdi.basic`, `injection.ssti.basic`, `injection.fileupload.detect`
  - Update `policyRegistry.js`: `policy_extreme` enables all three

### 🔵 TIER 4 — Backend Fixes

- [ ] **TODO-08** Persist jobs to SQLite — edit `backend/db.js` + `backend/jobsStore.js`
  - Add `jobs` table (id, project\_id, status, policy\_id, targets\_json, created\_at, result\_json)
  - Update `jobsStore.js` to read/write SQLite instead of in-memory Map
  - Zero API changes — `server.js` routes unchanged
  - **Fixes:** job metadata lost on server restart

### 🟣 TIER 5 — Frontend / UI

- [ ] **TODO-09** `src/ui/views/dashboardView.js` — wire to `GET /api/stats` (currently 633-byte skeleton with no real data)
- [ ] **TODO-10** Report generation UI — wire “Generate Report” button → `GET /api/scans/:jobId/report`, verify `frontend/report.js` import
- [ ] **TODO-11** Finding detail side-panel in `findingsListView.js` — slide-in panel with evidence snippet, OWASP/CWE tags, status changer
- [ ] **TODO-12** `src/ui/views/targetsView.js` — NEW FILE — per-project target list, bulk paste, env tag, IP range input field
- [ ] **TODO-13** `src/ui/views/policyView.js` — NEW FILE — policy editor UI
- [ ] `src/ui/views/settingsView.js` — NEW FILE (was in original design spec)
- [ ] `src/ui/views/modulesView.js` — NEW FILE (was in original design spec)
- [ ] `src/ui/views/projectDetailView.js` — NEW FILE (was in original design spec)

### ⚠️ TIER 6 — Big Structural Change (do last)

- [ ] **TODO-14** Unify dual scan engines — make `backend/engine-bridge.js` a thin adapter that imports `runScanJob` from `src/core/engine.js` instead of being its own 44KB standalone engine

---

## ⚠️ Known Gaps & Warnings

| Issue | Status |
|-------|--------|
| **Dual scan engines** — `engine-bridge.js` (44KB) and `src/core/engine.js` (18KB) are completely independent | Tracked as TODO-14, do last |
| **Jobs not persisted** — `jobsStore.js` is pure in-memory Map, restart loses all job metadata | Tracked as TODO-08 |
| **dashboardView.js is a skeleton** — 633 bytes, zero API calls, no real data displayed | Tracked as TODO-09 |
| **5 UI views missing** — `targetsView`, `policyView`, `settingsView`, `modulesView`, `projectDetailView` | Tracked as TODO-12/13 |
| **`frontend/report.js`** — file exists but import into `app.js` unverified | Check during TODO-10 |
| **CVE-2026-41940 advisory** — was under embargo at time of writing `cPanelWhm.js`; validate against NVD/SentinelOne before using in reports | Verify before client use |

---

## Architecture

```
/backend             Express API + SQLite + worker + engine-bridge (standalone)
  server.js          22 API routes
  db.js              SQLite schema + query helpers
  engine-bridge.js   Standalone scan engine (44KB) — NOT YET unified with src/core
  dorkEngine.js      Google + GitHub dork generator
  reportGenerator.js HTML + Markdown report builder
  utils/
    cidrExpand.js    CIDR/IP range expander (new — TODO-04)
    normalize.js
    retry.js
    severityScore.js

/src/core            Modular scan engine (correct long-term architecture)
  engine.js          v1.7.0 — orchestrates all phases
  crawler.js         HTML crawl, SiteModel builder
  injection.js       SQLi + XSS + path traversal
  moduleRegistry.js  16 ModuleDefs
  policyRegistry.js  3 policies (normal / aggressive / extreme)
  checks/
    tlsHeaders.js        Phase 1b
    cookieSession.js     Phase 1c
    cPanelWhm.js         Phase 1d  (TODO-04)
    cveFingerprints.js   Phase 1e
    laravelEnv.js        Phase 1f  (TODO-05)
    jsSecretScan.js      Phase 2.5a
    sourceMapDetect.js   Phase 2.5b

/src/ui              Frontend view modules
  views/
    findingsListView.js    ✅ real data
    jobConsoleView.js      ✅ real data
    projectListView.js     ✅ real data
    dashboardView.js       ⚠️ SKELETON — TODO-09
    targetsView.js         ❌ MISSING — TODO-12
    policyView.js          ❌ MISSING — TODO-13
    settingsView.js        ❌ MISSING
    modulesView.js         ❌ MISSING
    projectDetailView.js   ❌ MISSING

/frontend            Compiled SPA assets
  app.js             ~50KB core SPA logic
  index.html         Terminal console UI shell
  style.css          Cyberpunk terminal theme
  report.js          Report UI module (import unverified)
```

**Scan Policies:**  
`policy_normal` — passive checks only  
`policy_aggressive` — + SQLi / XSS  
`policy_extreme` — all modules including active injection

**DB:** `backend/data/scanner.db` (auto-created, excluded from git)
