# web-vuln-console

Modular web vulnerability scanner console — env/config/backup/git exposure, SQLi, XSS, path traversal, policy engine, payload library, dork generator, HTML/Markdown reports.

**Stack:** Node.js + Express backend · SQLite (better-sqlite3) · Vanilla JS SPA frontend · Termux / VPS compatible

---

## Wiring Checklist (pending `index.html` + `app.js` batch update)

These backend/logic files are fully built and pushed but are **not yet wired into the frontend**.  
Do them all in one pass when touching `index.html` and `app.js`.

### 🧨 Payload Library (`frontend/payloads.js`)
- [ ] Add `<script src="payloads.js"></script>` to `frontend/index.html` (before closing `</body>`)
- [ ] Call `loadPayloadPage()` inside `app.js` `showPage()` handler for page `'payloads'`

---

## Backend-Only TODOs (no frontend needed — same pattern as Payload Library)

These can be built the same way: **new isolated file + route + mount in server.js**.  
Zero risk of breaking anything existing. Do one at a time.

### 🍪 Cookie / Session Flag Checker (`src/core/checks/cookieSession.js`)
- New file: `src/core/checks/cookieSession.js`
- Checks per `Set-Cookie` header: `HttpOnly`, `Secure`, `SameSite`, `SameSite=None` without `Secure`
- Session ID entropy check + URL-exposed session token detection
- Wire into `engine.js` Phase 1b (2 lines alongside `tlsHeaders`)
- Add `ModuleDef` `cookie.session.flags` to `moduleRegistry.js`
- **Files touched:** new file, `engine.js` (+2 lines), `moduleRegistry.js` (+1 entry)

### 🗺️ Source Map Detector (`src/core/checks/sourceMapDetect.js`)
- New file: `src/core/checks/sourceMapDetect.js`
- For every `.js` URL in SiteModel, probe `url + '.map'`
- If response is valid JSON with `sources` key → flag **critical** (exposes original unminified source)
- Wire into `engine.js` Phase 2.5 (after crawl)
- Add `ModuleDef` `exposure.sourcemap` to `moduleRegistry.js`
- **Files touched:** new file, `engine.js` (+2 lines), `moduleRegistry.js` (+1 entry)

### 🔑 JS Secret Scanner (`src/core/checks/jsSecretScan.js`)
- New file: `src/core/checks/jsSecretScan.js`
- Fetches every `.js` asset URL from SiteModel and regex-scans for:
  - `AKIA` (AWS key), `sk-` (Stripe), `AIza` (Google API), `Bearer` tokens
  - Firebase config objects, GitHub tokens (`ghp_`, `gho_`), raw JWTs (`eyJ`)
- Wire into `engine.js` Phase 2.5 alongside sourceMapDetect
- Add `ModuleDef` `exposure.js.secrets` to `moduleRegistry.js`
- **Files touched:** new file, `engine.js` (+2 lines), `moduleRegistry.js` (+1 entry)

### 💉 Command Injection + SSTI + File Upload (`src/core/injection.js` additions)
- Add `runCommandInjection()` — payloads: `; id`, `& whoami`, `| id`, `` `id` ``, `$(id)` · detect `uid=` / `root` in response
- Add `runSstiChecks()` — payloads: `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>` · detect `49` in response
- Add `runFileUploadDetect()` — find upload forms in SiteModel, probe with benign `.txt` then `.php`/`.jsp`
- Add `ModuleDef`s: `injection.cmdi.basic`, `injection.ssti.basic`, `injection.fileupload.detect`
- Update `policyRegistry.js`: `policy_extreme` enables all three
- **Files touched:** `injection.js` (additions only), `moduleRegistry.js`, `policyRegistry.js`

### 🌐 CIDR / IP Range Expander (`backend/utils/cidrExpand.js`)
- New file: `backend/utils/cidrExpand.js`
- Parses CIDR notation (e.g. `192.168.1.0/24`) → array of IP strings
- Needed by TODO-04 cPanel/WHM IP range scanner
- Pure utility, zero API surface, no routes needed
- **Files touched:** new file only

### 🐛 CVE Passive Checks (additions to `engine.js` Phase 1)
- `checkPhpinfo()` — `/phpinfo.php`, `/info.php`, `/debug`, `/_profiler`
- `checkSvnHg()` — `/.svn/entries`, `/.hg/manifest`
- `checkViteBypass()` — `/@fs/` path bypass, open dev server (CVE-2025-46565 pattern)
- `checkMauticEnv()` — Mautic `.env` web-reachable (CVE-2024-47056 pattern)
- `checkMoodleListing()` — Moodle `r.php` router dir listing (CVE-2025-62396 pattern)
- `checkCloudBuckets()` — S3 / Azure open bucket probe
- `checkWordPressDebug()` — `/wp-config.php.bak`, `debug.log` in `/wp-content/`
- **Files touched:** `engine.js`, `moduleRegistry.js`

---

## Architecture Notes

```
/backend         Express API + SQLite + worker + engine-bridge (standalone scan engine)
/src/core        Modular scan engine (correct long-term architecture)
/frontend        Vanilla JS SPA (app.js ~50KB + page modules)
```

> ⚠️ **Two parallel scan engines exist** (`engine-bridge.js` 44KB vs `src/core/engine.js` 18KB).  
> They are fully independent. Unification is TODO-14 — do last, after all modules are feature-complete.

**Scan Policies:** `policy_normal` (passive) · `policy_aggressive` (+SQLi/XSS) · `policy_extreme` (all modules)  
**DB:** `backend/data/scanner.db` (auto-created, excluded from git)  
**Port:** `7777` default (Termux / VPS)
