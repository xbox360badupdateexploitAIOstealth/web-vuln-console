# web-vuln-console

Modular web vulnerability scanner console — env/config/backup/git exposure, SQLi, XSS, path traversal, SSRF,
open redirect, CORS, admin panel detection, tech fingerprinting, CVE fingerprints, cPanel/WHM IP sweep,
Laravel .env hunter, command injection, SSTI, file upload detection, policy engine, dork generator,
HTML/Markdown reports.

**Stack:** Node.js + Express backend · SQLite (better-sqlite3) · Vanilla JS SPA frontend · Termux / VPS compatible  
**Engine:** `src/core/engine.js` v1.7.0 (v2.0.0 pending engine wiring) · 27+ ModuleDefs · 8 scan phases  
**Port:** `7777` default

---

## ✅ Complete Commit Log — All Sessions

### June 4 2026 — Initial Build

| # | Commit | What landed |
|---|--------|-------------|
| 1 | [`6a97885`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/6a9788526cbf703d3b5d194864ca09b1d925e76a) | `tlsHeaders.js` — TLS & security headers checker |

### June 5–6 2026 — SPA Frontend + Backend

| # | Commit | What landed |
|---|--------|-------------|
| 2 | [`1bccf83`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/1bccf8355b6d57a1dc23b41dde5195bf43cb0afe) | `dev.txt` v2 — accuracy audit |
| 3 | [`d0b4be2`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/d0b4be293c44d570d6d615f2c624d24b7ede52e9) | Projects UI (1/3) — `index.html` modal HTML |
| 4 | [`2ce876d`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/2ce876d5ae9cb8a6ddb160c9198fa3d69c366e7f) | Projects UI (2/3) — rich cards, modal, per-project stats, filter in `app.js` |
| 5 | [`bf90225`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/bf902259fb72b205023218b2b950820f146145ca) | Projects UI (3/3) — inline modal, risk badges, quick-launch scan |
| 6 | [`fcf9e20`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/fcf9e2002cd739de1b94cb8629dfa9cb8ac05983) | Module catalog UI — visual registry with policy matrix, severity, category, search |
| 7 | [`0412690`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/041269027582eac8115d09170b261e9fb1a7dad2) | Projects UI — rich project cards, risk score, launch scan, create/edit modal |
| 8 | [`36377ee`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/36377ee1c59fc587bdc9e27022063d6ec904dbd7) | Projects page HTML structure |
| 9 | [`6df89b9`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/6df89b9d7f2e7a33d3dc3b078d4d1c1a74ad9c0e) | `reportGenerator.js` — HTML + Markdown export |
| 10 | [`cf16182`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/cf16182d116e8077b4302a2700129e635e568987) | `server.js` v2 — retry endpoint, global stats, PATCH projects, env field on targets, global error handler |
| 11 | [`90c7e14`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/90c7e14a9ee0108ab93067982f2559cb0a9adc6f) | `engine.js` v2 — TLS check, cookie security, API key leak, subdomain takeover, JWT exposure, expanded SQLi/XSS |

### June 6 2026 — Check Files Session (TODO-01 → TODO-07 + extras)

| # | Commit | What landed |
|---|--------|-------------|
| 12 | [`b7cd78e`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/b7cd78ee15e2118e49db1ed7465164bff38793f5) | `dev.txt` v3 — verified by source read |
| 13 | [`5ede63f`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/5ede63f9935e93c265062139617c38bce3ea4103) | **TODO-01** `cookieSession.js` — HttpOnly, Secure, SameSite, entropy, __Host-/__Secure- prefix, session token in URL |
| 14 | [`2dc9942`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/2dc99421fde3d7f99a7871ce235eb36c81e5eb8c) | **TODO-02 (1/3)** `jsSecretScan.js` — AWS, Stripe, Google, Firebase, GitHub PAT, Slack, OpenAI, Bearer, PEM |
| 15 | [`c692cc9`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/c692cc9f0d9baa4af3f0305d3dae08f2e18a022a) | **TODO-02 (2/3)** `moduleRegistry.js` — add `exposure.js.secrets` + `cookie.session.flags` |
| 16 | [`2afb6d5`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/2afb6d5066e67e423dddf682c1db7a8ccb40ee14) | **TODO-01+02 (3/3)** `engine.js` — wire Phase 1b `cookieSession` + Phase 2.5a `jsSecretScan` |
| 17 | [`d42d334`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/d42d334f41616a2d6b547081bb067877e17702fe) | **TODO-03 (1/3)** `sourceMapDetect.js` initial |
| 18 | [`9f85c35`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/9f85c3523c621a36c1f3c31315d5c12b03901b8e) | **TODO-03 (1/3)** `sourceMapDetect.js` v2 — header detection, XSSI strip, dedup, internal path leak |
| 19 | [`c3c44bf`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/c3c44bfae7d1c6037f2afbf0bf8050bafa692d7a) | **TODO-03 (2/3)** `engine.js` — wire Phase 2.5b `sourceMapDetect` |
| 20 | [`9e40ac3`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/9e40ac3f25d2602b54a47db7dd9588bb8e10f2c2) | **TODO-03 (3/3)** `moduleRegistry.js` — add `exposure.sourcemap` |
| 21 | [`0cbbfe9`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/0cbbfe9e1159b3bc301183b48cfaf1eb400dcd4a) | **TODO-04 (1/2)** `cPanelWhm.js` + `cidrExpand.js` — CVE-2026-41940, 6 ports × 7 paths, CIDR expander |
| 22 | [`e308d75`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/e308d75e7166ac034005d38a5e6ed675c00e48df) | **TODO-26** Payload library manager — SQLite store, REST API, SecLists import, full UI |
| 23 | [`c2bc56f`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/c2bc56fdb8b6d8f7c514dc83c202c44fec9ff11) | **TODO-04 (2/2)** `engine.js` Phase 1d wired + `moduleRegistry.js` `exposure.cve.cpanel_whm` |
| 24 | [`28cc82b`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/28cc82b92f5010aa559426f43ce1ca7441b372dd) | `README.md` — wiring checklist + backend TODO candidates |
| 25 | [`5775735`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/5775735d407700e4dd29bbdc40e493217717d5b2) | `cveFingerprints.js` — 15 CVE checks (Nginx UI, Craft CMS, Laravel Livewire, Next.js, n8n, Langflow, FortiGate, Ivanti, Aruba, Vite, MindsDB, SharePoint, Oracle, Cisco FMC, Modular DS) |
| 26 | [`28af739`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/28af7395dc8e7145067b2129499b3d1e548790db) | **TODO-05 (1/3)** `laravelEnv.js` — 56 probe paths, 50+ secret patterns, APP_KEY RCE analysis |
| 27 | [`4c55810`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/4c558109956d14fd5fe45d051bc9cfe11e878500) | `moduleRegistry.js` — add `cve.fingerprints` ModuleDef |
| 28 | [`fbb5bbf`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/fbb5bbf106986566e98a6b7ff858b131b99e28cc) | `engine.js` v1.6.0 — wire Phase 1e `cveFingerprints` |
| 29 | [`c7c94ff`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/c7c94ffe0e2e82fc75951bc5d8694a23d01b0dde) | **TODO-05 (2/3)** `moduleRegistry.js` — add `exposure.cve.laravel_env_hunt` |
| 30 | [`ffe30e5`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/ffe30e5dbd8957e8c1716ae96fcb18abd56cd1c9) | `policyRegistry.js` — enable `cve.fingerprints` in `policy_normal` and `policy_aggressive` |
| 31 | [`015ea73`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/015ea739d082ba15a648008ead5625b5c1ae3166) | **TODO-05 (3/3)** `engine.js` v1.7.0 — wire Phase 1f `laravelEnvHunt` |
| 32 | [`1dacd13`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/1dacd137f9038312cb25c849716222a537c7865f) | `README.md` — full commit log, todo tracker, engine state |
| 33 | [`33dc421`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/33dc421cc9a3600d1152726226207a4ebada2dfd) | `robotsTxtParse.js` — passive robots.txt + sitemap.xml recon (Phase 2.5c) |
| 34 | [`5bc5a41`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/5bc5a412c23d4684c208028aa668a08e33b101e4) | **TODO-06 (1/3)** `cvePassive.js` — phpinfo, SVN/Hg, Vite @fs bypass, Mautic .env, Moodle listing, open cloud buckets, WP debug |
| 35 | [`ff4c087`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/ff4c087095f5823e379ab83fbc8033d008bc4840) | **TODO-06 (2/3)** `moduleRegistry.js` — 7 new ModuleDefs for cvePassive checks |
| 36 | [`6bb0dd2`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/6bb0dd28215992268fe817bdec83727d363cf8ca) | `models.js` — add `techStack` property + `addDiscoveredPath()` |
| 37 | [`b637048`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/b637048004013b6a47133e850f5196ba7ec593fb) | **TODO-06 (3/3)** `engine.js` — wire 7 cvePassive checks into Phase 1g |
| 38 | [`10490b5`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/10490b5f53f05268d7358c5c2d2f5997e782f67d) | `techFingerprint.js` — passive tech stack detection (8 CMS, 11 frameworks, 9 CDN/server layers) |
| 39 | [`0add901`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/0add90193b2231b2e2182c7e36490e8b9e326039) | `phpInfoExposure.js` — 15 paths, 8 body signatures, PHP version extraction |
| 40 | [`3ce6a1e`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/3ce6a1e3a4bad036ba2a0ce31899540416a7ea93) | `adminPanelDetect.js` — 28 panel definitions, CMS-hint gating, dual severity tiers |
| 41 | [`e7b51e4`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/e7b51e4863e9c668744e12732bcd9831806b7194) | `dev.txt` v4 — post TODO-01 through TODO-06 + TODO-26 |
| 42 | [`cbed7e3`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/cbed7e3a8a0b72f629fa42b3e1256ec61ffaf905) | `corsMisconfig.js` — origin reflection w/ creds = critical, wildcard+creds = high, null origin = medium |
| 43 | [`7be88f0`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/7be88f0ab036752a7a47681ac9e44373703edb3e) | `httpMethodsProbe.js` — TRACE/TRACK XST, PUT/DELETE, WebDAV, CONNECT |
| 44 | [`5c8fa94`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/5c8fa9417345cb6e704f5dc05c0ad5924c71efab) | **TODO-07 (1/2)** `injection.js` — `runCommandInjection`, `runSstiChecks`, `runFileUploadDetect` |
| 45 | [`8ff5058`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/8ff505897bebb68dd09a44c3b5d42cb1fa486e05) | `apiKeyExposure.js` — Swagger/OpenAPI (13 paths), raw spec (16 paths), GraphQL introspection |
| 46 | [`1934ae7`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/1934ae76c0292deb27372d5fb2b061df11378a5d) | `openRedirect.js` — 10 payloads, UNC/tab-encoded/double-slash bypass, 3 detection methods |
| 47 | [`a6f3ff4`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/a6f3ff4ede920796a3d39ec68177268787abadec) | `ssrfProbe.js` — 10 cloud metadata payloads (AWS IMDSv1/IAM, GCP, Azure, DO, localhost), cred-leak escalation |
| 48 | [`255146a`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/255146ac274a5150e622cbe0f310ce1797b76fa8) | `moduleRegistry.js` — register 8 new modules (techFingerprint, phpInfo, adminPanel, cors, httpMethods, apiExposure, openRedirect, ssrf) |
| 49 | [`99158a2`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/99158a2f92d97aafc3cd3e01b84b83cf451d06bd) | **TODO-07 (registry)** `moduleRegistry.js` — add `injection.cmdi.basic`, `injection.ssti.basic`, `injection.fileupload.detect` |
| 50 | [`9ac2350`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/9ac23504670dcc11810991348a5ce3b16afc56bf) | **TODO-07 (policy)** `policyRegistry.js` — enable cmdi/ssti/fileupload in `policy_aggressive` |

### June 6 2026 — UI Architecture Session (state, views, app wiring)

| # | Commit | What landed |
|---|--------|-------------|
| 51 | [`bb71101`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/bb711015b6a8984d692e6735020dafb0fe8823c2) | **`state.js` rewrite** — `AppState` singleton, `currentProject`/`currentProjectId`, db-backed `loadProjects`/`saveProject`/`deleteProject`, `selectProject` + `localStorage` persistence, `on`/`off`/`emit` change bus, legacy named exports preserved |
| 52 | [`3e2a24f`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/3e2a24f045215cb0ad39af609a7a6697ef6907d4) | **`projectListView.js` rewrite** — db-backed (no hardcoded demo data), New Project slide-down form (name/client/contact/auth/tags/policy), inline edit rows per project, delete with confirm guard, row-click + Select button → `state.selectProject()`, active project highlight + ACTIVE badge, live search across name+client+tags, risk score badge (LOW/MED/HIGH), state bus subscription for live refresh, `window._wvcToast` integration |
| 53 | [`4310d0e`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/4310d0e9683a4e6e8dd8bf1a2bccb3c92c529024) | **`jobConsoleView.js` rewrite** — `jobQueue.enqueue()` + `runPersistedJob` (all results written to db), user-editable target URL (no hardcoded value), policy + env selectors, `onProgress` callback → live log stream, queue status badge (running/queued), abort button (`jobQueue.cancel()`), findings summary table inline after scan, job history from `db.getAll(S.SCAN_JOBS)` (last 20), active project badge from `state` bus, `_browserFetch()` adapter |
| 54 | [`b869d99`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/b869d99126e90b93ac84c1d4b6b76adcd2bcd6e7) | **`app.js` rewrite** — `renderTargetsView` wired + re-renders on project switch, active nav highlight (blue left border + bold), sidebar project footer (live via state bus), Modules view (card grid from `moduleRegistry`, live search, class+severity badges, OWASP/CWE/stack-filter tags), Policies view (limits stats + expandable module overrides), Settings view (backend URL `localStorage`, ToS reset, clear all IndexedDB stores), global `window._wvcToast`, `state.loadProjects()` on boot |

---

## 📌 Current Status Snapshot

### ✅ Completed — Source Check Files (`src/core/checks/`)

| File | Phase | Status |
|------|-------|--------|
| `tlsHeaders.js` | 1b | ✅ wired |
| `cookieSession.js` | 1c | ✅ wired |
| `cPanelWhm.js` | 1d | ✅ wired |
| `cveFingerprints.js` | 1e | ✅ wired |
| `laravelEnv.js` | 1f | ✅ wired |
| `cvePassive.js` | 1g | ✅ wired (7 checks) |
| `jsSecretScan.js` | 2.5a | ✅ wired |
| `sourceMapDetect.js` | 2.5b | ✅ wired |
| `robotsTxtParse.js` | 2.5c | ✅ wired ⚠️ needs ModuleDef |
| `techFingerprint.js` | 1b | ⚠️ file exists — **NOT wired** |
| `phpInfoExposure.js` | 1h | ⚠️ file exists — **NOT wired** |
| `adminPanelDetect.js` | 1h | ⚠️ file exists — **NOT wired** |
| `corsMisconfig.js` | 1h | ⚠️ file exists — **NOT wired** |
| `httpMethodsProbe.js` | 1h | ⚠️ file exists — **NOT wired** |
| `apiKeyExposure.js` | 2.5c | ⚠️ file exists — **NOT wired** |
| `openRedirect.js` | 3 | ⚠️ file exists — **NOT wired** |
| `ssrfProbe.js` | 3 | ⚠️ file exists — **NOT wired** |
| `injection.js` (cmdi/ssti/upload) | 3 | ⚠️ functions exist — **NOT wired in engine** |

### ✅ Completed — UI (`src/ui/`)

| File | Status | Notes |
|------|--------|-------|
| `state.js` | ✅ complete | AppState singleton, change bus, db-backed projects |
| `views/projectListView.js` | ✅ complete | db-backed, full create/edit/delete, project selection |
| `views/jobConsoleView.js` | ✅ complete | jobQueue, live log, history, findings summary |
| `views/targetsView.js` | ✅ complete | API-wired, bulk import, CIDR input, inline edit |
| `views/findingsListView.js` | ✅ complete | reads state + API |
| `views/dashboardView.js` | ⚠️ skeleton | no real API calls yet |
| `app.js` | ✅ complete | all 8 routes wired, nav highlight, sidebar footer, settings/modules/policies views |
| `tos.js` | ✅ complete | TOS gate, localStorage persistence |

### ⚠️ NOT YET DONE

| Area | What's missing |
|------|----------------|
| `engine.js` wiring | 8 check files fully written but not imported/called |
| `dashboardView.js` | Real `GET /api/stats` call, live stats cards |
| `jobQueue.js` | May need `cancel()` method verified / implemented |
| `db.js` | `S.TARGETS`, `S.AUDIT_EVENTS` stores — verify schema matches UI calls |
| `models.js` | `Project`, `Target`, `ScanJob` constructors — verify field names match state.js usage |
| Backend persistence | `jobsStore.js` still in-memory Map; jobs lost on restart |
| Report UI | "Generate Report" button not wired to `GET /api/scans/:jobId/report` |
| Finding detail panel | No slide-in panel with evidence, OWASP/CWE, status changer |
| `policyView.js` | Full policy editor (not just read-only view in app.js) |
| `projectDetailView.js` | Per-project detail page (targets summary, job history, risk score) |

---

## 📋 TODO Tracker

### ✅ DONE

- [x] **TODO-01** `cookieSession.js` — cookie security checker
- [x] **TODO-02** `jsSecretScan.js` — JS asset secret scanner
- [x] **TODO-03** `sourceMapDetect.js` — source map exposure detector
- [x] **TODO-04** `cPanelWhm.js` + `cidrExpand.js` — cPanel/WHM CVE-2026-41940 scanner
- [x] **TODO-05** `laravelEnv.js` — advanced Laravel .env hunter
- [x] **TODO-06** `cvePassive.js` — phpinfo, SVN/Hg, Vite bypass, Mautic, Moodle, cloud buckets, WP debug
- [x] **TODO-07** `injection.js` additions — cmdi, ssti, file upload functions + 3 ModuleDefs + policy wiring
- [x] **TODO-09** `state.js` — AppState singleton, db-backed projects, change bus *(was listed as UI work)*
- [x] **TODO-12** `targetsView.js` — per-project target list, bulk import, CIDR, env tags, inline edit, delete
- [x] **TODO-26** Payload library manager — SQLite store, REST API, SecLists import, UI
- [x] `app.js` — all nav routes wired, active highlight, modules/policies/settings views
- [x] `projectListView.js` — fully db-backed rewrite
- [x] `jobConsoleView.js` — jobQueue, live log, history, abort
- [x] `cveFingerprints.js` — 15 CVE fingerprint checks
- [x] `robotsTxtParse.js` — robots.txt + sitemap.xml recon
- [x] `techFingerprint.js` — passive tech stack detection
- [x] `phpInfoExposure.js` — phpinfo exposure
- [x] `adminPanelDetect.js` — 28 panel definitions
- [x] `corsMisconfig.js` — 3 CORS vulnerability classes
- [x] `httpMethodsProbe.js` — dangerous HTTP methods
- [x] `apiKeyExposure.js` — Swagger/OpenAPI, GraphQL
- [x] `openRedirect.js` — active open redirect
- [x] `ssrfProbe.js` — cloud metadata SSRF
- [x] `moduleRegistry.js` — 27+ ModuleDefs
- [x] `policyRegistry.js` — 3 policies, injection modules wired

### 🔴 NEXT — Engine Wiring (Priority 1, unblocks everything)

- [ ] **TODO-ENGINE** Update `engine.js` to v2.0.0 — wire all 8 pending check files:
  - Import + call `runTechFingerprint()` — Phase 1b (**must run first before all other checks**)
  - Import + call `runPhpInfoExposure()` — Phase 1h
  - Import + call `runAdminPanelDetect()` — Phase 1h
  - Import + call `runCorsMisconfig()` — Phase 1h
  - Import + call `runHttpMethodsProbe()` — Phase 1h
  - Import + call `runApiExposure()` — Phase 2.5c
  - Import + call `runOpenRedirect()` — Phase 3
  - Import + call `runSsrfProbe()` — Phase 3
  - Wire `runCommandInjection`, `runSstiChecks`, `runFileUploadDetect` into Phase 3
  - Add `recon.robots_txt` ModuleDef to `moduleRegistry.js`
  - Bump engine version to `v2.0.0`

### 🟡 TIER 2 — Core Infrastructure

- [ ] **TODO-CORE-1** Verify / implement `jobQueue.cancel(jobId)` — needed by Abort button in jobConsoleView
- [ ] **TODO-CORE-2** Verify `db.js` stores: `S.TARGETS`, `S.AUDIT_EVENTS`, `S.SCAN_JOBS`, `S.FINDINGS`, `S.EVIDENCES` schema matches UI expectations
- [ ] **TODO-CORE-3** Verify `models.js` constructors: `Project`, `Target`, `ScanJob` field names align with state.js + views
- [ ] **TODO-08** Persist jobs to SQLite — `backend/jobsStore.js` (currently in-memory Map, lost on restart)

### 🟢 TIER 3 — Frontend Polish

- [ ] **TODO-DASH** `dashboardView.js` — wire to `GET /api/stats`; real stats cards (total findings by severity, jobs run, targets scanned, last scan time)
- [ ] **TODO-REPORT** Report generation UI — wire "Generate Report" → `GET /api/scans/:jobId/report`
- [ ] **TODO-FINDING-PANEL** Finding detail slide-in panel — full evidence snippet, OWASP/CWE tags, status changer (open/confirmed/false-positive/fixed)
- [ ] **TODO-13** `policyView.js` — full editable policy editor (app.js has read-only policy view; needs create/edit/clone/delete)
- [ ] **TODO-PROJDETAIL** `projectDetailView.js` — per-project summary page (targets, jobs, findings breakdown, risk score history)

### ⚠️ TIER 4 — Structural (do last)

- [ ] **TODO-14** Unify dual scan engines — `backend/engine-bridge.js` (44KB standalone) vs `src/core/engine.js` (modular). Make `engine-bridge.js` a thin adapter that imports from `src/core/engine.js`.

---

## ⚠️ Known Gaps & Warnings

| Issue | Severity | Status |
|-------|----------|--------|
| **8 check files not wired into `engine.js`** | 🔴 Blocker | TODO-ENGINE — next priority |
| **`jobQueue.cancel()` may not exist** | 🔴 Blocker | TODO-CORE-1 |
| **`db.js` / `models.js` field alignment unverified** | 🟡 High | TODO-CORE-2/3 |
| **Dual scan engines** | 🟡 High | TODO-14 (do last) |
| **`jobsStore.js` is in-memory** | 🟡 High | TODO-08 |
| **`dashboardView.js` is a skeleton** | 🟢 Medium | TODO-DASH |
| **`robotsTxtParse.js` has no ModuleDef** | 🟢 Medium | Fix during TODO-ENGINE |
| **CVE-2026-41940** — was under embargo at time of writing | ⚠️ Caution | Verify against NVD before client use |

---

## 📦 Module Registry — 27+ ModuleDefs

| ID | Name | Class | Severity | Phase |
|----|------|-------|----------|-------|
| `exposure.env.direct` | Direct .env Exposure | passive | critical | 1 |
| `exposure.env.variants` | .env Variant Exposure | passive | critical | 1 |
| `exposure.backup.db_dumps` | Database Backup Files | passive | critical | 1 |
| `exposure.backup.archives` | Archive Backup Files | passive | high | 1 |
| `misconfig.dirlisting.generic` | Directory Listing Detection | passive | medium | 1 |
| `vcs.git.exposed` | Exposed .git Repository | passive | high | 1 |
| `debug.stacktraces` | Verbose Error & Stack Trace Detection | passive | medium | 1 |
| `tls.headers.basic` | TLS & Security Header Check | passive | info | 1b |
| `cookie.session.flags` | Cookie & Session Security Checks | passive | high | 1c |
| `exposure.cve.cpanel_whm` | cPanel & WHM Panel Exposure (CVE-2026-41940) | passive | critical | 1d |
| `cve.fingerprints` | CVE Fingerprint Checks (2025–2026) | passive | high | 1e |
| `exposure.cve.laravel_env_hunt` | Laravel .env Exposure & Secret Extraction | passive | critical | 1f |
| `misconfig.phpinfo.exposed` | PHP Info / Debug Page Exposed | passive | critical | 1g |
| `vcs.svn_hg.exposed` | SVN / Mercurial Repository Exposure | passive | critical | 1g |
| `exposure.cve.vite_bypass` | Vite Dev Server / @fs LFI Bypass | passive | critical | 1g |
| `exposure.cve.mautic_env` | Mautic .env Disclosure (CVE-2024-47056) | passive | critical | 1g |
| `exposure.cve.moodle_listing` | Moodle Data Directory Exposure (CVE-2025-62396) | passive | high | 1g |
| `exposure.cloud.open_bucket` | Open Cloud Storage Bucket (S3/Azure/GCS) | passive | critical | 1g |
| `exposure.cms.wp_debug` | WordPress Debug Artifacts Exposed | passive | critical | 1g |
| `recon.tech_fingerprint` | Technology Stack Fingerprinting | passive | info | 1b |
| `exposure.phpinfo` | phpinfo() Page Exposure | passive | critical | 1h |
| `exposure.admin_panels` | Admin Panel & Login Page Detection | passive | critical/med | 1h |
| `misconfig.cors` | CORS Misconfiguration | passive | high | 1h |
| `misconfig.http_methods` | Dangerous HTTP Methods Detection | passive | medium | 1h |
| `exposure.api_endpoints` | API Documentation & GraphQL Exposure | passive | medium | 2.5c |
| `exposure.js.secrets` | JavaScript Asset Secret Scanner | passive | critical | 2.5a |
| `exposure.sourcemap` | Source Map Exposure | passive | high | 2.5b |
| `injection.open_redirect` | Open Redirect | active | high | 3 |
| `injection.ssrf.basic` | SSRF — Cloud Metadata & Internal Service Probe | active | high/critical | 3 |
| `injection.sqli.basic` | Basic SQL Injection Probes | active | high | 3 |
| `injection.xss.reflected_basic` | Reflected XSS Probes | active | medium | 3 |
| `injection.path_traversal.basic` | Path Traversal / Local File Read | active | critical | 3 |
| `injection.cmdi.basic` | OS Command Injection | active | critical | 3 |
| `injection.ssti.basic` | Server-Side Template Injection | active | critical | 3 |
| `injection.fileupload.detect` | File Upload Detection & Probe | active | high | 3 |

---

## 🛠️ Engine Phase Map (v1.7.0 current → v2.0.0 target)

```
Phase 1b   runTechFingerprint()          recon.tech_fingerprint       ⚠️ FILE EXISTS — NOT wired
Phase 1b   runTlsHeaderChecks()          tls.headers.basic             ✅ wired
Phase 1c   runCookieSessionChecks()      cookie.session.flags          ✅ wired
Phase 1d   runCPanelWhmScan()            exposure.cve.cpanel_whm       ✅ wired
Phase 1e   runCveFingerprints()          cve.fingerprints              ✅ wired
Phase 1    runPassiveExposureChecks()    7 checks                      ✅ wired
Phase 1f   runLaravelEnvHunt()           exposure.cve.laravel_env_hunt ✅ wired
Phase 1g   runCvePassiveChecks()         7 checks                      ✅ wired
Phase 1h   runPhpInfoExposure()          exposure.phpinfo              ⚠️ FILE EXISTS — NOT wired
Phase 1h   runAdminPanelDetect()         exposure.admin_panels         ⚠️ FILE EXISTS — NOT wired
Phase 1h   runCorsMisconfig()            misconfig.cors                ⚠️ FILE EXISTS — NOT wired
Phase 1h   runHttpMethodsProbe()         misconfig.http_methods        ⚠️ FILE EXISTS — NOT wired
Phase 2    crawlTargetAndBuildSiteModel()  maxDepth:2  maxPages:30
Phase 2.5a runJsSecretScan()             exposure.js.secrets           ✅ wired
Phase 2.5b runSourceMapDetect()          exposure.sourcemap            ✅ wired
Phase 2.5c runRobotsTxtParse()           (needs ModuleDef)             ✅ wired
Phase 2.5c runApiExposure()              exposure.api_endpoints        ⚠️ FILE EXISTS — NOT wired
Phase 3    runActiveInjectionChecks()
             ├─ injection.sqli.basic              ✅ wired
             ├─ injection.xss.reflected_basic     ✅ wired
             ├─ injection.path_traversal.basic    ✅ wired
             ├─ injection.cmdi.basic              ⚠️ function exists — NOT wired
             ├─ injection.ssti.basic              ⚠️ function exists — NOT wired
             ├─ injection.fileupload.detect       ⚠️ function exists — NOT wired
             ├─ injection.open_redirect           ⚠️ FILE EXISTS — NOT wired
             └─ injection.ssrf.basic              ⚠️ FILE EXISTS — NOT wired
```

---

## Architecture

```
/backend                  Express API + SQLite + worker
  server.js               22+ API routes (v2)
  db.js                   SQLite schema + query helpers
  engine-bridge.js        Standalone 44KB scan engine (NOT unified with src/core — TODO-14)
  dorkEngine.js           Google + GitHub dork generator
  reportGenerator.js      HTML + Markdown report builder
  payloadLibrary.js       Custom payload store — SQLite + REST API (TODO-26 ✅)
  utils/
    cidrExpand.js         CIDR/IP range expander
    normalize.js
    retry.js
    severityScore.js

/src/core                 Modular scan engine
  engine.js               v1.7.0 (v2.0.0 pending TODO-ENGINE)
  crawler.js              HTML crawl, SiteModel builder
  injection.js            SQLi + XSS + path traversal + CMDi + SSTI + FileUpload
  moduleRegistry.js       27+ ModuleDefs ✅
  policyRegistry.js       3 policies ✅
  jobQueue.js             Job queue — cancel() method needs verification
  db.js                   IndexedDB wrapper — store schema needs verification
  models.js               Project, Target, ScanJob, Finding, Evidence, SiteModel
  policyRegistry.js       policy_normal / policy_aggressive / policy_extreme
  checks/
    tlsHeaders.js         ✅ wired
    cookieSession.js      ✅ wired
    cPanelWhm.js          ✅ wired
    cveFingerprints.js    ✅ wired
    laravelEnv.js         ✅ wired
    cvePassive.js         ✅ wired
    jsSecretScan.js       ✅ wired
    sourceMapDetect.js    ✅ wired
    robotsTxtParse.js     ✅ wired (needs ModuleDef)
    techFingerprint.js    ⚠️ NOT wired
    phpInfoExposure.js    ⚠️ NOT wired
    adminPanelDetect.js   ⚠️ NOT wired
    corsMisconfig.js      ⚠️ NOT wired
    httpMethodsProbe.js   ⚠️ NOT wired
    apiKeyExposure.js     ⚠️ NOT wired
    openRedirect.js       ⚠️ NOT wired
    ssrfProbe.js          ⚠️ NOT wired

/src/ui                   Frontend SPA
  app.js                  ✅ all 8 routes wired, nav highlight, toast, boot sequence
  state.js                ✅ AppState singleton, change bus, db-backed projects
  tos.js                  ✅ TOS gate
  views/
    dashboardView.js      ⚠️ SKELETON — no real API calls
    projectListView.js    ✅ db-backed, full CRUD, selection
    jobConsoleView.js     ✅ jobQueue, live log, history, abort
    targetsView.js        ✅ API-wired, bulk import, CIDR, env tags
    findingsListView.js   ✅ reads state + API

/frontend                 Compiled SPA assets
  app.js                  ~50KB legacy SPA logic
  index.html              Terminal console UI shell
  style.css               Cyberpunk terminal theme
```

**Scan Policies:**  
`policy_normal` — passive checks only  
`policy_aggressive` — + SQLi / XSS / CMDi / SSTI / file upload  
`policy_extreme` — all modules including SSRF, open redirect, path traversal  

**DB:** `backend/data/scanner.db` (auto-created, excluded from git)
