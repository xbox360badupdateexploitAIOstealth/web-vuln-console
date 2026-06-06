# web-vuln-console

Modular web vulnerability scanner console — env/config/backup/git exposure, SQLi, XSS, path traversal, SSRF, open redirect, CORS, admin panel detection, tech fingerprinting, CVE fingerprints, cPanel/WHM IP sweep, Laravel .env hunter, command injection, SSTI, file upload detection, policy engine, dork generator, HTML/Markdown reports.

**Stack:** Node.js + Express backend · SQLite (better-sqlite3) · Vanilla JS SPA frontend · Termux / VPS compatible  
**Engine:** `src/core/engine.js` v2.0.0 · 27 ModuleDefs · 8 scan phases  
**Port:** `7777` default

---

## ✅ Complete Commit Log — All Sessions

### June 4 2026 — Initial Build

| # | Commit | What landed |
|---|--------|-------------|
| 1 | [`6a97885`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/6a9788526cbf703d3b5d194864ca09b1d925e76a) | `tlsHeaders.js` — TLS & security headers checker (missing headers, HTTP downgrade, HSTS, CSP, clickjacking) |

### June 5–6 2026 — SPA Frontend + Backend

| # | Commit | What landed |
|---|--------|-------------|
| 2 | [`1bccf83`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/1bccf8355b6d57a1dc23b41dde5195bf43cb0afe) | `dev.txt` — full accuracy audit rewrite |
| 3 | [`d0b4be2`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/d0b4be293c44d570d6d615f2c624d24b7ede52e9) | Projects UI (1/3) — rich modal HTML in `index.html` |
| 4 | [`2ce876d`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/2ce876d5ae9cb8a6ddb160c9198fa3d69c366e7f) | Projects UI (2/3) — rich cards, modal, per-project stats, filter in `app.js` |
| 5 | [`bf90225`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/bf902259fb72b205023218b2b950820f146145ca) | Projects UI (3/3) — inline modal, risk badges, quick-launch scan |
| 6 | [`fcf9e20`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/fcf9e2002cd739de1b94cb8629dfa9cb8ac05983) | Module catalog UI page — visual registry with policy matrix, severity, category, search filter |
| 7 | [`0412690`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/041269027582eac8115d09170b261e9fb1a7dad2) | Projects UI — rich project cards with per-project stats, risk score, launch scan, create/edit modal |
| 8 | [`36377ee`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/36377ee1c59fc587bdc9e27022063d6ec904dbd7) | Projects page HTML structure — header bar, search/filter, project list container |
| 9 | [`6df89b9`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/6df89b9d7f2e7a33d3dc3b078d4d1c1a74ad9c0e) | `reportGenerator.js` — HTML + Markdown export from project findings |
| 10 | [`cf16182`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/cf16182d116e8077b4302a2700129e635e568987) | `server.js` v2 — retry endpoint, global stats, PATCH projects, env field on targets, global error handler |
| 11 | [`90c7e14`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/90c7e14a9ee0108ab93067982f2559cb0a9adc6f) | `engine.js` v2 — TLS check, cookie security, API key leak detector, subdomain takeover, JWT exposure, expanded SQLi/XSS payloads |

### June 6 2026 — Check Files Session (TODO-01 → TODO-07 + extras)

| # | Commit | What landed |
|---|--------|-------------|
| 12 | [`b7cd78e`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/b7cd78ee15e2118e49db1ed7465164bff38793f5) | `dev.txt` v3 — fully verified by source read |
| 13 | [`5ede63f`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/5ede63f9935e93c265062139617c38bce3ea4103) | **TODO-01** `cookieSession.js` — cookie security (HttpOnly, Secure, SameSite, entropy, __Host-/__Secure- prefixes, session token in URL) |
| 14 | [`2dc9942`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/2dc99421fde3d7f99a7871ce235eb36c81e5eb8c) | **TODO-02 (1/3)** `jsSecretScan.js` — JS asset secret scanner (AWS keys, Stripe, Google, Firebase, GitHub PATs, Slack, OpenAI, Bearer tokens, PEM keys) |
| 15 | [`c692cc9`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/c692cc9f0d9baa4af3f0305d3dae08f2e18a022a) | **TODO-02 (2/3)** `moduleRegistry.js` — add `exposure.js.secrets` + `cookie.session.flags` ModuleDefs |
| 16 | [`2afb6d5`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/2afb6d5066e67e423dddf682c1db7a8ccb40ee14) | **TODO-01+02 (3/3)** `engine.js` — wire Phase 1b `cookieSession` + Phase 2.5 `jsSecretScan` |
| 17 | [`d42d334`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/d42d334f41616a2d6b547081bb067877e17702fe) | **TODO-03 (1/3)** `sourceMapDetect.js` initial |
| 18 | [`9f85c35`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/9f85c3523c621a36c1f3c31315d5c12b03901b8e) | **TODO-03 (1/3)** `sourceMapDetect.js` v2 — header detection, XSSI strip, dedup, internal path leak |
| 19 | [`c3c44bf`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/c3c44bfae7d1c6037f2afbf0bf8050bafa692d7a) | **TODO-03 (2/3)** `engine.js` — wire Phase 2.5b `sourceMapDetect` |
| 20 | [`9e40ac3`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/9e40ac3f25d2602b54a47db7dd9588bb8e10f2c2) | **TODO-03 (3/3)** `moduleRegistry.js` — add `exposure.sourcemap` ModuleDef |
| 21 | [`0cbbfe9`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/0cbbfe9e1159b3bc301183b48cfaf1eb400dcd4a) | **TODO-04 (1/2)** `cPanelWhm.js` + `cidrExpand.js` — CVE-2026-41940 scanner, 6 ports × 7 paths, CIDR/IP range expander |
| 22 | [`e308d75`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/e308d75e7166ac034005d38a5e6ed675c00e48df) | **TODO-26** `payloadLibrary` — custom payload library manager (SQLite store, full REST API, SecLists import, full UI) |
| 23 | [`c2bc56f`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/c2bc56fdb8b6d8f7c514dc83c202c44fea9fcf11) | **TODO-04 (2/2)** `engine.js` v1.5.0 Phase 1d wired + `moduleRegistry.js` `exposure.cve.cpanel_whm` ModuleDef |
| 24 | [`28cc82b`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/28cc82b92f5010aa559426f43ce1ca7441b372dd) | `README.md` — expand with wiring checklist and backend TODO candidates |
| 25 | [`5775735`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/5775735d407700e4dd29bbdc40e493217717d5b2) | `cveFingerprints.js` — 15 CVE fingerprint checks (Nginx UI, Craft CMS, Laravel Livewire, Next.js RSC, n8n, Langflow, FortiGate, Ivanti, Aruba, Vite, MindsDB, SharePoint, Oracle, Cisco FMC, Modular DS) |
| 26 | [`28af739`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/28af7395dc8e7145067b2129499b3d1e548790db) | **TODO-05 (1/3)** `laravelEnv.js` — 56 probe paths, 50+ secret patterns, APP\_KEY RCE analysis, cloud DB risk scoring |
| 27 | [`4c55810`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/4c558109956d14fd5fe45d051bc9cfe11e878500) | `moduleRegistry.js` — add `cve.fingerprints` ModuleDef |
| 28 | [`fbb5bbf`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/fbb5bbf106986566e98a6b7ff858b131b99e28cc) | `engine.js` v1.5.0 → v1.6.0 — wire Phase 1e `cveFingerprints` |
| 29 | [`c7c94ff`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/c7c94ffe0e2e82fc75951bc5d8694a23d01b0dde) | **TODO-05 (2/3)** `moduleRegistry.js` — add `exposure.cve.laravel_env_hunt` ModuleDef |
| 30 | [`ffe30e5`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/ffe30e5dbd8957e8c1716ae96fcb18abd56cd1c9) | `policyRegistry.js` — enable `cve.fingerprints` in `policy_normal` and `policy_aggressive` |
| 31 | [`015ea73`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/015ea739d082ba15a648008ead5625b5c1ae3166) | **TODO-05 (3/3)** `engine.js` v1.7.0 — wire Phase 1f `runLaravelEnvHunt` |
| 32 | [`1dacd13`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/1dacd137f9038312cb25c849716222a537c7865f) | `README.md` — update with full commit log, todo tracker, engine state |
| 33 | [`33dc421`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/33dc421cc9a3600d1152726226207a4ebada2dfd) | `robotsTxtParse.js` — passive robots.txt + sitemap.xml recon (Phase 2.5c) |
| 34 | [`5bc5a41`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/5bc5a412c23d4684c208028aa668a08e33b101e4) | **TODO-06 (1/3)** `cvePassive.js` — phpinfo, SVN/Hg, Vite @fs bypass, Mautic .env, Moodle listing, open cloud buckets, WP debug artifacts |
| 35 | [`ff4c087`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/ff4c087095f5823e379ab83fbc8033d008bc4840) | **TODO-06 (2/3)** `moduleRegistry.js` — add 7 ModuleDefs for all cvePassive checks |
| 36 | [`6bb0dd2`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/6bb0dd28215992268fe817bdec83727d363cf8ca) | `siteModel` — add `techStack` property + `addDiscoveredPath()` for robotsTxt and techFingerprint modules |
| 37 | [`b637048`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/b637048004013b6a47133e850f5196ba7ec593fb) | **TODO-06 (3/3)** `engine.js` — wire 7 cvePassive checks into Phase 1g |
| 38 | [`10490b5`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/10490b5f53f05268d7358c5c2d2f5997e782f67d) | `techFingerprint.js` — passive tech stack detection, detects 8 CMS + 11 frameworks + 9 CDN/server layers, writes `siteModel.techStack` |
| 39 | [`0add901`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/0add90193b2231b2e2182c7e36490e8b9e326039) | `phpInfoExposure.js` — passive phpinfo() exposure, 15 paths, 8 body signatures, extracts PHP version |
| 40 | [`3ce6a1e`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/3ce6a1e3a4bad036ba2a0ce31899540416a7ea93) | `adminPanelDetect.js` — 28 panel definitions (WordPress, Joomla, Drupal, phpMyAdmin, Adminer, Grafana, Kibana, Jenkins, SonarQube, Portainer, Traefik, Vault, RabbitMQ, k8s Dashboard, cPanel, WHM + generic), CMS-hint gating, two severity tiers |
| 41 | [`e7b51e4`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/e7b51e4863e9c668744e12732bcd9831806b7194) | `dev.txt` v4 — fully updated post TODO-01 through TODO-06 + TODO-26 |
| 42 | [`cbed7e3`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/cbed7e3a8a0b72f629fa42b3e1256ec61ffaf905) | `corsMisconfig.js` — passive CORS misconfiguration (origin reflection w/ creds = critical, wildcard+creds = high, null origin = medium) |
| 43 | [`7be88f0`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/7be88f0ab036752a7a47681ac9e44373703edb3e) | `httpMethodsProbe.js` — dangerous HTTP methods (OPTIONS probe, TRACE/TRACK XST, PUT/DELETE non-API = high, WebDAV = medium, CONNECT = medium) |
| 44 | [`5c8fa94`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/5c8fa9417345cb6e704f5dc05c0ad5924c71efab) | **TODO-07 (1/2)** `injection.js` — add `runCommandInjection`, `runSstiChecks`, `runFileUploadDetect` |
| 45 | [`8ff5058`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/8ff505897bebb68dd09a44c3b5d42cb1fa486e05) | `apiKeyExposure.js` — Swagger/OpenAPI UI (13 paths), raw spec JSON/YAML (16 paths), GraphQL introspection (POST + schema confirm), GraphQL endpoint w/ introspection off (12 paths) |
| 46 | [`1934ae7`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/1934ae76c0292deb27372d5fb2b061df11378a5d) | `openRedirect.js` — active open redirect (10 payloads incl. UNC/tab-encoded/double-slash bypass, detects 3xx Location + meta-refresh + JS window.location, 50 ep × 150 probes cap) |
| 47 | [`a6f3ff4`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/a6f3ff4ede920796a3d39ec68177268787abadec) | `ssrfProbe.js` — active SSRF (10 cloud metadata payloads: AWS IMDSv1/IAM/user-data, GCP metadata/SA token, Azure IMDS/managed identity, DigitalOcean, localhost; escalates to critical on credential leak) |
| 48 | [`255146a`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/255146ac274a5150e622cbe0f310ce1797b76fa8) | `moduleRegistry.js` — register 8 new modules (techFingerprint, phpInfo, adminPanel, cors, httpMethods, apiExposure, openRedirect, ssrf) |
| 49 | [`99158a2`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/99158a2f92d97aafc3cd3e01b84b83cf451d06bd) | **TODO-07 (registry)** `moduleRegistry.js` — add `injection.cmdi.basic`, `injection.ssti.basic`, `injection.fileupload.detect` ModuleDefs |
| 50 | [`9ac2350`](https://github.com/xbox360badupdateexploitAIOstealth/web-vuln-console/commit/9ac23504670dcc11810991348a5ce3b16afc56bf) | **TODO-07 (policy)** `policyRegistry.js` — enable `injection.cmdi.basic`, `injection.ssti.basic`, `injection.fileupload.detect` in `policy_aggressive` |

---

## 📦 Current Module Registry — 27 ModuleDefs

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
| `recon.tech_fingerprint` | Technology Stack Fingerprinting | passive | info | 1b (first) |
| `exposure.phpinfo` | phpinfo() Page Exposure | passive | critical | 1g |
| `exposure.admin_panels` | Admin Panel & Login Page Detection | passive | critical/med | 1g |
| `misconfig.cors` | CORS Misconfiguration | passive | high | 1h |
| `misconfig.http_methods` | Dangerous HTTP Methods Detection | passive | medium | 1h |
| `exposure.api_endpoints` | API Documentation & GraphQL Exposure | passive | medium | 2.5c |
| `injection.open_redirect` | Open Redirect | active | high | 3 |
| `injection.ssrf.basic` | SSRF — Cloud Metadata & Internal Service Probe | active | high/critical | 3 |
| `injection.sqli.basic` | Basic SQL Injection Probes | active | high | 3 |
| `injection.xss.reflected_basic` | Reflected XSS Probes | active | medium | 3 |
| `injection.path_traversal.basic` | Path Traversal / Local File Read | active | critical | 3 |
| `injection.cmdi.basic` | OS Command Injection | active | critical | 3 |
| `injection.ssti.basic` | Server-Side Template Injection | active | critical | 3 |
| `injection.fileupload.detect` | File Upload Detection & Probe | active | high | 3 |

---

## 🛠️ Engine Phase Map (v2.0.0 target)

```
Phase 1b   runTechFingerprint()        recon.tech_fingerprint        ← NEW (wiring pending)
Phase 1b   runTlsHeaderChecks()        tls.headers.basic
Phase 1c   runCookieSessionChecks()    cookie.session.flags
Phase 1d   runCPanelWhmScan()          exposure.cve.cpanel_whm
Phase 1e   runCveFingerprints()        cve.fingerprints

Phase 1    runPassiveExposureChecks()
             ├─ exposure.env.direct
             ├─ exposure.env.variants
             ├─ exposure.backup.db_dumps
             ├─ exposure.backup.archives
             ├─ misconfig.dirlisting.generic
             ├─ vcs.git.exposed
             └─ debug.stacktraces

Phase 1f   runLaravelEnvHunt()         exposure.cve.laravel_env_hunt

Phase 1g   runCvePassiveChecks()       7 checks:
             ├─ misconfig.phpinfo.exposed
             ├─ vcs.svn_hg.exposed
             ├─ exposure.cve.vite_bypass
             ├─ exposure.cve.mautic_env
             ├─ exposure.cve.moodle_listing
             ├─ exposure.cloud.open_bucket
             └─ exposure.cms.wp_debug

Phase 1h   runPhpInfoExposure()        exposure.phpinfo              ← NEW (wiring pending)
Phase 1h   runAdminPanelDetect()       exposure.admin_panels         ← NEW (wiring pending)
Phase 1h   runCorsMisconfig()          misconfig.cors                ← NEW (wiring pending)
Phase 1h   runHttpMethodsProbe()       misconfig.http_methods        ← NEW (wiring pending)

Phase 2    crawlTargetAndBuildSiteModel()   maxDepth:2  maxPages:30

Phase 2.5a runJsSecretScan()           exposure.js.secrets
Phase 2.5b runSourceMapDetect()        exposure.sourcemap
Phase 2.5c runRobotsTxtParse()         (recon — no ModuleDef yet)    ← needs ModuleDef
Phase 2.5c runApiExposure()            exposure.api_endpoints        ← NEW (wiring pending)

Phase 3    runActiveInjectionChecks()
             ├─ injection.sqli.basic
             ├─ injection.xss.reflected_basic
             ├─ injection.path_traversal.basic
             ├─ injection.cmdi.basic              ← NEW (wiring pending)
             ├─ injection.ssti.basic              ← NEW (wiring pending)
             ├─ injection.fileupload.detect       ← NEW (wiring pending)
             ├─ injection.open_redirect           ← NEW (wiring pending)
             └─ injection.ssrf.basic              ← NEW (wiring pending)
```

---

## 📋 TODO List — Current Status

### ✅ DONE

- [x] **TODO-01** `cookieSession.js` — cookie security checker
- [x] **TODO-02** `jsSecretScan.js` — JS asset secret scanner
- [x] **TODO-03** `sourceMapDetect.js` — source map exposure detector
- [x] **TODO-04** `cPanelWhm.js` + `cidrExpand.js` — cPanel/WHM CVE-2026-41940 scanner
- [x] **TODO-05** `laravelEnv.js` — advanced Laravel .env hunter
- [x] **TODO-06** `cvePassive.js` — phpinfo, SVN/Hg, Vite bypass, Mautic, Moodle, cloud buckets, WP debug
- [x] **TODO-07** `injection.js` additions — `runCommandInjection`, `runSstiChecks`, `runFileUploadDetect` + 3 ModuleDefs + policy wiring
- [x] **TODO-26** Payload library manager — SQLite store, REST API, SecLists import, full UI
- [x] `cveFingerprints.js` — 15 CVE checks (2025–2026)
- [x] `robotsTxtParse.js` — robots.txt + sitemap.xml recon
- [x] `techFingerprint.js` — passive tech stack detection (8 CMS, 11 frameworks, 9 CDN/server)
- [x] `phpInfoExposure.js` — 15 paths, 8 body sigs, PHP version extraction
- [x] `adminPanelDetect.js` — 28 panel definitions, CMS-hint gating, dual severity tiers
- [x] `corsMisconfig.js` — 3 vulnerability classes (origin reflection, wildcard+creds, null origin)
- [x] `httpMethodsProbe.js` — TRACE/TRACK XST, PUT/DELETE, WebDAV, CONNECT
- [x] `apiKeyExposure.js` — Swagger/OpenAPI UI + spec, GraphQL introspection
- [x] `openRedirect.js` — 10 payloads, 3 detection methods, 150-probe cap
- [x] `ssrfProbe.js` — 10 cloud metadata payloads, credential-leak escalation to critical
- [x] `moduleRegistry.js` — all 27+ ModuleDefs registered
- [x] `policyRegistry.js` — new injection modules in `policy_aggressive`

### 🔴 NEXT — Engine Wiring (Priority 1)

- [ ] **TODO-ENGINE** Wire all 8 new check files into `engine.js`:
  - `runTechFingerprint()` — Phase 1b (must run FIRST, before all other checks)
  - `runPhpInfoExposure()` — Phase 1h
  - `runAdminPanelDetect()` — Phase 1h
  - `runCorsMisconfig()` — Phase 1h
  - `runHttpMethodsProbe()` — Phase 1h
  - `runApiExposure()` — Phase 2.5c
  - `runOpenRedirect()` — Phase 3
  - `runSsrfProbe()` — Phase 3
  - Wire `runCommandInjection`, `runSstiChecks`, `runFileUploadDetect` into Phase 3 in `injection.js`
  - Add `recon.robots_txt` ModuleDef for `robotsTxtParse.js`
  - Bump engine version to `v2.0.0`

### 🟡 TIER 2 — Backend Persistence

- [ ] **TODO-08** Persist jobs to SQLite — `backend/db.js` + `backend/jobsStore.js`
  - Add `jobs` table (id, project\_id, status, policy\_id, targets\_json, created\_at, result\_json)
  - Update `jobsStore.js` to read/write SQLite instead of in-memory Map
  - **Fixes:** job metadata lost on server restart

### 🟣 TIER 3 — Frontend / UI

- [ ] **TODO-09** `dashboardView.js` — wire to `GET /api/stats` (currently a skeleton)
- [ ] **TODO-10** Report generation UI — wire "Generate Report" → `GET /api/scans/:jobId/report`
- [ ] **TODO-11** Finding detail side-panel — slide-in panel with evidence snippet, OWASP/CWE tags, status changer
- [ ] **TODO-12** `targetsView.js` — NEW FILE — per-project target list, bulk paste, env tag, IP range input
- [ ] **TODO-13** `policyView.js` — NEW FILE — policy editor UI
- [ ] `settingsView.js` — NEW FILE
- [ ] `modulesView.js` — NEW FILE
- [ ] `projectDetailView.js` — NEW FILE

### ⚠️ TIER 4 — Big Structural Change (do last)

- [ ] **TODO-14** Unify dual scan engines — make `backend/engine-bridge.js` a thin adapter importing `runScanJob` from `src/core/engine.js`

---

## ⚠️ Known Gaps & Warnings

| Issue | Status |
|-------|--------|
| **8 new check files not yet wired into engine.js** — all files exist, imports + phase calls missing | **TODO-ENGINE — next priority** |
| **Dual scan engines** — `engine-bridge.js` (44KB) and `src/core/engine.js` are independent | Tracked as TODO-14, do last |
| **Jobs not persisted** — `jobsStore.js` is pure in-memory Map | Tracked as TODO-08 |
| **dashboardView.js is a skeleton** — 633 bytes, zero API calls | Tracked as TODO-09 |
| **5 UI views missing** — `targetsView`, `policyView`, `settingsView`, `modulesView`, `projectDetailView` | Tracked as TODO-12/13 |
| **`robotsTxtParse.js` has no ModuleDef** — check runs but won't appear in policy/module registry | Add during TODO-ENGINE |
| **CVE-2026-41940** — was under embargo at time of writing; validate against NVD before client use | Verify before production use |

---

## Architecture

```
/backend             Express API + SQLite + worker + engine-bridge (standalone)
  server.js          22+ API routes (v2)
  db.js              SQLite schema + query helpers
  engine-bridge.js   Standalone scan engine (44KB) — NOT YET unified with src/core
  dorkEngine.js      Google + GitHub dork generator
  reportGenerator.js HTML + Markdown report builder
  payloadLibrary.js  Custom payload store — SQLite + REST API (TODO-26)
  utils/
    cidrExpand.js    CIDR/IP range expander
    normalize.js
    retry.js
    severityScore.js

/src/core            Modular scan engine
  engine.js          v1.7.0 current (v2.0.0 pending engine wiring TODO)
  crawler.js         HTML crawl, SiteModel builder
  injection.js       SQLi + XSS + path traversal + CMDi + SSTI + FileUpload (needs wiring)
  moduleRegistry.js  27+ ModuleDefs
  policyRegistry.js  3 policies (normal / aggressive / extreme)
  models.js          SiteModel + Finding + Evidence (techStack property added)
  checks/
    tlsHeaders.js          Phase 1b  ✅ wired
    cookieSession.js       Phase 1c  ✅ wired
    cPanelWhm.js           Phase 1d  ✅ wired
    cveFingerprints.js     Phase 1e  ✅ wired
    laravelEnv.js          Phase 1f  ✅ wired
    cvePassive.js          Phase 1g  ✅ wired (7 checks)
    robotsTxtParse.js      Phase 2.5c ✅ wired (needs ModuleDef)
    jsSecretScan.js        Phase 2.5a ✅ wired
    sourceMapDetect.js     Phase 2.5b ✅ wired
    techFingerprint.js     Phase 1b  ⚠️ FILE EXISTS — not yet wired
    phpInfoExposure.js     Phase 1h  ⚠️ FILE EXISTS — not yet wired
    adminPanelDetect.js    Phase 1h  ⚠️ FILE EXISTS — not yet wired
    corsMisconfig.js       Phase 1h  ⚠️ FILE EXISTS — not yet wired
    httpMethodsProbe.js    Phase 1h  ⚠️ FILE EXISTS — not yet wired
    apiKeyExposure.js      Phase 2.5c ⚠️ FILE EXISTS — not yet wired
    openRedirect.js        Phase 3   ⚠️ FILE EXISTS — not yet wired
    ssrfProbe.js           Phase 3   ⚠️ FILE EXISTS — not yet wired

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
`policy_aggressive` — + SQLi / XSS / CMDi / SSTI / file upload  
`policy_extreme` — all modules including SSRF, open redirect, path traversal

**DB:** `backend/data/scanner.db` (auto-created, excluded from git)
