/* =================================================================
   WebVulnConsole ⚡ — report bridge (TODO-10)
   Loaded by index.html AFTER app.js.
   Exposes the live app state + utils to report.js via window globals.
   This file is a thin shim — no logic lives here.
   ================================================================= */

// Expose state so report.js can call window._wvcState
Object.defineProperty(window, '_wvcState', {
  get() {
    // app.js declares `let state` in its scope; we reach it via
    // the window.state alias that app.js sets below.
    return window._appState || {};
  },
  configurable: true,
});
