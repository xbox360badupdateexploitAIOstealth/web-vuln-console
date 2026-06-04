// src/ui/tos.js
// Simple Terms of Service gate rendered dynamically.

const STORAGE_KEY = 'web_vuln_console_tos_accepted_v1';

export function ensureTosAccepted() {
  if (typeof window === 'undefined') return true;
  try {
    if (window.localStorage && window.localStorage.getItem(STORAGE_KEY) === '1') {
      return true;
    }
  } catch (_) {
    // ignore storage errors and fall back to showing banner every time
  }

  renderTosOverlay();
  return false;
}

function renderTosOverlay() {
  if (document.getElementById('tos-overlay')) return;

  const overlay = document.createElement('div');
  overlay.id = 'tos-overlay';
  overlay.style.position = 'fixed';
  overlay.style.inset = '0';
  overlay.style.background = 'rgba(15,23,42,0.92)';
  overlay.style.zIndex = '9999';
  overlay.style.display = 'flex';
  overlay.style.alignItems = 'center';
  overlay.style.justifyContent = 'center';

  const panel = document.createElement('div');
  panel.style.maxWidth = '640px';
  panel.style.width = '92%';
  panel.style.background = '#020617';
  panel.style.border = '1px solid #1f2937';
  panel.style.borderRadius = '8px';
  panel.style.padding = '18px 20px';
  panel.style.boxShadow = '0 18px 45px rgba(0,0,0,0.7)';
  panel.style.fontSize = '13px';
  panel.style.lineHeight = '1.5';

  panel.innerHTML = `
    <h2 style="margin: 0 0 8px; font-size: 16px;">Authorized Security Testing Only</h2>
    <p style="margin: 4px 0; opacity: 0.85;">
      This console is intended for <strong>legitimate security assessment</strong> of systems that you own or are
      explicitly authorized to test.
    </p>
    <p style="margin: 4px 0; opacity: 0.85;">
      By continuing you confirm that:
    </p>
    <ul style="margin: 6px 0 8px 18px; padding: 0; opacity: 0.85;">
      <li>You are the owner or have written permission from the owner of all targets you scan.</li>
      <li>You will comply with applicable laws, contracts, and your client engagements.</li>
      <li>You will not use this tool for unauthorized or malicious activity.</li>
    </ul>
    <p style="margin: 4px 0 10px; font-size: 12px; opacity: 0.8;">
      If you do not agree, close this page immediately.
    </p>
    <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 10px;">
      <button id="tos-decline" style="padding: 6px 10px; font-size: 12px; background: #111827; border: 1px solid #1f2937; color: #e5e7eb; border-radius: 4px; cursor: pointer;">Close</button>
      <button id="tos-accept" style="padding: 6px 10px; font-size: 12px; background: #22c55e; border: 1px solid #16a34a; color: #022c22; border-radius: 4px; cursor: pointer; font-weight: 500;">I understand and agree</button>
    </div>
  `;

  overlay.appendChild(panel);
  document.body.appendChild(overlay);

  const acceptBtn = document.getElementById('tos-accept');
  const declineBtn = document.getElementById('tos-decline');

  acceptBtn?.addEventListener('click', () => {
    try {
      window.localStorage && window.localStorage.setItem(STORAGE_KEY, '1');
    } catch (_) {}
    overlay.remove();
  });

  declineBtn?.addEventListener('click', () => {
    // Soft-close: just navigate away.
    window.location.href = 'https://example.com';
  });
}
