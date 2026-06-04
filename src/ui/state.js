// src/ui/state.js
// Simple in-memory UI state for demo usage.

let lastScanContext = null;

export function setLastScanContext(ctx) {
  lastScanContext = ctx || null;
}

export function getLastScanContext() {
  return lastScanContext;
}
