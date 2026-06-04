// backend/utils/severityScore.js
// Severity scoring and sorting utilities shared across the engine and report generator.

const SEV_RANK = {
  critical: 1,
  high:     2,
  medium:   3,
  low:      4,
  info:     5,
};

function rankOf(sev) {
  return SEV_RANK[sev] || 99;
}

/** Sort findings highest severity first. */
function sortFindingsBySeverity(findings) {
  return [...findings].sort((a, b) => rankOf(a.severity) - rankOf(b.severity));
}

/** Compute a simple risk score (0–100) for a list of findings. */
function computeRiskScore(findings) {
  if (!findings || !findings.length) return 0;
  const weights = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };
  const raw = findings.reduce((sum, f) => sum + (weights[f.severity] || 0), 0);
  return Math.min(100, Math.round(raw));
}

module.exports = { rankOf, sortFindingsBySeverity, computeRiskScore };
