// backend/utils/severityScore.js
// Weighted risk score + sort for findings.
// Score is 0–100. Factors: severity weights, unique categories, total count.

'use strict';

const WEIGHTS = {
  critical: 30,
  high:     15,
  medium:    6,
  low:       2,
  info:      0.5,
};

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Returns a 0–100 risk score for a set of findings.
 * Caps at 100. Critical findings above 2 give full score immediately.
 */
function computeRiskScore(findings) {
  if (!findings || !findings.length) return 0;

  const raw = findings.reduce((acc, f) => acc + (WEIGHTS[f.severity] || 0), 0);
  const uniqueCategories = new Set(findings.map((f) => f.category)).size;

  // Bonus for breadth (many different categories = worse)
  const breadthBonus = Math.min(uniqueCategories * 2, 20);

  const total = Math.min(raw + breadthBonus, 100);
  return Math.round(total);
}

/**
 * Sort findings by severity order then alphabetically by title.
 */
function sortFindingsBySeverity(findings) {
  return [...findings].sort((a, b) => {
    const ai = SEV_ORDER.indexOf(a.severity);
    const bi = SEV_ORDER.indexOf(b.severity);
    if (ai !== bi) return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
    return (a.title || '').localeCompare(b.title || '');
  });
}

module.exports = { computeRiskScore, sortFindingsBySeverity, WEIGHTS, SEV_ORDER };
