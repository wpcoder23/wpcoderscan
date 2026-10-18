// Liczenie oceny bezpieczeństwa na podstawie znalezisk.
import type { Finding, Severity } from '../rules/types';

// Wagi kary. Im cięższa podatność, tym mocniej zbija wynik.
const WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 0,
};

export interface Score {
  value: number; // 0 do 100, gdzie 100 to brak znalezisk
  counts: Record<Severity, number>;
  total: number;
}

export function scoreFindings(findings: Finding[]): Score {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let penalty = 0;
  for (const f of findings) {
    counts[f.severity]++;
    penalty += WEIGHT[f.severity];
  }
  // Prosta, monotoniczna funkcja. Jedna krytyczna od razu mocno obniża wynik.
  const value = Math.max(0, Math.round(100 - penalty));
  return { value, counts, total: findings.length };
}
