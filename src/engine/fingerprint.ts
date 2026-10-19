// Odcisk znaleziska, stabilny mimo przesunięć linii. Wejście: reguła, plik i treść linii.
// Używają go baseline oraz pole partialFingerprints w SARIF. Pierwsze wystąpienie dostaje czysty skrót.
// Kolejne identyczne w tym samym pliku dostają sufiks :2, :3 i tak dalej, jak w primaryLocationLineHash
// z GitHuba, żeby dwa takie same znaleziska nie zlały się w jeden alert.
import { createHash } from 'node:crypto';
import type { Finding } from '../rules/types';

export function baseFingerprint(f: Finding): string {
  return createHash('sha256')
    .update(`${f.ruleId}\n${f.file}\n${f.snippet ?? ''}`)
    .digest('hex')
    .slice(0, 16);
}

// Ustawia pole fingerprint. Numer wystąpienia liczymy w kolejności pliku i linii,
// niezależnie od tego, jak wynik jest później posortowany.
export function assignFingerprints(findings: Finding[]): void {
  const order = [...findings].sort(
    (a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.line - b.line || a.column - b.column || (a.ruleId < b.ruleId ? -1 : 1),
  );
  const seen = new Map<string, number>();
  for (const f of order) {
    const base = baseFingerprint(f);
    const n = (seen.get(base) ?? 0) + 1;
    seen.set(base, n);
    f.fingerprint = n === 1 ? base : `${base}:${n}`;
  }
}
