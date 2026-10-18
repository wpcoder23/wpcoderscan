// Weryfikacja podpowiedzi naprawy. Zmiana trafia do raportu tylko wtedy, gdy
// po jej nałożeniu kod nadal się parsuje bez błędów, znalezisko znika, a liczba
// znalezisk żadnej reguły nie rośnie. Dzięki temu nie podajemy złych poprawek.
import { analyzeSource } from '../engine/analyze';
import type { Finding, Patch, Rule } from '../rules/types';
import { applyEdits, patchesConflict } from './apply';

function countBy(findings: Finding[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const f of findings) m.set(f.ruleId, (m.get(f.ruleId) ?? 0) + 1);
  return m;
}

export interface VerifyInput {
  rel: string;
  abs: string;
  code: string;
  before: Finding[]; // wszystkie znaleziska pliku przed zmianą
  rules: Rule[];
}

export function verifyPatch(input: VerifyInput, finding: Finding, patch: Patch): boolean {
  if (patch.edits.length === 0) return false;
  // Zmiana nie może dodawać ani usuwać linii, bo diff zakłada stałą liczbę linii.
  if (patch.edits.some((e) => /[\r\n]/.test(e.replacement))) return false;

  const patched = applyEdits(input.code, patch.edits);
  if (patched === null || patched === input.code) return false;

  const after = analyzeSource(input.rel, input.abs, patched, input.rules);
  if (!after.parsed || after.parseErrors > 0 || after.errors.length > 0) return false;

  const was = countBy(input.before);
  const now = countBy(after.findings);
  if ((now.get(finding.ruleId) ?? 0) >= (was.get(finding.ruleId) ?? 0)) return false;
  for (const [rule, n] of now) {
    if (n > (was.get(rule) ?? 0)) return false;
  }
  return true;
}

// Zostawia tylko zweryfikowane i niekolidujące podpowiedzi. Zwraca nowe znaleziska
// z polem patch ustawionym tylko tam, gdzie bramki przeszły.
export function resolvePatches(input: VerifyInput): void {
  const withPatch = input.before.filter((f) => f.patch);
  if (withPatch.length === 0) return;

  // Plik z błędami składni: nie ufamy offsetom, żadnych podpowiedzi.
  const base = analyzeSource(input.rel, input.abs, input.code, input.rules);
  if (!base.parsed || base.parseErrors > 0) {
    for (const f of withPatch) delete f.patch;
    return;
  }

  const verified: Finding[] = [];
  for (const f of withPatch) {
    if (f.patch && verifyPatch(input, f, f.patch)) verified.push(f);
    else delete f.patch;
  }

  // Dwie podpowiedzi w tym samym miejscu: żadna nie jest bezpieczna bez decyzji człowieka.
  const conflicting = new Set<Finding>();
  for (let i = 0; i < verified.length; i++) {
    for (let j = i + 1; j < verified.length; j++) {
      const a = verified[i].patch!;
      const b = verified[j].patch!;
      if (patchesConflict(a, b)) {
        conflicting.add(verified[i]);
        conflicting.add(verified[j]);
      }
    }
  }
  for (const f of conflicting) delete f.patch;
}
