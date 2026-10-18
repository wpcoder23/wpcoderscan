// Podpowiedzi napraw w raportach: podgląd zmiany przy znalezisku i plik z łatką.
// Nic tu nie zapisuje w plikach źródłowych. Łatka trafia tylko do wskazanego pliku.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { analyzeSource } from '../engine/analyze';
import type { ScanResult } from '../engine';
import { allRules } from '../rules';
import type { Finding, Patch } from '../rules/types';
import { applyEdits } from './apply';
import { renderUnifiedDiff } from './diff';

export function readSource(cwd: string, file: string): string | null {
  try {
    return readFileSync(path.resolve(cwd, file), 'utf8');
  } catch {
    return null;
  }
}

// Krótki podgląd zmiany: tylko linie, które się różnią, z numerem linii.
export function previewPatch(code: string, patch: Patch): string[] {
  const after = applyEdits(code, patch.edits);
  if (after === null) return [];
  const a = code.split('\n');
  const b = after.split('\n');
  const out: string[] = [];
  for (let i = 0; i < a.length && i < b.length; i++) {
    if (a[i] === b[i]) continue;
    out.push(`- ${i + 1}: ${a[i].replace(/\r$/, '').trim()}`);
    out.push(`+ ${i + 1}: ${b[i].replace(/\r$/, '').trim()}`);
  }
  return out;
}

export interface PatchFile {
  diff: string; // łatka w formacie unified diff, pusta gdy nie ma pełnych poprawek
  files: number;
  patches: number; // liczba zastosowanych poprawek
  manual: number; // poprawki pominięte, bo wymagają decyzji człowieka
}

function countRules(findings: Finding[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const f of findings) m.set(f.ruleId, (m.get(f.ruleId) ?? 0) + 1);
  return m;
}

// Składa jedną łatkę ze wszystkich pełnych poprawek. Plik trafia do łatki tylko
// wtedy, gdy po nałożeniu wszystkich jego poprawek naraz kod nadal się parsuje
// i żadna reguła nie ma więcej znalezisk niż przed zmianą.
export function buildPatchFile(result: ScanResult, cwd: string): PatchFile {
  const byFile = new Map<string, Finding[]>();
  let manual = 0;
  for (const f of result.findings) {
    if (!f.patch) continue;
    if (f.patch.safety !== 'complete') {
      manual++;
      continue;
    }
    const list = byFile.get(f.file) ?? [];
    list.push(f);
    byFile.set(f.file, list);
  }

  const parts: string[] = [];
  let patches = 0;
  for (const [file, list] of byFile) {
    const code = readSource(cwd, file);
    if (code === null) continue;
    const after = applyEdits(
      code,
      list.flatMap((f) => f.patch!.edits),
    );
    if (after === null || after === code) continue;

    const abs = path.resolve(cwd, file);
    const before = result.findings.filter((f) => f.file === file);
    const check = analyzeSource(file, abs, after, allRules);
    if (!check.parsed || check.parseErrors > 0 || check.errors.length > 0) continue;
    const was = countRules(before);
    const now = countRules(check.findings);
    let grew = false;
    for (const [rule, n] of now) if (n > (was.get(rule) ?? 0)) grew = true;
    if (grew || check.findings.length >= before.length) continue;

    parts.push(renderUnifiedDiff(file, code, after));
    patches += list.length;
  }
  return { diff: parts.join(''), files: parts.length, patches, manual };
}
