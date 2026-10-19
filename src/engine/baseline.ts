// Baseline: zapis znalezisk, które zespół zna i świadomie zostawia. Z baseline skaner zgłasza
// i łamie build tylko na nowych znaleziskach, więc da się wdrożyć bramkę w starym kodzie.
// Dopasowanie idzie po odcisku (reguła, plik, treść linii, numer wystąpienia), nie po numerze linii.
import type { Translate } from '../i18n';
import type { Finding } from '../rules/types';

export interface BaselineEntry {
  id: string; // odcisk znaleziska
  rule: string;
  file: string;
  line: number; // tylko informacyjnie, do przeglądu pliku przez człowieka
}

export interface Baseline {
  version: 1;
  tool: 'wpcoderscan';
  entries: BaselineEntry[];
}

export class BaselineError extends Error {}

export function createBaseline(findings: Finding[]): Baseline {
  const entries: BaselineEntry[] = findings
    .filter((f) => f.fingerprint)
    .map((f) => ({ id: f.fingerprint as string, rule: f.ruleId, file: f.file, line: f.line }))
    .sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.line - b.line || (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0));
  return { version: 1, tool: 'wpcoderscan', entries };
}

export function serializeBaseline(baseline: Baseline): string {
  return JSON.stringify(baseline, null, 2) + '\n';
}

export function parseBaseline(text: string, t: Translate): Baseline {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new BaselineError(t('baseline.invalid'));
  }
  const obj = raw as { version?: unknown; entries?: unknown };
  if (!obj || typeof obj !== 'object' || obj.version !== 1 || !Array.isArray(obj.entries)) {
    throw new BaselineError(t('baseline.invalid'));
  }
  const entries: BaselineEntry[] = [];
  for (const e of obj.entries as Array<Record<string, unknown>>) {
    if (!e || typeof e.id !== 'string' || !e.id) throw new BaselineError(t('baseline.invalid'));
    entries.push({
      id: e.id,
      rule: typeof e.rule === 'string' ? e.rule : '',
      file: typeof e.file === 'string' ? e.file : '',
      line: typeof e.line === 'number' ? e.line : 0,
    });
  }
  return { version: 1, tool: 'wpcoderscan', entries };
}

export interface BaselineResult {
  kept: Finding[]; // nowe znaleziska
  baselined: Finding[]; // znaleziska znane z baseline
  stale: number; // wpisy baseline bez dopasowania wśród aktywnych reguł
}

export interface BaselineScope {
  rules: ReadonlySet<string>; // reguły, które działały w tym skanie
  files: ReadonlySet<string>; // pliki, które w tym skanie przeczytano
}

// Zakres ogranicza liczenie nieaktualnych wpisów do reguł i plików, które w tym skanie były sprawdzane.
// Dzięki temu baseline zapisany z --extended nie zgłasza "nieaktualnych" wpisów w skanie bez tej flagi,
// a skan --diff nie uznaje za nieaktualne wpisów dla plików, których nie czytał.
export function applyBaseline(findings: Finding[], baseline: Baseline, scope: BaselineScope): BaselineResult {
  const known = new Set(baseline.entries.map((e) => e.id));
  const kept: Finding[] = [];
  const baselined: Finding[] = [];
  const matched = new Set<string>();
  for (const f of findings) {
    if (f.fingerprint && known.has(f.fingerprint)) {
      baselined.push(f);
      matched.add(f.fingerprint);
    } else {
      kept.push(f);
    }
  }
  const stale = baseline.entries.filter(
    (e) => !matched.has(e.id) && (e.rule === '' || scope.rules.has(e.rule)) && (e.file === '' || scope.files.has(e.file)),
  ).length;
  return { kept, baselined, stale };
}
