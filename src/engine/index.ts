// Pętla silnika. Zbiera pliki, parsuje, uruchamia reguły, liczy wynik.
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { collectPhpFiles, type CollectOptions } from '../collector';
import { allRules } from '../rules';
import type { Finding, Rule } from '../rules/types';
import { analyzeSource, type ScanError } from './analyze';
import { resolvePatches } from '../fix/verify';
import { scoreFindings, type Score } from './score';

export interface ScanOptions extends CollectOptions {
  rules?: Rule[];
  cwd?: string; // do liczenia ścieżek względnych
  files?: string[]; // jawna lista plików do skanu, pomija kolektor (tryb diff)
}

export type { ScanError };

export interface ScanResult {
  target: string;
  filesScanned: number;
  findings: Finding[];
  score: Score;
  errors: ScanError[];
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export async function scan(target: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const cwd = opts.cwd ?? process.cwd();
  const rules = opts.rules ?? allRules;
  // W trybie diff dostajemy gotową listę plików. Inaczej zbiera ją kolektor.
  const files = opts.files ?? (await collectPhpFiles(target, opts));
  const findings: Finding[] = [];
  const errors: ScanError[] = [];

  for (const abs of files) {
    // Ścieżki zawsze z ukośnikiem w przód, żeby wynik był taki sam na każdym
    // systemie i zgodny z formatem SARIF.
    const rel = (path.relative(cwd, abs) || path.basename(abs)).split(path.sep).join('/');

    let code: string;
    try {
      code = await fs.readFile(abs, 'utf8');
    } catch (e) {
      errors.push({ file: rel, message: `nie udało się odczytać pliku: ${(e as Error).message}` });
      continue;
    }

    const analysis = analyzeSource(rel, abs, code, rules);
    errors.push(...analysis.errors);
    // Podpowiedzi napraw przechodzą bramki: parse, ponowny skan, brak konfliktów.
    resolvePatches({ rel, abs, code, before: analysis.findings, rules });
    findings.push(...analysis.findings);
  }

  // Najcięższe najpierw, potem po pliku i linii.
  findings.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );

  const score = scoreFindings(findings);
  return { target, filesScanned: files.length, findings, score, errors };
}
