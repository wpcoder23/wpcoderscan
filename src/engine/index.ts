// Pętla silnika. Zbiera pliki, parsuje, uruchamia reguły, liczy wynik.
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { collectPhpFiles, type CollectOptions } from '../collector';
import { parsePhp } from '../parser';
import { allRules } from '../rules';
import type { Finding, FileContext, PhpNode, Rule } from '../rules/types';
import { scoreFindings, type Score } from './score';

export interface ScanOptions extends CollectOptions {
  rules?: Rule[];
  cwd?: string; // do liczenia ścieżek względnych
}

export interface ScanError {
  file: string;
  message: string;
}

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
  const files = await collectPhpFiles(target, opts);
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

    let ast: PhpNode;
    try {
      ast = parsePhp(code, rel);
    } catch (e) {
      errors.push({ file: rel, message: `błąd parsowania: ${(e as Error).message}` });
      continue;
    }

    const lines = code.split(/\r?\n/);
    const ctx: FileContext = {
      file: rel,
      absolutePath: abs,
      code,
      lines,
      ast,
      snippetAt(line: number) {
        return (lines[line - 1] ?? '').trim();
      },
    };

    for (const rule of rules) {
      try {
        const ruleFindings = rule.check(ctx);
        for (const f of ruleFindings) {
          if (!f.snippet) f.snippet = ctx.snippetAt(f.line);
        }
        findings.push(...ruleFindings);
      } catch (e) {
        errors.push({ file: rel, message: `reguła ${rule.id} rzuciła wyjątek: ${(e as Error).message}` });
      }
    }
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
