// Analiza jednego pliku z treści w pamięci. Używana przez skan oraz przez
// weryfikację podpowiedzi napraw, która sprawdza kod po zmianie.
import { parsePhp } from '../parser';
import type { Finding, FileContext, PhpNode, Rule } from '../rules/types';

export interface ScanError {
  file: string;
  message: string;
}

// Zamienia surowy błąd na czytelny komunikat. Przepełnienie stosu zdarza się
// tylko na patologicznie głęboko zagnieżdżonym kodzie, nie na realnych plikach.
export function describeError(e: unknown): string {
  const msg = (e as Error)?.message ?? String(e);
  if (/call stack/i.test(msg)) return 'plik zbyt głęboko zagnieżdżony, pominięto';
  return msg;
}

export interface SourceAnalysis {
  findings: Finding[];
  errors: ScanError[];
  parseErrors: number; // liczba błędów składni zgłoszonych przez parser
  parsed: boolean;
}

export function analyzeSource(rel: string, abs: string, code: string, rules: Rule[]): SourceAnalysis {
  const errors: ScanError[] = [];
  const findings: Finding[] = [];

  let ast: PhpNode;
  try {
    ast = parsePhp(code, rel);
  } catch (e) {
    errors.push({ file: rel, message: `błąd parsowania: ${describeError(e)}` });
    return { findings, errors, parseErrors: 0, parsed: false };
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
      errors.push({ file: rel, message: `reguła ${rule.id}: ${describeError(e)}` });
    }
  }

  const parseErrors = Array.isArray((ast as unknown as { errors?: unknown }).errors)
    ? (ast as unknown as { errors: unknown[] }).errors.length
    : 0;
  return { findings, errors, parseErrors, parsed: true };
}
