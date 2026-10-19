// Analiza jednego pliku z treści w pamięci. Używana przez skan oraz przez
// weryfikację podpowiedzi napraw, która sprawdza kod po zmianie.
import { createTranslator, DEFAULT_LANG, type Lang, type Translate } from '../i18n';
import { parsePhp } from '../parser';
import type { Finding, FileContext, PhpNode, Rule } from '../rules/types';

export interface ScanError {
  file: string;
  message: string;
}

// Zamienia surowy błąd na czytelny komunikat. Przepełnienie stosu zdarza się
// tylko na patologicznie głęboko zagnieżdżonym kodzie, nie na realnych plikach.
export function describeError(e: unknown, t: Translate = createTranslator(DEFAULT_LANG)): string {
  const msg = (e as Error)?.message ?? String(e);
  if (/call stack/i.test(msg)) return t('error.tooDeep');
  return msg;
}

export interface SourceAnalysis {
  findings: Finding[];
  errors: ScanError[];
  parseErrors: number; // liczba błędów składni zgłoszonych przez parser
  parsed: boolean;
}

export function analyzeSource(
  rel: string,
  abs: string,
  code: string,
  rules: Rule[],
  lang: Lang = DEFAULT_LANG,
): SourceAnalysis {
  const t = createTranslator(lang);
  const errors: ScanError[] = [];
  const findings: Finding[] = [];

  let ast: PhpNode;
  try {
    ast = parsePhp(code, rel);
  } catch (e) {
    errors.push({ file: rel, message: t('error.parse', { detail: describeError(e, t) }) });
    return { findings, errors, parseErrors: 0, parsed: false };
  }

  const lines = code.split(/\r?\n/);
  const ctx: FileContext = {
    file: rel,
    absolutePath: abs,
    code,
    lines,
    lang,
    t,
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
      errors.push({ file: rel, message: t('error.rule', { rule: rule.id, detail: describeError(e, t) }) });
    }
  }

  const parseErrors = Array.isArray((ast as unknown as { errors?: unknown }).errors)
    ? (ast as unknown as { errors: unknown[] }).errors.length
    : 0;
  return { findings, errors, parseErrors, parsed: true };
}
