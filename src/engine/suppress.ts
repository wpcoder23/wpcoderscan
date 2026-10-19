// Komentarze wyciszające znaleziska w kodzie.
//   // wpcoderscan-ignore wp.xss.echo_superglobal -- powód
//   $x = $wpdb->query( $sql ); // wpcoderscan-ignore wp.sqli.unprepared
//   // wpcoderscan-ignore-file wp.secret.hardcoded
// Komentarz w osobnej linii dotyczy następnej linii. Komentarz za kodem dotyczy swojej linii.
// Wersja z -file dotyczy całego pliku. Wymagamy identyfikatora reguły, żeby jeden komentarz
// nie zakrył przypadkiem przyszłych znalezisk innych reguł. Gwiazdka działa jako wzorzec:
// wp.xss.* albo samo *.
import type { Finding } from '../rules/types';

export interface IgnoreDirective {
  line: number; // linia komentarza, od 1
  target: number; // linia, której dotyczy komentarz, 0 dla całego pliku
  scope: 'line' | 'file';
  patterns: string[];
  reason?: string;
}

export interface IgnoreProblem {
  line: number;
  kind: 'noRule' | 'unknownRule';
  rule?: string;
}

export interface ParsedIgnores {
  directives: IgnoreDirective[];
  problems: IgnoreProblem[];
}

export interface Suppression {
  line: number; // linia komentarza, który wyciszył znalezisko
  scope: 'line' | 'file';
  reason?: string;
}

export type SuppressedFinding = Finding & { suppressedBy: Suppression };

// Początek komentarza (//, # albo /*), słowo kluczowe i reszta linii.
const DIRECTIVE = /(\/\/|#|\/\*+)[ \t]*wpcoderscan-ignore(-file)?(?![\w-])(.*)$/;

function patternToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
}

export function matchesPattern(pattern: string, ruleId: string): boolean {
  return patternToRegExp(pattern).test(ruleId);
}

// Czyta komentarze wyciszające z treści pliku. knownRuleIds służy do wykrycia literówek.
export function parseIgnores(code: string, knownRuleIds: readonly string[]): ParsedIgnores {
  const directives: IgnoreDirective[] = [];
  const problems: IgnoreProblem[] = [];
  if (!code.includes('wpcoderscan-ignore')) return { directives, problems };

  const lines = code.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = DIRECTIVE.exec(line);
    if (!m) continue;
    const lineNo = i + 1;
    const isFile = m[2] === '-file';

    let rest = m[3].replace(/^[ \t]*:/, '');
    if (m[1].startsWith('/*')) rest = rest.replace(/\*+\/.*$/, '');
    rest = rest.replace(/\?>.*$/, '');
    const dash = /(^|\s)--(\s|$)/.exec(rest);
    const reason = dash ? rest.slice(dash.index + dash[0].length).trim() : '';
    const list = dash ? rest.slice(0, dash.index) : rest;
    const patterns = list.split(/[\s,]+/).filter(Boolean);
    if (patterns.length === 0) {
      problems.push({ line: lineNo, kind: 'noRule' });
      continue;
    }

    for (const p of patterns) {
      if (!knownRuleIds.some((id) => matchesPattern(p, id))) {
        problems.push({ line: lineNo, kind: 'unknownRule', rule: p });
      }
    }

    // Komentarz za kodem dotyczy swojej linii, komentarz w osobnej linii następnej.
    const before = line.slice(0, m.index).replace(/^\s*<\?(php|=)?/i, '').trim();
    const target = isFile ? 0 : before === '' ? lineNo + 1 : lineNo;
    directives.push({
      line: lineNo,
      target,
      scope: isFile ? 'file' : 'line',
      patterns,
      ...(reason ? { reason } : {}),
    });
  }
  return { directives, problems };
}

// Dzieli znaleziska pliku na zostające i wyciszone.
export function applyIgnores(
  findings: Finding[],
  directives: IgnoreDirective[],
): { kept: Finding[]; suppressed: SuppressedFinding[] } {
  if (directives.length === 0) return { kept: findings, suppressed: [] };
  const kept: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  for (const f of findings) {
    const d = directives.find(
      (x) => (x.scope === 'file' || x.target === f.line) && x.patterns.some((p) => matchesPattern(p, f.ruleId)),
    );
    if (d) {
      suppressed.push({ ...f, suppressedBy: { line: d.line, scope: d.scope, ...(d.reason ? { reason: d.reason } : {}) } });
    } else {
      kept.push(f);
    }
  }
  return { kept, suppressed };
}
