// Reguła: XSS z echo lub print na danych z superglobala bez ucieczki.
// Start konserwatywny. Zgłasza tylko superglobal trafiający wprost do echo
// albo print, który nie jest opakowany w funkcję ucieczki, sanitizacji ani
// w rzutowanie liczbowe. To heurystyka, więc domyślnie tylko ostrzega.
import { walk } from '../parser';
import { asNode, calledName, callArgs, isSuperglobalAccess, nodeStart, type AnyNode } from './ast-utils';
import type { Finding, FileContext, Rule } from './types';

// Funkcje, które usuwają ryzyko XSS, gdy owijają dane.
const SAFE_FUNCS = new Set([
  'esc_html',
  'esc_attr',
  'esc_url',
  'esc_url_raw',
  'esc_js',
  'esc_textarea',
  'esc_html__',
  'esc_html_e',
  'esc_html_x',
  'esc_attr__',
  'esc_attr_e',
  'esc_attr_x',
  'wp_kses',
  'wp_kses_post',
  'wp_kses_data',
  'sanitize_text_field',
  'sanitize_textarea_field',
  'sanitize_email',
  'sanitize_key',
  'sanitize_title',
  'sanitize_file_name',
  'absint',
  'intval',
  'floatval',
  'boolval',
  'number_format',
  'wp_json_encode',
  'htmlspecialchars',
  'htmlentities',
]);

const NEUTRAL_CASTS = new Set(['int', 'integer', 'float', 'double', 'bool', 'boolean']);

const SKIP_KEYS = new Set(['loc', 'leadingComments', 'trailingComments']);

// Czy w wyrażeniu jest superglobal, który nie przeszedł przez ucieczkę.
function hasUnescapedSuperglobal(node: unknown, safe: boolean): boolean {
  if (Array.isArray(node)) return (node as unknown[]).some((e) => hasUnescapedSuperglobal(e, safe));
  const n = asNode(node);
  if (!n) return false;

  if ((n.kind === 'offsetlookup' || n.kind === 'variable') && isSuperglobalAccess(n)) {
    return !safe;
  }
  if (n.kind === 'call') {
    const name = calledName(n);
    const nextSafe = safe || (name ? SAFE_FUNCS.has(name) : false);
    return callArgs(n).some((a) => hasUnescapedSuperglobal(a, nextSafe));
  }
  if (n.kind === 'cast') {
    const neutral = NEUTRAL_CASTS.has(String(n.type ?? '').toLowerCase());
    return hasUnescapedSuperglobal(n.expr, safe || neutral);
  }
  for (const k of Object.keys(n)) {
    if (SKIP_KEYS.has(k)) continue;
    if (hasUnescapedSuperglobal(n[k], safe)) return true;
  }
  return false;
}

export const xssEchoRule: Rule = {
  id: 'wp.xss.echo_superglobal',
  title: 'Dane z superglobala w echo lub print bez ucieczki',
  severity: 'high',
  confidence: 'heuristic',
  cwe: ['CWE-79'],
  asvs: ['5.3.3'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];

    const report = (node: AnyNode) => {
      const loc = nodeStart(node);
      findings.push({
        ruleId: xssEchoRule.id,
        severity: 'high',
        confidence: 'heuristic',
        message:
          'Dane z superglobala trafiają do echo lub print bez funkcji ucieczki. Grozi odbitym XSS.',
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: xssEchoRule.cwe,
        asvs: xssEchoRule.asvs,
        fix: 'Opakuj dane funkcją ucieczki zależną od kontekstu: esc_html w treści, esc_attr w atrybucie, esc_url w adresie. Dla HTML z tagami użyj wp_kses_post.',
      });
    };

    walk(ctx.ast, (node) => {
      const n = node as AnyNode;
      if (n.kind === 'echo') {
        const exprs = Array.isArray(n.expressions) ? (n.expressions as unknown[]) : [];
        for (const e of exprs) {
          if (hasUnescapedSuperglobal(e, false)) report(asNode(e) ?? n);
        }
      } else if (n.kind === 'print') {
        if (hasUnescapedSuperglobal(n.expression, false)) report(asNode(n.expression) ?? n);
      }
    });

    return findings;
  },
};
