// Reguła: XSS z echo lub print na danych użytkownika bez ucieczki.
// Dane śledzimy lekką analizą skażenia (taint.ts). Zgłaszamy superglobal
// trafiający do echo albo print bez funkcji ucieczki, sanitizacji ani
// rzutowania liczbowego, a także zmienną wcześniej zasilona takimi danymi.
// To heurystyka, więc domyślnie tylko ostrzega i nie łamie build.
import { buildXssPatch } from '../fix/xss-patch';
import { walk } from '../parser';
import { asNode, nodeStart, type AnyNode } from './ast-utils';
import { TaintAnalyzer, XSS_SPEC } from './taint';
import type { Finding, FileContext, Patch, PhpNode, Rule, Severity } from './types';

export const xssEchoRule: Rule = {
  id: 'wp.xss.echo_superglobal',
  title: 'Dane użytkownika w echo lub print bez ucieczki',
  severity: 'high',
  confidence: 'heuristic',
  cwe: ['CWE-79'],
  asvs: ['5.3.3'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const taint = new TaintAnalyzer(ctx.ast, XSS_SPEC);

    const report = (node: AnyNode, severity: Severity, message: string, patch?: Patch) => {
      const loc = nodeStart(node);
      findings.push({
        ruleId: xssEchoRule.id,
        severity,
        confidence: 'heuristic',
        message,
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: xssEchoRule.cwe,
        asvs: xssEchoRule.asvs,
        fix: 'Opakuj dane funkcją ucieczki zależną od kontekstu: esc_html w treści, esc_attr w atrybucie, esc_url w adresie. Dla HTML z tagami użyj wp_kses_post.',
        ...(patch ? { patch } : {}),
      });
    };

    const check = (expr: unknown, stmt: AnyNode, exprIndex: number, stack: PhpNode[]) => {
      const hit = taint.analyze(expr, stack);
      const at = asNode(expr) ?? stmt;
      const exprNode = asNode(expr);
      const patch = exprNode
        ? buildXssPatch({ ctx, taint, stmt, expr: exprNode, exprIndex, stack })
        : undefined;
      if (hit.direct) {
        report(
          at,
          'high',
          'Dane z superglobala trafiają do echo lub print bez funkcji ucieczki. Grozi odbitym XSS.',
          patch,
        );
      } else if (hit.viaVar) {
        report(
          at,
          'medium',
          `Zmienna $${hit.via ?? ''} zawiera dane z superglobala i trafia do echo lub print bez funkcji ucieczki. Możliwy odbity XSS.`,
          patch,
        );
      }
    };

    walk(ctx.ast, (node, stack) => {
      const n = node as AnyNode;
      if (n.kind === 'echo') {
        const exprs = Array.isArray(n.expressions) ? (n.expressions as unknown[]) : [];
        exprs.forEach((e, i) => check(e, n, i, stack));
      } else if (n.kind === 'print') {
        check(n.expression, n, 0, stack);
      }
    });

    return findings;
  },
};
