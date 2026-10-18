// Reguła: XSS z echo lub print na danych użytkownika bez ucieczki.
// Dane śledzimy lekką analizą skażenia (taint.ts). Zgłaszamy superglobal
// trafiający do echo albo print bez funkcji ucieczki, sanitizacji ani
// rzutowania liczbowego, a także zmienną wcześniej zasilona takimi danymi.
// To heurystyka, więc domyślnie tylko ostrzega i nie łamie build.
import { buildXssPatch } from '../fix/xss-patch';
import { walk } from '../parser';
import { asNode, calledName, callArgs, nodeStart, type AnyNode } from './ast-utils';
import { collectDefinitions, resolveCallbackNode } from './callbacks';
import { originText, TaintAnalyzer, XSS_SPEC } from './taint';
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

    // Atrybuty shortcode zapisuje autor wpisu, więc skutkiem jest zapisany XSS.
    const xssKind = (hit: { source?: string }) => (hit.source === 'shortcode' ? 'zapisanym XSS' : 'odbitym XSS');

    // Callbacki add_shortcode z tego pliku: pierwszy parametr ($atts) to dane od autora wpisu.
    const shortcodeScopes = new Set<AnyNode>();
    if (ctx.code.includes('add_shortcode')) {
      const defs = collectDefinitions(ctx.ast);
      walk(ctx.ast, (node, stack) => {
        const n = node as AnyNode;
        if (calledName(n) !== 'add_shortcode') return;
        const cb = asNode(callArgs(n)[1]);
        const target = cb ? resolveCallbackNode(cb, stack, defs) : undefined;
        if (!target) return;
        const params = Array.isArray(target.arguments) ? (target.arguments as unknown[]) : [];
        const id = asNode(asNode(params[0])?.name);
        if (typeof id?.name === 'string') {
          taint.seed(target, id.name, 'shortcode');
          shortcodeScopes.add(target);
        }
      });
    }

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

    // sink to nazwa ujścia w komunikacie. Podpowiedź naprawy budujemy tylko dla echo i print.
    const check = (expr: unknown, stmt: AnyNode, exprIndex: number, stack: PhpNode[], sink = 'echo lub print') => {
      // Odpowiedzi JSON w die, wp_die i printf to zwykle AJAX, nie HTML.
      const call = asNode(expr);
      if (sink !== 'echo lub print' && call && ['json_encode', 'wp_json_encode'].includes(calledName(call) ?? '')) return;
      const hit = taint.analyze(expr, stack);
      const at = asNode(expr) ?? stmt;
      const exprNode = asNode(expr);
      const patch = exprNode && (stmt.kind === 'echo' || stmt.kind === 'print')
        ? buildXssPatch({ ctx, taint, stmt, expr: exprNode, exprIndex, stack })
        : undefined;
      if (hit.direct) {
        report(
          at,
          hit.source ? 'medium' : 'high',
          `Dane ${originText(hit)} trafiają do ${sink} bez funkcji ucieczki. Grozi ${xssKind(hit)}.`,
          patch,
        );
      } else if (hit.viaVar) {
        report(
          at,
          'medium',
          `Zmienna $${hit.via ?? ''} zawiera dane ${originText(hit)} i trafia do ${sink} bez funkcji ucieczki. Możliwy ${xssKind(hit) === 'zapisanym XSS' ? 'zapisany' : 'odbity'} XSS.`,
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
      } else if (n.kind === 'exit') {
        // die( $tekst ) wypisuje tekst bez ucieczki.
        const e = asNode(n.expression);
        if (e && e.kind !== 'number') check(e, n, 0, stack, 'die lub exit');
      } else if (n.kind === 'return' && shortcodeScopes.size > 0) {
        // Wynik shortcode trafia do treści strony jako HTML bez ucieczki.
        let scope: PhpNode | undefined;
        for (let i = stack.length - 1; i >= 0 && !scope; i--) {
          if (['function', 'closure', 'method', 'arrowfunc'].includes(stack[i].kind)) scope = stack[i];
        }
        if (scope && shortcodeScopes.has(scope as AnyNode) && n.expr) {
          check(n.expr, n, 0, stack, 'zwracanego HTML shortcode');
        }
      } else if (n.kind === 'call') {
        const fn = calledName(n);
        const args = callArgs(n);
        if (fn === 'printf' || fn === 'vprintf') {
          args.forEach((a, i) => check(a, n, i, stack, 'printf'));
        } else if (fn === 'wp_die' && args[0]) {
          // Komunikat wp_die jest wypisywany jako HTML bez ucieczki.
          check(args[0], n, 0, stack, 'wp_die');
        }
      }
    });

    return findings;
  },
};
