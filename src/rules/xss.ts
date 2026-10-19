// Reguła: XSS z echo lub print na danych użytkownika bez ucieczki.
// Dane śledzimy lekką analizą skażenia (taint.ts). Zgłaszamy superglobal
// trafiający do echo albo print bez funkcji ucieczki, sanitizacji ani
// rzutowania liczbowego, a także zmienną wcześniej zasilona takimi danymi.
// To heurystyka, więc domyślnie tylko ostrzega i nie łamie build.
import { buildXssPatch } from '../fix/xss-patch';
import { walk } from '../parser';
import { asNode, baseVariable, calledName, callArgs, nodeStart, type AnyNode } from './ast-utils';
import { linkCallers } from './callers';
import { findShortcodeHandlers, returnsArray } from './shortcodes';
import { chainParts, literalString, originText, TaintAnalyzer, viaText, XSS_SPEC } from './taint';
import type { MessageKey } from '../i18n';
import type { Finding, FileContext, Patch, PhpNode, Rule, Severity } from './types';

// Ujścia XSS rozpoznawane w kodzie. Nazwę do komunikatu bierzemy z katalogu tłumaczeń.
type Sink = 'echo' | 'exit' | 'shortcode' | 'printf' | 'wp_die' | 'html' | 'do_shortcode';

const SINK_KEY: Record<Sink, MessageKey> = {
  echo: 'xss.sink.echo',
  exit: 'xss.sink.exit',
  shortcode: 'xss.sink.shortcode',
  printf: 'xss.sink.printf',
  wp_die: 'xss.sink.wp_die',
  html: 'xss.sink.html',
  do_shortcode: 'xss.sink.do_shortcode',
};

// Ujścia wywnioskowane z kształtu kodu, nie z nazwy funkcji. Raportujemy je z poziomem średnim.
const INFERRED_SINKS = new Set<Sink>(['html', 'do_shortcode']);

const SCOPE_KINDS = new Set(['function', 'closure', 'method', 'arrowfunc']);

// Literał ze znacznikiem HTML: <a href=, <div>, </p>, <br/>.
const HTML_TAG = /<\/?[a-zA-Z][a-zA-Z0-9-]*(?:[\s>/]|$)/;

// Czy wyrażenie składa tekst z literałem pasującym do wzorca: 'x' . $a, "x $a" albo sprintf( 'x %s', $a ).
function chainHasLiteral(expr: unknown, pattern: RegExp): boolean {
  const e = asNode(expr);
  if (!e) return false;
  const target = e.kind === 'call' && calledName(e) === 'sprintf' ? callArgs(e)[0] : e;
  const parts: AnyNode[] = [];
  chainParts(target, parts);
  return parts.some((part) => {
    const lit = literalString(part);
    return lit !== undefined && pattern.test(lit);
  });
}

// Czy w zakresie zmienna dostaje tekst z HTML: $html = '<div>' . .., $html .= '<a href="' . .. albo $html['x'] = ...
function scopeBuildsHtmlInto(scope: AnyNode, name: string): boolean {
  let found = false;
  walk(scope, (node) => {
    if (found) return;
    const n = node as AnyNode;
    if (n.kind !== 'assign') return;
    const left = asNode(n.left);
    const base = left ? baseVariable(left) : undefined;
    if (base && base.kind === 'variable' && base.name === name && chainHasLiteral(n.right, HTML_TAG)) found = true;
  });
  return found;
}

export const xssEchoRule: Rule = {
  id: 'wp.xss.echo_superglobal',
  titleKey: 'rule.wp.xss.echo_superglobal.title',
  severity: 'high',
  confidence: 'heuristic',
  cwe: ['CWE-79'],
  asvs: ['5.3.3'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const taint = new TaintAnalyzer(ctx.ast, XSS_SPEC);

    // Atrybuty shortcode zapisuje autor wpisu, więc skutkiem jest zapisany XSS.
    const isStored = (hit: { source?: string }) => hit.source === 'shortcode';

    // Funkcje obsługujące shortcode: atrybuty ($atts) to dane od autora wpisu.
    const shortcodeScopes = new Set<AnyNode>();
    for (const h of findShortcodeHandlers(ctx.ast, ctx.code)) {
      taint.seed(h.scope, h.param, 'shortcode');
      shortcodeScopes.add(h.scope);
    }
    linkCallers(taint, ctx.ast, ctx.code);

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
        fix: ctx.t('xss.fix'),
        ...(patch ? { patch } : {}),
      });
    };

    // sink to ujście, którego nazwa trafia do komunikatu. Podpowiedź naprawy budujemy tylko dla echo i print.
    const check = (expr: unknown, stmt: AnyNode, exprIndex: number, stack: PhpNode[], sink: Sink = 'echo') => {
      // Odpowiedzi JSON w die, wp_die i printf to zwykle AJAX, nie HTML.
      const call = asNode(expr);
      if (sink !== 'echo' && call && ['json_encode', 'wp_json_encode'].includes(calledName(call) ?? '')) return;
      const hit = taint.analyze(expr, stack);
      const at = asNode(expr) ?? stmt;
      const exprNode = asNode(expr);
      const patch = exprNode && (stmt.kind === 'echo' || stmt.kind === 'print')
        ? buildXssPatch({ ctx, taint, stmt, expr: exprNode, exprIndex, stack })
        : undefined;
      if (hit.direct) {
        report(
          at,
          hit.source || INFERRED_SINKS.has(sink) ? 'medium' : 'high',
          ctx.t('xss.direct', {
            origin: originText(hit, ctx.t),
            sink: ctx.t(SINK_KEY[sink]),
            kind: ctx.t(isStored(hit) ? 'xss.risk.stored' : 'xss.risk.reflected'),
          }),
          patch,
        );
      } else if (hit.viaVar) {
        report(
          at,
          'medium',
          ctx.t('xss.viaVar', {
            var: viaText(hit),
            origin: originText(hit, ctx.t),
            sink: ctx.t(SINK_KEY[sink]),
            kind: ctx.t(isStored(hit) ? 'xss.possible.stored' : 'xss.possible.reflected'),
          }),
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
        if (e && e.kind !== 'number') check(e, n, 0, stack, 'exit');
      } else if (n.kind === 'return' && n.expr) {
        let scope: PhpNode | undefined;
        for (let i = stack.length - 1; i >= 0 && !scope; i--) {
          if (SCOPE_KINDS.has(stack[i].kind)) scope = stack[i];
        }
        if (!scope) return;
        if (shortcodeScopes.has(scope as AnyNode)) {
          // Wynik shortcode trafia do treści strony jako HTML bez ucieczki.
          if (!returnsArray(n.expr, scope as AnyNode)) check(n.expr, n, 0, stack, 'shortcode');
        } else {
          // Funkcja zwraca tekst z tagami HTML zbudowany z danych bez ucieczki. Wywołujący zwykle go wypisuje.
          const expr = asNode(n.expr);
          const buildsHtml = !!expr && (expr.kind === 'variable' && typeof expr.name === 'string'
            ? scopeBuildsHtmlInto(scope as AnyNode, expr.name)
            : chainHasLiteral(expr, HTML_TAG));
          if (buildsHtml) check(n.expr, n, 0, stack, 'html');
        }
      } else if (n.kind === 'assign') {
        // $obiekt->content = '<div>' . $dane . '</div>': HTML zapisany we właściwości, którą ktoś potem wypisze.
        const left = asNode(n.left);
        if (left && (left.kind === 'propertylookup' || left.kind === 'staticlookup') && chainHasLiteral(n.right, HTML_TAG)) {
          check(n.right, n, 0, stack, 'html');
        }
      } else if (n.kind === 'call') {
        const fn = calledName(n);
        const args = callArgs(n);
        if (fn === 'printf' || fn === 'vprintf') {
          args.forEach((a, i) => check(a, n, i, stack, 'printf'));
        } else if (fn === 'wp_die' && args[0]) {
          // Komunikat wp_die jest wypisywany jako HTML bez ucieczki.
          check(args[0], n, 0, stack, 'wp_die');
        } else if (fn === 'do_shortcode' && args[0]) {
          // Dane wklejone do tekstu z kodami krótkimi mogą wstrzyknąć własny kod krótki albo atrybut.
          check(args[0], n, 0, stack, 'do_shortcode');
        }
      }
    });

    return findings;
  },
};
