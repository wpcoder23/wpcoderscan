// Reguła rozszerzona: parametr funkcji wklejony do zapytania $wpdb bez prepare.
// Skaner nie widzi wywołujących funkcję, więc nie wie, czy do parametru trafiają
// dane użytkownika. Tak wygląda jednak wiele historycznych podatności SQL
// injection, dlatego reguła działa tylko w trybie rozszerzonym i zawsze jest
// heurystyką. Znaleziska, które pokrywa zwykła reguła SQL injection, pomijamy.
import { walk } from '../parser';
import { asNode, nodeStart, type AnyNode } from './ast-utils';
import { linkCallers } from './callers';
import { findShortcodeHandlers } from './shortcodes';
import { SINKS, wpdbMethodCall } from './sqli';
import { SQL_PARAM_SPEC, SQL_SPEC, TaintAnalyzer, viaText } from './taint';
import type { Finding, FileContext, Rule } from './types';

export const sqliParamRule: Rule = {
  id: 'wp.sqli.param_unprepared',
  titleKey: 'rule.wp.sqli.param_unprepared.title',
  severity: 'medium',
  confidence: 'heuristic',
  cwe: ['CWE-89'],
  asvs: ['5.3.4'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const base = new TaintAnalyzer(ctx.ast, SQL_SPEC);
    const extended = new TaintAnalyzer(ctx.ast, SQL_PARAM_SPEC);
    // Źródła znane zwykłej regule (shortcode, wywołania z tego samego pliku) nie są zgłaszane drugi raz.
    for (const h of findShortcodeHandlers(ctx.ast, ctx.code)) base.seed(h.scope, h.param, 'shortcode');
    linkCallers(base, ctx.ast, ctx.code);

    walk(ctx.ast, (node, stack) => {
      const method = wpdbMethodCall(node);
      if (!method || !SINKS.has(method)) return;

      const args = (node as AnyNode).arguments as unknown[] | undefined;
      const arg = asNode(args?.[0]);
      if (!arg || arg.kind === 'string' || arg.kind === 'number') return;

      const known = base.analyze(arg, stack);
      if (known.direct || known.viaVar) return; // zgłosi to zwykła reguła
      const hit = extended.analyze(arg, stack);
      if (!hit.viaVar || hit.source !== 'param') return;

      const loc = nodeStart(arg) ?? nodeStart(node as AnyNode);
      findings.push({
        ruleId: sqliParamRule.id,
        severity: 'medium',
        confidence: 'heuristic',
        message: ctx.t('sqli.param.message', { method, var: viaText(hit) }),
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: sqliParamRule.cwe,
        asvs: sqliParamRule.asvs,
        fix: ctx.t('sqli.param.fix'),
      });
    });
    return findings;
  },
};
