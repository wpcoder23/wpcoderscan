// Reguła: SQL injection w zapytaniach $wpdb budowanych bez prepare.
// Wykrywa wywołania $wpdb->query/get_results/get_row/get_col/get_var,
// w których zapytanie powstaje z danych użytkownika. Dane śledzimy lekką
// analizą skażenia w obrębie funkcji (taint.ts). Superglobal wprost w
// zapytaniu to wykrycie pewne. Zmienna wcześniej zasilona danymi z
// superglobala to heurystyka. Zwykła zmienna o nieznanym pochodzeniu
// (nazwa tabeli, parametr funkcji) nie jest zgłaszana, bo w realnych
// wtyczkach to prawie zawsze fałszywy alarm.
import { walk } from '../parser';
import { asNode, nodeStart, offsetName, type AnyNode } from './ast-utils';
import { originText, SQL_SPEC, TaintAnalyzer, viaText } from './taint';
import type { Finding, FileContext, Rule } from './types';

export const SINKS = new Set(['query', 'get_results', 'get_row', 'get_col', 'get_var']);

function isWpdbVar(node: unknown): boolean {
  const n = asNode(node);
  return !!n && n.kind === 'variable' && n.name === 'wpdb';
}

// Zwraca nazwę metody, jeśli węzeł to wywołanie $wpdb->metoda(...).
export function wpdbMethodCall(node: unknown): string | undefined {
  const n = asNode(node);
  if (!n || n.kind !== 'call') return undefined;
  const callee = asNode(n.what);
  if (!callee || callee.kind !== 'propertylookup') return undefined;
  if (!isWpdbVar(callee.what)) return undefined;
  return offsetName(callee.offset);
}

export const sqliRule: Rule = {
  id: 'wp.sqli.unprepared',
  titleKey: 'rule.wp.sqli.unprepared.title',
  severity: 'high',
  confidence: 'firm',
  cwe: ['CWE-89'],
  asvs: ['5.3.4'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const taint = new TaintAnalyzer(ctx.ast, SQL_SPEC);

    walk(ctx.ast, (node, stack) => {
      const method = wpdbMethodCall(node);
      if (!method || !SINKS.has(method)) return;

      const args = (node as AnyNode).arguments as unknown[] | undefined;
      const arg = asNode(args?.[0]);
      if (!arg) return;
      if (arg.kind === 'string' || arg.kind === 'number') return; // literał

      const hit = taint.analyze(arg, stack);
      if (!hit.direct && !hit.viaVar) return;

      const loc = nodeStart(arg) ?? nodeStart(node as AnyNode);
      const base = {
        ruleId: sqliRule.id,
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: sqliRule.cwe,
        asvs: sqliRule.asvs,
        fix: ctx.t('sqli.fix'),
      };
      if (hit.direct) {
        findings.push({
          ...base,
          severity: 'critical',
          confidence: 'firm',
          message: ctx.t('sqli.direct', { method }),
        });
      } else {
        findings.push({
          ...base,
          severity: 'high',
          confidence: 'heuristic',
          message: ctx.t('sqli.viaVar', { method, var: viaText(hit), origin: originText(hit, ctx.t) }),
        });
      }
    });
    return findings;
  },
};
