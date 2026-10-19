// Reguła: SQL injection w zapytaniach $wpdb budowanych bez prepare.
// Wykrywa wywołania $wpdb->query/get_results/get_row/get_col/get_var,
// w których zapytanie powstaje z danych użytkownika. Dane śledzimy lekką
// analizą skażenia w obrębie funkcji (taint.ts). Superglobal wprost w
// zapytaniu to wykrycie pewne. Zmienna wcześniej zasilona danymi z
// superglobala to heurystyka. Zwykła zmienna o nieznanym pochodzeniu
// (nazwa tabeli, parametr funkcji) nie jest zgłaszana, bo w realnych
// wtyczkach to prawie zawsze fałszywy alarm.
import { walk } from '../parser';
import { asNode, calledName, callArgs, nodeStart, offsetName, type AnyNode } from './ast-utils';
import { collectDefinitions, resolveCallbackNode } from './callbacks';
import { linkCallers } from './callers';
import { findShortcodeHandlers } from './shortcodes';
import { literalString, originText, SQL_SPEC, TaintAnalyzer, viaText, type TaintHit } from './taint';
import type { Finding, FileContext, PhpNode, Rule } from './types';

export const SINKS = new Set(['query', 'get_results', 'get_row', 'get_col', 'get_var']);

// Haki, których wynik WordPress wkleja do zapytania WP_Query, WP_Term_Query albo WP_Comment_Query.
const CLAUSE_HOOK = /^(?:posts_(?:where|search|orderby|join|groupby|fields|distinct|limits|clauses|request)(?:_paged|_request)?|terms_clauses|comments_clauses|get_terms_(?:orderby|fields)|found_posts_query)$/;

// Właściwości obiektów zapytań (WP_User_Query w pre_user_query, WP_Query), których tekst trafia do SQL.
const CLAUSE_PROPS = new Set(['query_where', 'query_orderby', 'query_from', 'query_fields', 'query_limit', 'query_groupby']);

const SCOPE_KINDS = new Set(['function', 'closure', 'method', 'arrowfunc']);

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
    // Atrybuty shortcode pochodzą od autora wpisu, więc są danymi użytkownika.
    for (const h of findShortcodeHandlers(ctx.ast, ctx.code)) taint.seed(h.scope, h.param, 'shortcode');
    linkCallers(taint, ctx.ast, ctx.code);

    const emit = (hit: TaintHit, at: AnyNode, wpdb: { method: string } | { target: string }) => {
      const loc = nodeStart(at);
      const base = {
        ruleId: sqliRule.id,
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: sqliRule.cwe,
        asvs: sqliRule.asvs,
        fix: ctx.t('sqli.fix'),
      };
      const clause = 'target' in wpdb;
      const vars = { ...wpdb, var: viaText(hit), origin: originText(hit, ctx.t) };
      if (hit.unquoted) {
        // Wartość przeszła przez esc_sql albo addslashes, ale stoi w zapytaniu poza cudzysłowem.
        findings.push({
          ...base,
          severity: 'high',
          confidence: hit.direct ? 'firm' : 'heuristic',
          message: ctx.t(clause ? (hit.direct ? 'sqli.clause.unquoted' : 'sqli.clause.unquoted.viaVar') : hit.direct ? 'sqli.unquoted' : 'sqli.unquoted.viaVar', vars),
          fix: ctx.t('sqli.unquoted.fix'),
        });
      } else if (hit.direct) {
        findings.push({
          ...base,
          severity: 'critical',
          confidence: 'firm',
          message: ctx.t(clause ? 'sqli.clause.direct' : 'sqli.direct', vars),
        });
      } else {
        findings.push({
          ...base,
          severity: 'high',
          confidence: 'heuristic',
          message: ctx.t(clause ? 'sqli.clause.viaVar' : 'sqli.viaVar', vars),
        });
      }
    };

    // Funkcje zarejestrowane na hakach filtrujących fragmenty zapytania. Ich zwrot trafia do SQL.
    const clauseScopes = new Map<AnyNode, string>();
    if (ctx.code.includes('add_filter') && /posts_|terms_clauses|comments_clauses|get_terms_|found_posts_query/.test(ctx.code)) {
      const defs = collectDefinitions(ctx.ast);
      walk(ctx.ast, (node, stack) => {
        const n = node as AnyNode;
        if (calledName(n) !== 'add_filter') return;
        const args = callArgs(n);
        const hook = literalString(args[0]);
        if (!hook || !CLAUSE_HOOK.test(hook) || !args[1]) return;
        const target = resolveCallbackNode(args[1], stack, defs);
        if (target) clauseScopes.set(target, hook);
      });
    }

    // Wyrażenie, które trafia do fragmentu zapytania: wynik filtra albo właściwość query_where i podobne.
    const checkClause = (expr: unknown, stack: PhpNode[], target: string) => {
      const e = asNode(expr);
      if (!e || e.kind === 'string' || e.kind === 'number') return;
      const hit = taint.analyze(e, stack);
      if (hit.direct || hit.viaVar) emit(hit, e, { target });
    };

    walk(ctx.ast, (node, stack) => {
      const n = node as AnyNode;
      if (n.kind === 'return' && n.expr && clauseScopes.size > 0) {
        let scope: PhpNode | undefined;
        for (let i = stack.length - 1; i >= 0 && !scope; i--) {
          if (SCOPE_KINDS.has(stack[i].kind)) scope = stack[i];
        }
        const hook = scope ? clauseScopes.get(scope as AnyNode) : undefined;
        if (hook) checkClause(n.expr, stack, hook);
        return;
      }
      if (n.kind === 'arrowfunc' && clauseScopes.has(n)) {
        checkClause(n.body, [...stack, node], clauseScopes.get(n) as string);
        return;
      }
      if (n.kind === 'assign') {
        const left = asNode(n.left);
        const prop = left && left.kind === 'propertylookup' ? offsetName(left.offset) : undefined;
        if (prop && CLAUSE_PROPS.has(prop)) checkClause(n.right, stack, prop);
        return;
      }

      const method = wpdbMethodCall(node);
      if (!method || !SINKS.has(method)) return;

      const args = (node as AnyNode).arguments as unknown[] | undefined;
      const arg = asNode(args?.[0]);
      if (!arg) return;
      if (arg.kind === 'string' || arg.kind === 'number') return; // literał

      const hit = taint.analyze(arg, stack);
      if (!hit.direct && !hit.viaVar) return;
      emit(hit, arg, { method });
    });
    return findings;
  },
};
