// Reguła: SQL injection w zapytaniach $wpdb budowanych bez prepare.
// Wykrywa wywołania $wpdb->query/get_results/get_row/get_col/get_var,
// w których argument SQL powstaje z interpolacji lub sklejania ze zmienną.
// Pomija interpolację nazw tabel ($wpdb->posts itp.) oraz $wpdb->prepare().
import { walk } from '../parser';
import { asNode, baseVariable, nodeStart, offsetName, SUPERGLOBALS, type AnyNode } from './ast-utils';
import type { Finding, FileContext, Rule, Severity } from './types';

const SINKS = new Set(['query', 'get_results', 'get_row', 'get_col', 'get_var']);

function isWpdbVar(node: unknown): boolean {
  const n = asNode(node);
  return !!n && n.kind === 'variable' && n.name === 'wpdb';
}

// Zwraca nazwę metody, jeśli węzeł to wywołanie $wpdb->metoda(...).
function wpdbMethodCall(node: unknown): string | undefined {
  const n = asNode(node);
  if (!n || n.kind !== 'call') return undefined;
  const callee = asNode(n.what);
  if (!callee || callee.kind !== 'propertylookup') return undefined;
  if (!isWpdbVar(callee.what)) return undefined;
  return offsetName(callee.offset);
}

function isPrepareCall(node: unknown): boolean {
  return wpdbMethodCall(node) === 'prepare';
}

// Interpolacja $wpdb->tabela to nazwa tabeli, bezpieczna.
function isWpdbProp(node: unknown): boolean {
  const n = asNode(node);
  return !!n && n.kind === 'propertylookup' && isWpdbVar(n.what);
}

interface RiskPart {
  superglobal: boolean;
}

// Zbiera ryzykowne elementy dynamiczne z wyrażenia SQL.
function collectRisky(node: unknown, acc: RiskPart[]): void {
  const n = asNode(node);
  if (!n) return;
  if (Array.isArray(node)) {
    for (const e of node as unknown[]) collectRisky(e, acc);
    return;
  }
  switch (n.kind) {
    case 'string':
    case 'number':
    case 'boolean':
    case 'nowdoc':
      return;
    case 'propertylookup':
      if (isWpdbProp(n)) return; // nazwa tabeli, bezpieczne
      acc.push({ superglobal: false });
      return;
    case 'variable': {
      if (n.name === 'wpdb') return;
      const name = typeof n.name === 'string' ? n.name : '';
      acc.push({ superglobal: SUPERGLOBALS.has(name) });
      return;
    }
    case 'offsetlookup': {
      const base = baseVariable(n);
      const sg = !!base && base.kind === 'variable' && SUPERGLOBALS.has(base.name as string);
      acc.push({ superglobal: sg });
      return;
    }
    case 'call':
      if (isPrepareCall(n)) return;
      acc.push({ superglobal: false });
      return;
    case 'encapsed':
      collectRisky(n.value, acc);
      return;
    case 'bin':
      collectRisky(n.left, acc);
      collectRisky(n.right, acc);
      return;
    default:
      for (const k of Object.keys(n)) {
        if (k === 'loc' || k === 'leadingComments' || k === 'trailingComments') continue;
        collectRisky(n[k], acc);
      }
  }
}

function severityFor(arg: AnyNode, risky: RiskPart[]): Severity {
  if (risky.some((r) => r.superglobal)) return 'critical';
  if (arg.kind === 'encapsed' || arg.kind === 'bin') return 'high';
  return 'medium';
}

export const sqliRule: Rule = {
  id: 'wp.sqli.unprepared',
  title: 'Zapytanie do bazy bez $wpdb->prepare z danymi dynamicznymi',
  severity: 'high',
  confidence: 'firm',
  cwe: ['CWE-89'],
  asvs: ['5.3.4'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    walk(ctx.ast, (node) => {
      const method = wpdbMethodCall(node);
      if (!method || !SINKS.has(method)) return;

      const args = (node as AnyNode).arguments as unknown[] | undefined;
      const arg = asNode(args?.[0]);
      if (!arg) return;
      if (arg.kind === 'string' || arg.kind === 'number') return; // literał
      if (isPrepareCall(arg)) return; // $wpdb->query($wpdb->prepare(...))

      const risky: RiskPart[] = [];
      collectRisky(arg, risky);
      if (risky.length === 0) return; // tylko nazwy tabel $wpdb->..., bezpieczne

      const sev = severityFor(arg, risky);
      const loc = nodeStart(arg) ?? nodeStart(node as AnyNode);
      findings.push({
        ruleId: sqliRule.id,
        severity: sev,
        confidence: 'firm',
        message: `Wywołanie $wpdb->${method}() buduje zapytanie z danych dynamicznych bez prepare. Grozi SQL injection.`,
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: sqliRule.cwe,
        asvs: sqliRule.asvs,
        fix: 'Użyj $wpdb->prepare() z placeholderami %s, %d, %f i przekaż dane jako argumenty, zamiast sklejać je w tekst zapytania.',
      });
    });
    return findings;
  },
};
