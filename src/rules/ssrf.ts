// Reguła: żądanie HTTP wysyłane pod adres pochodzący od użytkownika (SSRF).
// O skutku rozstrzyga początek adresu, czyli schemat i host. Dane użytkownika doklejone za ustalonym hostem
// (https://api.example.com/?q=...) zmieniają tylko zapytanie, więc ich nie zgłaszamy. wp_safe_remote_*
// odrzuca adresy z sieci wewnętrznych, więc też zostają poza regułą. Host ustalony w zmiennej ($url = 'https://api...')
// też liczy się jako ustalony. Za bramką administratora wynik jest słabą wskazówką.
import { walk } from '../parser';
import { asNode, calledName, callArgs, entryKeyName, nodeStart, type AnyNode } from './ast-utils';
import { linkCallers } from './callers';
import { findShortcodeHandlers } from './shortcodes';
import { adminGated, downgradeGated, enclosingScope, gradeHit, hostIsFixed, leadingTaint, varsPassedTo } from './sink-utils';
import { KEY_SPEC, literalString, TaintAnalyzer } from './taint';
import type { Finding, FileContext, PhpNode, Rule } from './types';

// Funkcje, których pierwszy argument to adres albo host.
const HTTP_SINKS = new Set([
  'wp_remote_get',
  'wp_remote_post',
  'wp_remote_request',
  'wp_remote_head',
  'wp_remote_fopen',
  'get_headers',
  'curl_init',
  'fsockopen',
  'pfsockopen',
  'stream_socket_client',
]);

// Opakowania, które nie zmieniają hosta, więc oceniamy to, co jest w środku.
const URL_WRAPPERS = new Set([
  'esc_url_raw', 'esc_url', 'sanitize_url', 'trim', 'rtrim', 'ltrim', 'untrailingslashit', 'trailingslashit',
  'wp_unslash', 'strtolower', 'html_entity_decode', 'htmlspecialchars_decode', 'urldecode', 'rawurldecode',
]);

// Funkcje, którymi autor sprawdza adres albo wyciąga z niego host do porównania.
const URL_GUARDS = new Set(['wp_http_validate_url', 'parse_url', 'wp_parse_url']);

// Wyrażenie, które niesie adres. add_query_arg( klucz, wartość, adres ) i add_query_arg( tablica, adres )
// ocenia sam adres. Zwraca undefined, gdy adresu nie da się wskazać (add_query_arg bez adresu).
function urlExpr(start: AnyNode): AnyNode | undefined {
  let e: AnyNode = start;
  for (let i = 0; i < 6 && e.kind === 'call'; i++) {
    const name = calledName(e);
    const args = callArgs(e);
    if (name && URL_WRAPPERS.has(name) && args[0]) {
      e = args[0];
    } else if (name === 'add_query_arg') {
      const url = args.length >= 3 ? args[2] : args.length === 2 && args[0].kind === 'array' ? args[1] : undefined;
      if (!url) return undefined;
      e = url;
    } else if (name === 'sprintf' && args[0]) {
      const fmt = literalString(args[0]);
      if (fmt === undefined) return args[0];
      // Host jest ustalony, gdy format zamyka go przed pierwszym znacznikiem %.
      if (hostIsFixed(fmt.split('%')[0])) return undefined;
      return args[1];
    } else {
      break;
    }
  }
  return e;
}

// Adres z opcji CURLOPT_URL w curl_setopt( $ch, CURLOPT_URL, $url ) albo w tablicy curl_setopt_array.
function curlUrl(call: AnyNode): AnyNode | undefined {
  const name = calledName(call);
  const args = callArgs(call);
  const isUrlOpt = (n: AnyNode | undefined) => n?.kind === 'name' && String(n.name).replace(/^\\/, '') === 'CURLOPT_URL';
  if (name === 'curl_setopt' && isUrlOpt(args[1])) return args[2];
  if (name === 'curl_setopt_array') {
    const arr = asNode(args[1]);
    const items = arr && arr.kind === 'array' && Array.isArray(arr.items) ? (arr.items as unknown[]) : [];
    for (const it of items) {
      const entry = asNode(it);
      const key = asNode(entry?.key);
      if (entry && key && (isUrlOpt(key) || entryKeyName(entry) === 'CURLOPT_URL')) return asNode(entry.value);
    }
  }
  return undefined;
}

export const ssrfRule: Rule = {
  id: 'wp.http.ssrf',
  titleKey: 'rule.wp.http.ssrf.title',
  severity: 'high',
  confidence: 'firm',
  cwe: ['CWE-918'],
  asvs: ['12.6.1'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const taint = new TaintAnalyzer(ctx.ast, KEY_SPEC);
    for (const h of findShortcodeHandlers(ctx.ast, ctx.code)) taint.seed(h.scope, h.param, 'shortcode');
    linkCallers(taint, ctx.ast, ctx.code);

    walk(ctx.ast, (node, stack: PhpNode[]) => {
      const n = node as AnyNode;
      if (n.kind !== 'call') return;
      const name = calledName(n);
      if (!name) return;

      let urlNode: AnyNode | undefined;
      if (HTTP_SINKS.has(name)) urlNode = callArgs(n)[0];
      else if (name === 'curl_setopt' || name === 'curl_setopt_array') {
        urlNode = curlUrl(n);
      }
      if (!urlNode) return;

      const target = urlExpr(urlNode);
      if (!target) return;
      // Host przekazany do fsockopen to cały adres, więc oceniamy go w całości.
      const wholeValue = name === 'fsockopen' || name === 'pfsockopen' || name === 'stream_socket_client';
      const hit = wholeValue ? taint.analyze(target, stack, n) : leadingTaint(taint, target, stack, n, hostIsFixed);
      const found = gradeHit(hit, 'high', 'medium', ctx.t);
      if (!found) return;
      const scope = enclosingScope(stack, ctx.ast);
      if (hit.viaVar && hit.via && varsPassedTo(scope, URL_GUARDS).has(hit.via)) return;
      const grade = adminGated(scope, hit, taint) ? downgradeGated(found) : found;

      const loc = nodeStart(n);
      findings.push({
        ruleId: ssrfRule.id,
        severity: grade.severity,
        confidence: grade.confidence,
        message: ctx.t('ssrf.message', { name, from: grade.from }),
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: ['CWE-918'],
        asvs: ['12.6.1'],
        fix: ctx.t('ssrf.fix'),
      });
    });

    return findings;
  },
};
