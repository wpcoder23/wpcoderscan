// Reguła: trasa REST API bez permission_callback albo z __return_true.
// register_rest_route bez permission_callback wystawia endpoint bez kontroli
// dostępu, więc to wykrycie pewne i łamie build. permission_callback ustawiony
// na __return_true na trasie tylko do odczytu (GET) to zwykle świadomie
// publiczne dane, więc go pomijamy. Na trasie zmieniającej dane (POST, PUT,
// PATCH, DELETE) to heurystyka, która tylko ostrzega.
import { walk } from '../parser';
import {
  arrayItems,
  asNode,
  calledName,
  entryKeyName,
  findEntry,
  nodeStart,
  offsetName,
  type AnyNode,
} from './ast-utils';
import type { Finding, FileContext, Rule } from './types';

const ENDPOINT_KEYS = new Set(['methods', 'callback', 'permission_callback']);

// Czy tablica wygląda na pojedynczą konfigurację endpointu.
function isEndpointConfig(arr: AnyNode): boolean {
  return arrayItems(arr).some((e) => {
    const k = entryKeyName(e);
    return !!k && ENDPOINT_KEYS.has(k);
  });
}

// Lista tablic konfiguracji endpointów w trzecim argumencie.
// Argument bywa jedną konfiguracją albo listą konfiguracji.
function endpointConfigs(argsArray: AnyNode): AnyNode[] {
  if (isEndpointConfig(argsArray)) return [argsArray];
  const nested: AnyNode[] = [];
  for (const entry of arrayItems(argsArray)) {
    const val = asNode(entry.value);
    if (val && val.kind === 'array' && isEndpointConfig(val)) nested.push(val);
  }
  return nested;
}

// Metody HTTP z wpisu 'methods'. Brak wpisu oznacza GET (domyślnie w WordPressie).
const READ_ONLY_METHODS = new Set(['GET', 'HEAD', 'READABLE']);

function methodNames(value: unknown, out: string[]): void {
  const v = asNode(value);
  if (!v) return;
  if (v.kind === 'string' && typeof v.value === 'string') {
    for (const part of v.value.split(',')) out.push(part.trim().toUpperCase());
  } else if (v.kind === 'staticlookup') {
    // WP_REST_Server::READABLE, ::CREATABLE, ::EDITABLE, ::DELETABLE, ::ALLMETHODS
    const nm = offsetName(v.offset);
    if (nm) out.push(nm.toUpperCase());
  } else if (v.kind === 'array') {
    for (const e of arrayItems(v)) methodNames(e.value, out);
  } else if (v.kind === 'bin') {
    methodNames(v.left, out);
    methodNames(v.right, out);
  } else {
    out.push('?'); // nieznane wyrażenie, traktujemy jak zmieniające dane
  }
}

function isReadOnly(cfg: AnyNode): boolean {
  const entry = findEntry(cfg, 'methods');
  if (!entry) return true;
  const names: string[] = [];
  methodNames(entry.value, names);
  return names.length > 0 && names.every((m) => READ_ONLY_METHODS.has(m));
}

function isReturnTrue(value: unknown): boolean {
  const v = asNode(value);
  return !!v && v.kind === 'string' && typeof v.value === 'string' && v.value === '__return_true';
}

export const restPermissionRule: Rule = {
  id: 'wp.rest.no_permission_callback',
  titleKey: 'rule.wp.rest.no_permission_callback.title',
  severity: 'high',
  confidence: 'firm',
  cwe: ['CWE-862'],
  asvs: ['4.1.1'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    walk(ctx.ast, (node) => {
      const n = node as AnyNode;
      if (calledName(n) !== 'register_rest_route') return;

      const args = Array.isArray(n.arguments) ? (n.arguments as unknown[]) : [];
      const argsArray = asNode(args[2]);
      if (!argsArray || argsArray.kind !== 'array') return; // nie tablica literalna, nie analizujemy

      for (const cfg of endpointConfigs(argsArray)) {
        const permission = findEntry(cfg, 'permission_callback');
        const loc = nodeStart(cfg) ?? nodeStart(n);
        const base = {
          ruleId: restPermissionRule.id,
          file: ctx.file,
          line: loc?.line ?? 1,
          column: loc?.column ?? 0,
          cwe: restPermissionRule.cwe,
          asvs: restPermissionRule.asvs,
        };
        if (!permission) {
          findings.push({
            ...base,
            severity: 'high',
            confidence: 'firm',
            message: ctx.t('rest.missing.message'),
            fix: ctx.t('rest.missing.fix'),
          });
        } else if (isReturnTrue(permission.value) && !isReadOnly(cfg)) {
          findings.push({
            ...base,
            severity: 'medium',
            confidence: 'heuristic',
            message: ctx.t('rest.openWrite.message'),
            fix: ctx.t('rest.openWrite.fix'),
          });
        }
      }
    });
    return findings;
  },
};
