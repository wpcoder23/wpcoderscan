// Reguła: trasa REST API bez permission_callback albo z __return_true.
// register_rest_route bez permission_callback wystawia endpoint bez kontroli
// dostępu. permission_callback ustawiony na __return_true otwiera go dla
// każdego. To wykrycie strukturalne, pewne, więc łamie build.
import { walk } from '../parser';
import type { Finding, FileContext, Position, PhpNode, Rule } from './types';

type AnyNode = Record<string, unknown> & { kind?: string };

function asNode(v: unknown): AnyNode | undefined {
  return v && typeof v === 'object' ? (v as AnyNode) : undefined;
}

function nodeStart(node: AnyNode | undefined): Position | undefined {
  const loc = node?.loc as { start?: Position } | undefined;
  return loc?.start;
}

// Nazwa wołanej funkcji, jeśli węzeł to proste wywołanie po nazwie.
function calledName(node: AnyNode): string | undefined {
  if (node.kind !== 'call') return undefined;
  const what = asNode(node.what);
  if (what && what.kind === 'name' && typeof what.name === 'string') return what.name;
  return undefined;
}

// Elementy tablicy (array literal) jako lista węzłów entry.
function arrayItems(node: unknown): AnyNode[] {
  const n = asNode(node);
  if (!n || n.kind !== 'array') return [];
  const items = Array.isArray(n.items) ? (n.items as unknown[]) : [];
  return items.map(asNode).filter((e): e is AnyNode => !!e);
}

// Nazwa klucza w entry, gdy klucz jest literałem tekstowym.
function entryKeyName(entry: AnyNode): string | undefined {
  const k = asNode(entry.key);
  if (k && k.kind === 'string' && typeof k.value === 'string') return k.value;
  return undefined;
}

const ENDPOINT_KEYS = new Set(['methods', 'callback', 'permission_callback']);

// Czy tablica wygląda na pojedynczą konfigurację endpointu.
function isEndpointConfig(arr: AnyNode): boolean {
  return arrayItems(arr).some((e) => {
    const k = entryKeyName(e);
    return !!k && ENDPOINT_KEYS.has(k);
  });
}

function findEntry(arr: AnyNode, keyName: string): AnyNode | undefined {
  return arrayItems(arr).find((e) => entryKeyName(e) === keyName);
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

function isReturnTrue(value: unknown): boolean {
  const v = asNode(value);
  return !!v && v.kind === 'string' && typeof v.value === 'string' && v.value === '__return_true';
}

export const restPermissionRule: Rule = {
  id: 'wp.rest.no_permission_callback',
  title: 'Trasa REST API bez kontroli dostępu',
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
          confidence: 'firm' as const,
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
            message:
              'register_rest_route bez permission_callback. Endpoint REST jest dostępny bez kontroli uprawnień.',
            fix: 'Dodaj permission_callback i sprawdź uprawnienia, np. current_user_can albo weryfikację nonce. Dla endpointu celowo publicznego ustaw to świadomie.',
          });
        } else if (isReturnTrue(permission.value)) {
          findings.push({
            ...base,
            severity: 'medium',
            message:
              'permission_callback ustawiony na __return_true. Endpoint REST jest otwarty dla każdego.',
            fix: 'Jeśli endpoint ma być publiczny, zostaw to świadomie. W innym wypadku sprawdź uprawnienia przez current_user_can albo weryfikację nonce.',
          });
        }
      }
    });
    return findings;
  },
};
