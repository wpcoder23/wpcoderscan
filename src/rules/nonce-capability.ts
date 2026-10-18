// Reguła: uchwyty akcji bez weryfikacji nonce i uprawnień.
// Patrzymy na add_action dla haków admin_post_* i wp_ajax_*. Rozwiązujemy
// uchwyt (nazwana funkcja w tym samym pliku albo domknięcie inline) i
// sprawdzamy, czy w ciele jest weryfikacja nonce oraz sprawdzenie zdolności.
// Haki nopriv obsługują niezalogowanych, więc wymagamy tam tylko nonce.
// Analiza jest jednoplikowa i nie zagląda w wywołane dalej funkcje, dlatego
// to heurystyka, która tylko ostrzega.
import { walk } from '../parser';
import { asNode, calledName, callArgs, nodeStart, type AnyNode } from './ast-utils';
import type { Finding, FileContext, Rule } from './types';

const NONCE_FUNCS = new Set(['check_admin_referer', 'check_ajax_referer', 'wp_verify_nonce']);
const CAP_FUNCS = new Set([
  'current_user_can',
  'current_user_can_for_blog',
  'author_can',
  'user_can',
]);

const SKIP_KEYS = new Set(['loc', 'leadingComments', 'trailingComments']);

type HookKind = 'priv' | 'nopriv';

function classifyHook(hook: string): HookKind | null {
  if (/^(?:admin_post_nopriv_|wp_ajax_nopriv_)/.test(hook)) return 'nopriv';
  if (/^(?:admin_post_|wp_ajax_)/.test(hook)) return 'priv';
  return null;
}

function functionName(n: AnyNode): string | undefined {
  const nm = n.name;
  if (typeof nm === 'string') return nm;
  const o = asNode(nm);
  if (o && typeof o.name === 'string') return o.name;
  return undefined;
}

// Czy gdziekolwiek w poddrzewie pada wywołanie jednej z podanych funkcji.
function containsCall(node: unknown, names: Set<string>): boolean {
  if (Array.isArray(node)) return (node as unknown[]).some((n) => containsCall(n, names));
  const n = asNode(node);
  if (!n) return false;
  if (n.kind === 'call') {
    const name = calledName(n);
    if (name && names.has(name)) return true;
  }
  for (const k of Object.keys(n)) {
    if (SKIP_KEYS.has(k)) continue;
    if (containsCall(n[k], names)) return true;
  }
  return false;
}

interface Handler {
  hook: string;
  kind: HookKind;
  callbackName?: string;
  body?: unknown;
  node: AnyNode;
}

export const nonceCapabilityRule: Rule = {
  id: 'wp.auth.unprotected_action',
  title: 'Uchwyt akcji bez weryfikacji nonce lub uprawnień',
  severity: 'high',
  confidence: 'heuristic',
  cwe: ['CWE-352', 'CWE-862'],
  asvs: ['4.2.2', '4.1.3'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const functionDefs = new Map<string, AnyNode>();
    const handlers: Handler[] = [];

    // Jeden przebieg zbiera definicje funkcji i rejestracje haków.
    walk(ctx.ast, (node) => {
      const n = node as AnyNode;

      if (n.kind === 'function') {
        const nm = functionName(n);
        if (nm) functionDefs.set(nm, n);
        return;
      }

      if (calledName(n) !== 'add_action') return;
      const args = callArgs(n);
      const hookNode = asNode(args[0]);
      if (!hookNode || hookNode.kind !== 'string' || typeof hookNode.value !== 'string') return;
      const kind = classifyHook(hookNode.value);
      if (!kind) return;

      const cb = asNode(args[1]);
      if (!cb) return;
      if (cb.kind === 'closure' || cb.kind === 'arrowfunc') {
        handlers.push({ hook: hookNode.value, kind, body: cb.body ?? cb, node: n });
      } else if (cb.kind === 'string' && typeof cb.value === 'string') {
        handlers.push({ hook: hookNode.value, kind, callbackName: cb.value, node: n });
      }
      // Callbacki metod (tablica [$this, 'metoda']) pomijamy, bo bez
      // rozwiązania nazwy groziłoby to fałszywym alarmem.
    });

    const emit = (node: AnyNode, message: string, cwe: string[], asvs: string[], fix: string) => {
      const loc = nodeStart(node);
      findings.push({
        ruleId: nonceCapabilityRule.id,
        severity: 'high',
        confidence: 'heuristic',
        message,
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe,
        asvs,
        fix,
      });
    };

    for (const h of handlers) {
      let body = h.body;
      if (!body && h.callbackName) {
        const fn = functionDefs.get(h.callbackName);
        if (!fn) continue; // uchwyt spoza tego pliku, nie oceniamy
        body = fn.body;
      }
      if (!body) continue;

      if (!containsCall(body, NONCE_FUNCS)) {
        emit(
          h.node,
          `Uchwyt haka "${h.hook}" nie weryfikuje nonce. Grozi CSRF.`,
          ['CWE-352'],
          ['4.2.2'],
          'Dodaj check_admin_referer lub check_ajax_referer na początku uchwytu, a w formularzu pole wp_nonce_field.',
        );
      }
      // Uprawnień wymagamy tylko tam, gdzie działa zalogowany użytkownik.
      if (h.kind === 'priv' && !containsCall(body, CAP_FUNCS)) {
        emit(
          h.node,
          `Uchwyt haka "${h.hook}" nie sprawdza uprawnień użytkownika. Grozi nieautoryzowanym działaniem.`,
          ['CWE-862'],
          ['4.1.3'],
          'Dodaj current_user_can z właściwą zdolnością na początku uchwytu i przerwij, gdy brak uprawnień.',
        );
      }
    }

    return findings;
  },
};
