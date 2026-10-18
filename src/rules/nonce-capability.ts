// Reguła: uchwyty akcji bez weryfikacji nonce i uprawnień.
// Patrzymy na add_action dla haków admin_post_* i wp_ajax_*. Rozwiązujemy
// uchwyt (nazwana funkcja w tym samym pliku albo domknięcie inline) i
// sprawdzamy, czy w ciele jest weryfikacja nonce oraz sprawdzenie zdolności.
// Haki nopriv obsługują niezalogowanych, więc wymagamy tam tylko nonce.
// Analiza jest jednoplikowa i nie zagląda w wywołane dalej funkcje, dlatego
// to heurystyka, która tylko ostrzega. Żeby ograniczyć fałszywe alarmy,
// zgłaszamy tylko uchwyty, które zmieniają stan (zapis opcji, użytkownika,
// wpisu, pliku albo bazy), i pomijamy te, które wołają pomocnika o nazwie
// sugerującej sprawdzenie nonce lub uprawnień.
import { walk } from '../parser';
import { asNode, calledName, callArgs, nodeStart, offsetName, type AnyNode } from './ast-utils';
import type { Finding, FileContext, Rule } from './types';

const NONCE_FUNCS = new Set(['check_admin_referer', 'check_ajax_referer', 'wp_verify_nonce']);
const CAP_FUNCS = new Set([
  'current_user_can',
  'current_user_can_for_blog',
  'author_can',
  'user_can',
]);

// Funkcje zmieniające stan serwisu. Uchwyt bez żadnej z nich zwykle tylko czyta.
const STATE_CHANGING = new Set([
  'update_option', 'add_option', 'delete_option', 'update_site_option', 'add_site_option',
  'delete_site_option', 'set_transient', 'delete_transient', 'set_site_transient',
  'delete_site_transient', 'wp_insert_user', 'wp_update_user', 'wp_delete_user', 'wp_create_user',
  'wp_set_password', 'wp_set_auth_cookie', 'update_user_meta', 'add_user_meta', 'delete_user_meta',
  'wp_insert_post', 'wp_update_post', 'wp_delete_post', 'wp_trash_post', 'wp_untrash_post',
  'update_post_meta', 'add_post_meta', 'delete_post_meta', 'wp_set_object_terms',
  'wp_insert_term', 'wp_update_term', 'wp_delete_term', 'wp_insert_comment', 'wp_delete_comment',
  'activate_plugin', 'deactivate_plugins', 'delete_plugins', 'switch_theme', 'wp_schedule_event',
  'wp_clear_scheduled_hook', 'wp_mail', 'unlink', 'file_put_contents', 'move_uploaded_file',
  'rename', 'copy', 'mkdir', 'rmdir', 'wp_delete_file', 'wp_handle_upload', 'wp_delete_attachment',
]);

// Metody $wpdb, które piszą do bazy.
const WPDB_WRITES = new Set(['query', 'insert', 'update', 'delete', 'replace']);

// Pomocnicy o takich nazwach najpewniej sprawdzają nonce albo uprawnienia.
const GUARD_NAME = /nonce|referer|security|verify|permission|authori[sz]|capabilit|user_can|is_user_logged_in|current_user|auth/i;

const SKIP_KEYS = new Set(['loc', 'leadingComments', 'trailingComments']);

// Nazwa wołanej metody ($obj->metoda, Klasa::metoda) niezależnie od obiektu.
function methodCallName(n: AnyNode): string | undefined {
  if (n.kind !== 'call') return undefined;
  const callee = asNode(n.what);
  if (!callee) return undefined;
  if (callee.kind === 'propertylookup' || callee.kind === 'staticlookup') {
    return offsetName(callee.offset);
  }
  return undefined;
}

function isWpdbWrite(n: AnyNode): boolean {
  const callee = asNode(n.what);
  if (!callee || callee.kind !== 'propertylookup') return false;
  const base = asNode(callee.what);
  const method = offsetName(callee.offset);
  return !!base && base.kind === 'variable' && base.name === 'wpdb' && !!method && WPDB_WRITES.has(method);
}

interface BodyFacts {
  changesState: boolean;
  callsGuardHelper: boolean;
}

// Jeden przebieg po ciele uchwytu zbiera fakty potrzebne do decyzji.
function inspectBody(node: unknown, facts: BodyFacts): void {
  if (Array.isArray(node)) {
    for (const n of node as unknown[]) inspectBody(n, facts);
    return;
  }
  const n = asNode(node);
  if (!n) return;
  if (n.kind === 'call') {
    const fn = calledName(n);
    if (fn) {
      if (STATE_CHANGING.has(fn)) facts.changesState = true;
      if (!NONCE_FUNCS.has(fn) && !CAP_FUNCS.has(fn) && GUARD_NAME.test(fn)) {
        facts.callsGuardHelper = true;
      }
    } else {
      const m = methodCallName(n);
      if (m && GUARD_NAME.test(m)) facts.callsGuardHelper = true;
      if (isWpdbWrite(n)) facts.changesState = true;
    }
  }
  for (const k of Object.keys(n)) {
    if (SKIP_KEYS.has(k)) continue;
    inspectBody(n[k], facts);
  }
}

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

      const facts: BodyFacts = { changesState: false, callsGuardHelper: false };
      inspectBody(body, facts);
      if (!facts.changesState || facts.callsGuardHelper) continue;

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
