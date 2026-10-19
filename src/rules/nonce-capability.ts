// Reguła: uchwyty akcji bez weryfikacji nonce i uprawnień.
// Patrzymy na add_action dla haków admin_post_* i wp_ajax_*. Rozwiązujemy uchwyt (nazwana funkcja w tym samym
// pliku albo domknięcie inline) i sprawdzamy, czy jest w nim weryfikacja nonce oraz sprawdzenie zdolności.
// Haki nopriv obsługują niezalogowanych, więc wymagamy tam tylko nonce.
// Uchwyt może być też metodą klasy z tego samego pliku: [ $this, 'metoda' ], [ self::class, 'metoda' ],
// [ Klasa::class, 'metoda' ] albo 'Klasa::metoda', także z przestrzenią nazw.
// Analiza zagląda w funkcje i metody wołane z uchwytu, o ile leżą w tym samym pliku. Nonce i uprawnienia
// szukamy do trzech poziomów w głąb. Zmianę stanu liczymy do dwóch poziomów i tylko w funkcji, która dostaje
// dane z żądania w argumencie albo sama je czyta. Dalej analiza nie sięga, dlatego to heurystyka, która tylko
// ostrzega. Żeby ograniczyć fałszywe alarmy, zgłaszamy tylko uchwyty, które zmieniają stan (zapis opcji,
// użytkownika, wpisu, pliku albo bazy), pomijamy te, które wołają pomocnika o nazwie sugerującej sprawdzenie
// nonce lub uprawnień (także w camelCase), i pomijamy uchwyty zamykające powiadomienie, baner albo wskazówkę.
// Uprawnień nie wymagamy od uchwytu, który ten sam callback rejestruje też dla niezalogowanych, bo taki uchwyt
// jest publiczny z założenia.
import { walk } from '../parser';
import { asNode, calledName, callArgs, nodeStart, offsetName, type AnyNode } from './ast-utils';
import { enclosingClass, functionName, resolveMethodCallback, shortClassName, type MethodRef } from './callbacks';
import { paramInfos } from './taint';
import type { Finding, FileContext, Rule, Severity } from './types';

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
  'update_term_meta', 'add_term_meta', 'delete_term_meta', 'update_comment_meta', 'add_comment_meta',
  'delete_comment_meta', 'update_metadata', 'add_metadata', 'delete_metadata', 'update_user_option',
  'delete_user_option', 'update_blog_option', 'add_blog_option', 'delete_blog_option',
  'update_network_option', 'wp_set_post_terms', 'wp_set_post_categories', 'wp_insert_attachment',
  'set_post_thumbnail', 'delete_post_thumbnail', 'wp_update_comment', 'wp_set_comment_status',
  'wp_trash_comment', 'wp_spam_comment', 'wp_untrash_comment', 'wp_reset_password', 'reset_password',
  'add_role', 'remove_role', 'wp_mkdir_p', 'fwrite', 'fputs', 'update_attached_file',
  'wp_update_attachment_metadata', 'wp_unschedule_event', 'wp_schedule_single_event', 'wp_clear_auth_cookie',
]);

// Metody obiektów, które zmieniają stan: konto użytkownika ($user->add_role()) i zamówienie WooCommerce.
const STATE_METHODS = new Set([
  'add_role', 'set_role', 'remove_role', 'add_cap', 'remove_cap', 'remove_all_caps', 'update_status', 'payment_complete',
]);

// Metody $wpdb, które piszą do bazy.
const WPDB_WRITES = new Set(['query', 'insert', 'update', 'delete', 'replace']);

// Pomocnicy o takich nazwach najpewniej sprawdzają nonce albo uprawnienia. Nazwy, które tylko brzmią podobnie,
// nie liczą się: wp_get_current_user, get_current_user_id, wp_get_referer, is_admin (to pytanie o obszar
// administracyjny, nie o prawa), get_the_author, get_access_token, wp_kses_allowed_html.
const GUARD_NAME = /nonce|(?<!get_)referer|security|verify|permission|permit|authori[sz]|capabilit|user_can|is_user_logged_in|has_cap|before_running|current_user_(?:can|is|has)|is_current_user|auth(?!or)|access(?!_token)|(?:is|user|check|has|ip|role)_allowed|allowed_(?:user|role|to|ip)|(?:^|_)can_|is_admin_user|is_admin_role|user_is_admin|is_administrator|is_super_admin|valid\w*_?ajax/i;

// Nazwa w camelCase (isUserAllowedToEdit) dostaje te same wzorce co nazwa w snake_case (is_user_allowed_to_edit).
function snakeCase(name: string): string {
  return name.replace(/([a-z0-9])([A-Z])/g, '$1_$2');
}

// Nazwa wołanej funkcji z zachowaną wielkością liter i bez przestrzeni nazw. calledName zwraca małe litery,
// a z nich nie da się odczytać słów w camelCase.
function rawCalledName(n: AnyNode): string | undefined {
  const what = asNode(n.what);
  return what && what.kind === 'name' && typeof what.name === 'string' ? what.name.replace(/^.*\\/, '') : undefined;
}

// Pomocnik o nazwie is_admin wołany jako metoda własnej klasy zwykle opakowuje sprawdzenie roli.
function isGuardName(name: string, method: boolean): boolean {
  const snake = snakeCase(name);
  return GUARD_NAME.test(snake) || (method && snake.toLowerCase() === 'is_admin');
}

const SKIP_KEYS = new Set(['loc', 'leadingComments', 'trailingComments']);

// Dane z żądania, które mogą sterować zmianą stanu.
const REQUEST_VARS = new Set(['_GET', '_POST', '_REQUEST', '_FILES']);

// Zapisy opcji, transjentów i meta użytkownika. Uchwyt, który robi tylko takie zapisy pod kluczem niezależnym od
// żądania i nazywa się jak zamknięcie powiadomienia, zapamiętuje stan interfejsu, a nie dane serwisu.
const UI_WRITES = new Set([
  'update_option', 'add_option', 'delete_option', 'update_site_option', 'add_site_option', 'delete_site_option',
  'set_transient', 'delete_transient', 'set_site_transient', 'delete_site_transient',
  'update_user_meta', 'add_user_meta', 'delete_user_meta', 'update_user_option', 'delete_user_option',
]);
const UI_HOOK = /dismiss|notice|banner|pointer|welcome|tooltip|promo|remind|never_show|floatbar|(?:^|[_-])(?:tour|cta|later)(?:[_-]|$)/i;

// Zapisy metadanych i opcji użytkownika, z identyfikatorem użytkownika w pierwszym argumencie i kluczem w drugim.
// Zapis do konta zalogowanego użytkownika zmienia tylko jego własne dane.
const USER_SCOPED_WRITES = new Set(['update_user_meta', 'add_user_meta', 'delete_user_meta', 'update_user_option', 'delete_user_option']);

// Ile poziomów wołanych funkcji i metod z tego samego pliku sprawdzamy w poszukiwaniu nonce i uprawnień oraz ile
// ich najwyżej. Zmianę stanu liczymy płycej, bo im dalej od uchwytu, tym słabszy ślad.
const MAX_DEPTH = 3;
const MAX_BODIES = 30;
const STATE_DEPTH = 2;

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

// Czy wyrażenie to identyfikator zalogowanego użytkownika: get_current_user_id(), wp_get_current_user()->ID,
// $current_user->ID albo ID obiektu przypisanego z wp_get_current_user().
function isCurrentUserId(expr: AnyNode | undefined, userObjs: Set<string>): boolean {
  if (!expr) return false;
  if (expr.kind === 'call') return calledName(expr) === 'get_current_user_id';
  if (expr.kind === 'propertylookup' && offsetName(expr.offset) === 'ID') {
    const what = asNode(expr.what);
    if (what?.kind === 'call') return calledName(what) === 'wp_get_current_user';
    if (what?.kind === 'variable') return what.name === 'current_user' || userObjs.has(String(what.name));
  }
  return false;
}

interface Reach {
  writes: boolean[]; // jeden wpis na zmianę stanu: true, gdy to zapis stanu interfejsu (UI_WRITES pod stałym kluczem)
  callsGuardHelper: boolean;
  hasNonce: boolean;
  hasCap: boolean;
  selfIds: Set<string>; // zmienne przypisane z identyfikatora zalogowanego użytkownika
  userObjs: Set<string>; // zmienne przypisane z wp_get_current_user()
  reqVars: Set<string>; // zmienne przypisane z wyrażenia, które sięga po dane z żądania
}

// Czy wyrażenie sięga po dane z żądania wprost albo przez zmienną przypisaną z takich danych.
function exprHasRequest(node: unknown, reqVars: Set<string>): boolean {
  if (Array.isArray(node)) return node.some((x) => exprHasRequest(x, reqVars));
  const n = asNode(node);
  if (!n) return false;
  if (n.kind === 'variable' && typeof n.name === 'string' && (REQUEST_VARS.has(n.name) || reqVars.has(n.name))) return true;
  for (const k of Object.keys(n)) {
    if (SKIP_KEYS.has(k)) continue;
    if (exprHasRequest(n[k], reqVars)) return true;
  }
  return false;
}

// Jeden przebieg po ciele zbiera fakty potrzebne do decyzji i wywołania, które trzeba jeszcze rozwiązać.
function inspect(node: unknown, reach: Reach, calls: AnyNode[]): void {
  if (Array.isArray(node)) {
    for (const n of node as unknown[]) inspect(n, reach, calls);
    return;
  }
  const n = asNode(node);
  if (!n) return;
  if (n.kind === 'call') {
    calls.push(n);
    const fn = calledName(n);
    if (fn) {
      if (NONCE_FUNCS.has(fn)) reach.hasNonce = true;
      else if (CAP_FUNCS.has(fn)) reach.hasCap = true;
      else if (isGuardName(rawCalledName(n) ?? fn, false)) reach.callsGuardHelper = true;
      if (STATE_CHANGING.has(fn)) {
        const args = callArgs(n);
        const owner = args[0];
        const own = USER_SCOPED_WRITES.has(fn) && (isCurrentUserId(owner, reach.userObjs) || (owner?.kind === 'variable' && reach.selfIds.has(String(owner.name))));
        if (!own) {
          const key = USER_SCOPED_WRITES.has(fn) ? args[1] : owner;
          reach.writes.push(UI_WRITES.has(fn) && !exprHasRequest(key, reach.reqVars));
        }
      }
    } else {
      const m = methodCallName(n);
      if (m) {
        if (isGuardName(m, true)) reach.callsGuardHelper = true;
        if (STATE_METHODS.has(m)) reach.writes.push(false);
      }
      if (isWpdbWrite(n)) reach.writes.push(false);
    }
  } else if (n.kind === 'assign') {
    const left = asNode(n.left);
    if (left?.kind === 'variable' && typeof left.name === 'string') {
      const right = asNode(n.right);
      if (isCurrentUserId(right, reach.userObjs)) reach.selfIds.add(left.name);
      if (right?.kind === 'call' && calledName(right) === 'wp_get_current_user') reach.userObjs.add(left.name);
      if (exprHasRequest(n.right, reach.reqVars)) reach.reqVars.add(left.name);
    }
  } else if (n.kind === 'propertylookup') {
    // $user->roles i $user->allcaps: sprawdzenie roli napisane ręcznie.
    const prop = offsetName(n.offset);
    if (prop === 'roles' || prop === 'allcaps') reach.callsGuardHelper = true;
  }
  for (const k of Object.keys(n)) {
    if (SKIP_KEYS.has(k)) continue;
    inspect(n[k], reach, calls);
  }
}

// Haki obsługujące żądania AJAX i admin-post. Hak nopriv obsługuje niezalogowanych.
type HookKind = 'priv' | 'nopriv';

function classifyHook(hook: string): HookKind | null {
  if (/^(?:admin_post_nopriv_|wp_ajax_nopriv_)/.test(hook)) return 'nopriv';
  if (/^(?:admin_post_|wp_ajax_)/.test(hook)) return 'priv';
  return null;
}

interface Handler {
  hook: string;
  kind: HookKind;
  key?: string; // tożsamość callbacku, żeby znaleźć ten sam uchwyt pod hakiem nopriv
  callbackName?: string;
  methodRef?: MethodRef;
  body?: unknown;
  cls?: string; // klasa otaczająca domknięcie, żeby rozwiązać $this
  node: AnyNode;
}

type MethodTable = Map<string, Map<string, AnyNode>>;

// Definicja funkcji albo metody z tego samego pliku, którą woła dane wywołanie.
function resolveCall(call: AnyNode, cls: string | undefined, fns: Map<string, AnyNode>, methods: MethodTable): { node: AnyNode; cls?: string } | undefined {
  const plain = calledName(call);
  if (plain) {
    const fn = fns.get(plain);
    return fn ? { node: fn } : undefined;
  }
  const callee = asNode(call.what);
  const name = callee ? offsetName(callee.offset) : undefined;
  if (!callee || !name) return undefined;
  const key = name.toLowerCase();
  const what = asNode(callee.what);
  let target: string | undefined;
  if (callee.kind === 'propertylookup') {
    if (what?.kind === 'variable' && what.name === 'this') target = cls;
  } else if (callee.kind === 'staticlookup') {
    if (what && (what.kind === 'selfreference' || what.kind === 'staticreference')) target = cls;
    else if (what?.kind === 'name' && typeof what.name === 'string') target = shortClassName(what.name);
  }
  if (!target) return undefined;
  const own = methods.get(target)?.get(key);
  if (own) return { node: own, cls: target };
  // Metoda odziedziczona po klasie z tego samego pliku: bierzemy ją, jeśli definiuje ją dokładnie jedna klasa.
  const owners = [...methods.entries()].filter(([, table]) => table.has(key));
  return owners.length === 1 ? { node: owners[0][1].get(key) as AnyNode, cls: owners[0][0] } : undefined;
}

export const nonceCapabilityRule: Rule = {
  id: 'wp.auth.unprotected_action',
  titleKey: 'rule.wp.auth.unprotected_action.title',
  severity: 'high',
  confidence: 'heuristic',
  cwe: ['CWE-352', 'CWE-862'],
  asvs: ['4.2.2', '4.1.3'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const functionDefs = new Map<string, AnyNode>();
    const methodDefs: MethodTable = new Map();
    const handlers: Handler[] = [];

    // Jeden przebieg zbiera definicje funkcji i metod oraz rejestracje haków.
    walk(ctx.ast, (node, stack) => {
      const n = node as AnyNode;

      if (n.kind === 'class' || n.kind === 'trait') {
        const cname = functionName(n)?.toLowerCase();
        const members = Array.isArray(n.body) ? (n.body as unknown[]) : [];
        if (cname) {
          const methods = methodDefs.get(cname) ?? new Map<string, AnyNode>();
          for (const m of members) {
            const mn = asNode(m);
            const mname = mn && mn.kind === 'method' ? functionName(mn) : undefined;
            if (mn && mname) methods.set(mname.toLowerCase(), mn);
          }
          methodDefs.set(cname, methods);
        }
        return;
      }

      if (n.kind === 'function') {
        const nm = functionName(n);
        if (nm) functionDefs.set(nm.toLowerCase(), n);
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
        handlers.push({ hook: hookNode.value, kind, body: cb.body ?? cb, cls: enclosingClass(stack), node: n });
      } else if (cb.kind === 'string' && typeof cb.value === 'string' && !cb.value.includes('::')) {
        const callbackName = cb.value.replace(/^\\/, '').toLowerCase();
        handlers.push({ hook: hookNode.value, kind, key: 'fn:' + callbackName, callbackName, node: n });
      } else {
        const methodRef = resolveMethodCallback(cb, stack);
        if (methodRef) handlers.push({ hook: hookNode.value, kind, key: 'm:' + methodRef.cls + '::' + methodRef.method.toLowerCase(), methodRef, node: n });
      }
      // Callbacki, których klasy nie da się rozwiązać w tym pliku (na przykład
      // [ $this->obiekt, 'metoda' ]), pomijamy, bo groziłoby to fałszywym alarmem.
    });

    // Fakty z uchwytu i z funkcji oraz metod z tego samego pliku, które woła.
    const reachOf = (body: unknown, cls: string | undefined): Reach => {
      const reach: Reach = { writes: [], callsGuardHelper: false, hasNonce: false, hasCap: false, selfIds: new Set(), userObjs: new Set(), reqVars: new Set() };
      const seen = new Set<unknown>([body]);
      let frontier: Array<{ body: unknown; cls?: string; fed: boolean; params: string[] }> = [{ body, cls, fed: true, params: [] }];
      for (let depth = 0; depth <= MAX_DEPTH && frontier.length > 0; depth++) {
        const next: Array<{ body: unknown; cls?: string; fed: boolean; params: string[] }> = [];
        for (const item of frontier) {
          const calls: AnyNode[] = [];
          const before = reach.writes.length;
          // Parametry pomocnika, który dostał dane z żądania, niosą je dalej.
          if (item.fed) for (const name of item.params) reach.reqVars.add(name);
          inspect(item.body, reach, calls);
          // Zmiana stanu w pomocniku liczy się, gdy pomocnik jest płytko i dostaje dane z żądania albo sam je czyta.
          // Pomocnik, który tylko porządkuje własne dane wtyczki, nie mówi nic o tym, kto steruje uchwytem.
          if (depth > 0 && (depth > STATE_DEPTH || !(item.fed || exprHasRequest(item.body, new Set())))) reach.writes.length = before;
          if (depth === MAX_DEPTH) continue;
          for (const call of calls) {
            const target = resolveCall(call, item.cls, functionDefs, methodDefs);
            if (!target || seen.has(target.node) || seen.size >= MAX_BODIES) continue;
            seen.add(target.node);
            next.push({
              body: target.node.body,
              cls: target.cls,
              fed: exprHasRequest(callArgs(call), reach.reqVars),
              params: paramInfos(target.node).map((p) => p.name),
            });
          }
        }
        frontier = next;
      }
      return reach;
    };

    const emit = (node: AnyNode, message: string, cwe: string[], asvs: string[], fix: string, severity: Severity = 'high') => {
      const loc = nodeStart(node);
      findings.push({
        ruleId: nonceCapabilityRule.id,
        severity,
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

    // Ten sam callback pod hakiem nopriv jest publiczny z założenia (formularz, logowanie, koszyk). Uprawnień
    // nie wymagamy wtedy od wariantu dla zalogowanych, a brak nonce zgłasza hak nopriv.
    const publicKeys = new Set(handlers.filter((x) => x.kind === 'nopriv' && x.key).map((x) => x.key));

    for (const h of handlers) {
      let body = h.body;
      let cls = h.cls;
      // Zgłaszamy w definicji uchwytu, bo tam trzeba dopisać sprawdzenie. Domknięcie leży w add_action.
      let where: AnyNode = h.node;
      if (!body && h.methodRef) {
        const method = methodDefs.get(h.methodRef.cls)?.get(h.methodRef.method.toLowerCase());
        if (!method) continue; // klasa albo metoda spoza tego pliku
        body = method.body;
        cls = h.methodRef.cls;
        where = method;
      }
      if (!body && h.callbackName) {
        const fn = functionDefs.get(h.callbackName);
        if (!fn) continue; // uchwyt spoza tego pliku, nie oceniamy
        body = fn.body;
        where = fn;
      }
      if (!body) continue;

      const reach = reachOf(body, cls);
      if (reach.writes.length === 0 || reach.callsGuardHelper) continue;
      // Zamknięcie powiadomienia, banera albo wskazówki zapisuje stan interfejsu. To nie jest luka w dostępie.
      if (UI_HOOK.test(h.hook) && reach.writes.every(Boolean)) continue;

      if (!reach.hasNonce) {
        emit(
          where,
          ctx.t('auth.nonce.message', { hook: h.hook }),
          ['CWE-352'],
          ['4.2.2'],
          ctx.t('auth.nonce.fix'),
        );
      }
      // Uprawnień wymagamy tylko tam, gdzie działa zalogowany użytkownik.
      if (h.kind === 'priv' && !reach.hasCap && !(h.key && publicKeys.has(h.key))) {
        emit(
          where,
          ctx.t('auth.capability.message', { hook: h.hook }),
          ['CWE-862'],
          ['4.1.3'],
          ctx.t('auth.capability.fix'),
          // Sam nonce zawęża atak do zalogowanych użytkowników (na przykład subskrybentów).
          reach.hasNonce ? 'medium' : 'high',
        );
      }
    }

    return findings;
  },
};
