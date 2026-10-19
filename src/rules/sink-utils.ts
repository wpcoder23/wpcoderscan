// Wspólne narzędzia reguł opartych na ujściach: ścieżki plików, adresy HTTP, wysyłanie plików, role
// użytkowników i nazwy opcji. Ocena trafienia skażenia, zakres otaczającej funkcji oraz sprawdzenia,
// które autor wykonał w tej samej funkcji. Skaner nie ocenia, czy sprawdzenie jest poprawne.
// Uznaje samo jego wykonanie za dowód, że autor o tym pomyślał, bo wolimy przeoczyć niż zalać alarmami.
// Rozwijanie zmiennych do tekstu, z którego powstały, służy tylko do zdjęcia podejrzenia. Nigdy go nie stawia.
import { walk } from '../parser';
import type { Translate } from '../i18n';
import { arrayItems, asNode, calledName, callArgs, findEntry, offsetName, type AnyNode } from './ast-utils';
import { collectDefinitions, resolveCallbackNode } from './callbacks';
import { callerScopes } from './callers';
import { guardedAt } from './guards';
import { chainParts, literalString, originText, viaText, type TaintAnalyzer, type TaintHit } from './taint';
import type { Confidence, PhpNode, Severity } from './types';

const SCOPE_KINDS = new Set(['function', 'closure', 'method', 'arrowfunc']);
const SKIP_KEYS = new Set(['loc', 'leadingComments', 'trailingComments']);
const NO_HIT: TaintHit = { direct: false, viaVar: false };

// Najbliższa funkcja albo metoda otaczająca ujście. Poza funkcją zakresem jest cały program.
export function enclosingScope(stack: readonly PhpNode[], program: PhpNode): AnyNode {
  for (let i = stack.length - 1; i >= 0; i--) {
    if (SCOPE_KINDS.has(stack[i].kind)) return stack[i] as AnyNode;
  }
  return program as AnyNode;
}

export interface Grade {
  severity: Severity;
  confidence: Confidence;
  from: string; // skąd pochodzą dane, do komunikatu
}

const LOWER: Record<Severity, Severity> = { critical: 'high', high: 'medium', medium: 'low', low: 'low', info: 'info' };

// Superglobal wprost to wykrycie pewne. Zmienna zasilona danymi użytkownika to heurystyka. Dane, które do
// parametru przekazało wywołanie z tego samego pliku, to najsłabszy dowód, więc taki wynik jest o stopień niższy.
export function gradeHit(hit: TaintHit, firm: Severity, heuristic: Severity, t: Translate): Grade | null {
  if (hit.direct) return { severity: firm, confidence: 'firm', from: t('from.direct') };
  if (hit.viaVar) {
    return {
      severity: hit.source === 'caller' ? LOWER[heuristic] : heuristic,
      confidence: 'heuristic',
      from: t('from.viaVar', { var: viaText(hit), origin: originText(hit, t) }),
    };
  }
  return null;
}

// Ujście za bramką administratora nie jest otwarte dla zwykłego użytkownika. Zgłaszamy je jako słabą wskazówkę.
export function downgradeGated(grade: Grade): Grade {
  return { ...grade, severity: 'low', confidence: 'heuristic' };
}

// Wynik o stopień niższy, gdy skutek jest ograniczony (na przykład atakujący wybiera nazwę opcji, ale nie jej wartość).
export function lowerGrade(grade: Grade): Grade {
  return { ...grade, severity: LOWER[grade.severity] };
}

// Nazwy funkcji wołanych w zakresie, małymi literami.
const callCache = new WeakMap<AnyNode, Set<string>>();
export function callsIn(scope: AnyNode): Set<string> {
  let names = callCache.get(scope);
  if (!names) {
    const found = new Set<string>();
    walk(scope, (n) => {
      if (n.kind !== 'call') return;
      const name = calledName(n as AnyNode);
      if (name) found.add(name);
    });
    names = found;
    callCache.set(scope, names);
  }
  return names;
}

export function callsAny(scope: AnyNode, fns: ReadonlySet<string>): boolean {
  for (const name of callsIn(scope)) if (fns.has(name)) return true;
  return false;
}

// Nazwa wołanej funkcji albo metody ($obiekt->nazwa(), Klasa::nazwa()). Nazwy metod zapisane camelCase
// zamieniamy na snake_case małymi literami: isValidCode to is_valid_code.
export function calleeName(call: AnyNode): string | undefined {
  const fn = calledName(call);
  if (fn) return fn;
  const what = asNode(call.what);
  if (what && (what.kind === 'propertylookup' || what.kind === 'staticlookup')) {
    const method = offsetName(what.offset);
    if (method) return method.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
  }
  return undefined;
}

// Nazwy wołanych funkcji i metod w zakresie.
const calleeCache = new WeakMap<AnyNode, string[]>();
export function calleeNames(scope: AnyNode): string[] {
  let names = calleeCache.get(scope);
  if (!names) {
    const found = new Set<string>();
    walk(scope, (n) => {
      if (n.kind !== 'call') return;
      const name = calleeName(n as AnyNode);
      if (name) found.add(name);
    });
    names = [...found];
    calleeCache.set(scope, names);
  }
  return names;
}

// Czy zakres woła funkcję albo metodę o nazwie pasującej do wzorca. Nonce i referer nie liczą się jako
// sprawdzenie, bo nonce ma każdy odwiedzający.
export function callsMatching(scope: AnyNode, pattern: RegExp): boolean {
  return calleeNames(scope).some((name) => !/nonce|referer/.test(name) && pattern.test(name));
}

// Nazwy wszystkich zmiennych w poddrzewie.
function collectVars(node: unknown, out: Set<string>): void {
  if (Array.isArray(node)) {
    for (const e of node as unknown[]) collectVars(e, out);
    return;
  }
  const n = asNode(node);
  if (!n) return;
  if (n.kind === 'variable' && typeof n.name === 'string') {
    out.add(n.name);
    return;
  }
  for (const k of Object.keys(n)) {
    if (SKIP_KEYS.has(k)) continue;
    const v = n[k];
    if (v && typeof v === 'object') collectVars(v, out);
  }
}

// Zmienne podane, także w głębi wyrażenia, do jednej z wymienionych funkcji w tym zakresie.
export function varsPassedTo(scope: AnyNode, fns: ReadonlySet<string>): Set<string> {
  const out = new Set<string>();
  walk(scope, (n) => {
    if (n.kind !== 'call') return;
    const name = calledName(n as AnyNode);
    if (name && fns.has(name)) collectVars((n as AnyNode).arguments, out);
  });
  return out;
}

// Funkcje, które autor woła na ścieżce, żeby ją oczyścić albo sprawdzić.
const PATH_GUARD_FUNCS = new Set([
  'validate_file', 'realpath', 'basename', 'wp_basename', 'sanitize_file_name', 'wp_unique_filename',
]);
// Funkcje szukające ".." albo separatora w ścieżce i usuwające je.
const DOTDOT_FUNCS = new Set([
  'strpos', 'stripos', 'strstr', 'stristr', 'str_contains', 'substr_count', 'preg_match', 'preg_replace', 'str_replace', 'str_ireplace',
]);

// Teksty podane wprost w argumencie: literał albo literały tablicy zapisanej wprost.
function literalsOf(arg: AnyNode): string[] {
  const single = literalString(arg);
  if (single !== undefined) return [single];
  if (arg.kind !== 'array' || !Array.isArray(arg.items)) return [];
  const out: string[] = [];
  for (const it of arg.items as unknown[]) {
    const s = literalString(asNode(it)?.value);
    if (s !== undefined) out.push(s);
  }
  return out;
}

// Czy tekst szukany w ścieżce to "..", jej zapis w wyrażeniu regularnym albo, poza regexem, sam separator.
function searchesTraversal(fn: string, text: string): boolean {
  if (text.includes('..') || text.includes('\\.\\.')) return true;
  return !fn.startsWith('preg_') && (text === '/' || text === '\\');
}

// Zmienne, które autor sprawdza pod kątem "..": strpos( $p, '..' ), str_replace( '../', '', $p ), strstr( $p, '/' ),
// preg_match( '/\.\./', $p ). Zmienna, której przypisano wynik takiego wywołania, też się liczy.
function varsCheckedForTraversal(scope: AnyNode): Set<string> {
  const out = new Set<string>();
  walk(scope, (n, stack) => {
    if (n.kind !== 'call') return;
    const name = calledName(n as AnyNode);
    if (!name || !DOTDOT_FUNCS.has(name)) return;
    const args = callArgs(n as AnyNode);
    if (!args.some((a) => literalsOf(a).some((text) => searchesTraversal(name, text)))) return;
    collectVars(args, out);
    const parent = asNode(stack[stack.length - 1]);
    const target = parent && parent.kind === 'assign' && parent.right === n ? asNode(parent.left) : undefined;
    if (target && target.kind === 'variable' && typeof target.name === 'string') out.add(target.name);
  });
  return out;
}

const pathGuardCache = new WeakMap<AnyNode, Set<string>>();
// Zmienne ścieżkowe, o których autor pomyślał w tej funkcji (oczyszczone, sprawdzone pod kątem "..", przez realpath).
export function pathGuardedVars(scope: AnyNode): Set<string> {
  let out = pathGuardCache.get(scope);
  if (!out) {
    out = new Set([...varsPassedTo(scope, PATH_GUARD_FUNCS), ...varsCheckedForTraversal(scope)]);
    pathGuardCache.set(scope, out);
  }
  return out;
}

// Uprawnienia, które ma tylko administrator. Funkcja za taką bramką nie jest otwarta dla zwykłego użytkownika.
const ADMIN_CAPS = new Set([
  'administrator', 'manage_options', 'manage_network', 'manage_network_options', 'manage_network_users',
  'manage_network_plugins', 'manage_network_themes', 'manage_sites', 'activate_plugins', 'install_plugins',
  'edit_plugins', 'delete_plugins', 'update_plugins', 'edit_themes', 'install_themes', 'switch_themes',
  'update_core', 'update_themes', 'delete_themes', 'promote_users', 'promote_user', 'create_users', 'edit_users',
  'edit_user', 'delete_users', 'delete_user', 'add_users', 'remove_users', 'list_users', 'import', 'export',
  'unfiltered_html', 'unfiltered_upload',
]);

function isAdminCap(cap: string | undefined): boolean {
  return cap !== undefined && (ADMIN_CAPS.has(cap) || cap.startsWith('manage_'));
}

// Funkcje i metody, które po nazwie sprawdzają uprawnienia administratora: $this->user_is_admin(),
// jkit_permission_check_admin(). Samo is_admin() to pytanie o ekran panelu, a nie o uprawnienia, więc nie pasuje.
// check_admin_referer() sprawdza nonce, który ma każdy zalogowany, więc nazwy z nonce i referer odpadają.
const ADMIN_METHOD =
  /^(?:\w+_)?(?:user_is_admin|current_user_is_admin|is_admin_user|is_user_admin|is_administrator|admin_only|only_admin|(?:check|require|ensure|verify)_admin(?:_(?:user|only|access|permissions?|caps?|capabilit(?:y|ies)|rights?|auth\w*))?|admin_(?:permissions?|access|check|caps?|capabilit(?:y|ies)|auth(?:oriz\w+)?)(?:_check|_callback)?|permissions?_(?:check_)?admin(?:_only)?|has_admin_(?:caps?|capabilit(?:y|ies)|access|rights?|permissions?|role)|(?:current_)?user_can_manage\w*|can_manage\w*|manage_options(?:_\w+)?)$/;

function isAdminMethod(name: string): boolean {
  return !/nonce|referer/.test(name) && ADMIN_METHOD.test(name);
}

// Funkcja opakowująca sprawdzenie uprawnienia, której przekazano stałe uprawnienie administratora:
// $this->check_permission( 'manage_options' ). Nazwa musi być czasownikiem sprawdzenia, bo add_cap( 'manage_options' )
// uprawnienie nadaje, a nie sprawdza.
const CAP_WRAPPER = /^(?:\w+_)?(?:check|verify|require|ensure|authori[sz]e|assert|enforce|guard)(?:_\w+)?$|(?:^|_)permissions?(?:_|$)|^(?:\w+_)?(?:user_)?can_\w+$/;

// Nazwa metody zapisana camelCase jako snake_case małymi literami: isValidCode to is_valid_code.
function snakeCase(name: string): string {
  return name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
}

// Wartość uprawnienia podana na stałe: literał albo apply_filters( 'nazwa', 'manage_options' ), gdzie drugi
// argument to wartość domyślna.
function capDefault(value: AnyNode | undefined): boolean {
  if (!value) return false;
  if (value.kind === 'call' && calledName(value) === 'apply_filters') return isAdminCap(literalString(callArgs(value)[1]));
  return isAdminCap(literalString(value));
}

// Czy wyrażenie uprawnienia oznacza uprawnienie administratora. Obok literału rozumiemy zmienną, której
// wszystkie przypisania w zakresie to takie uprawnienie: $cap = apply_filters( 'tag', 'manage_options' ).
function adminCapExpr(scope: AnyNode, expr: AnyNode | undefined): boolean {
  if (!expr) return false;
  if (expr.kind !== 'variable' || typeof expr.name !== 'string') return capDefault(expr);
  const values: Array<AnyNode | undefined> = [];
  walk(scope, (n) => {
    if (n.kind !== 'assign' || n.operator !== '=') return;
    const left = asNode((n as AnyNode).left);
    if (left && left.kind === 'variable' && left.name === expr.name) values.push(asNode((n as AnyNode).right));
  });
  return values.length > 0 && values.every(capDefault);
}

// Wywołanie funkcji z nazwą sprawdzenia, której podano uprawnienie administratora na stałe.
function wrapsAdminCap(scope: AnyNode, call: AnyNode, args: AnyNode[]): boolean {
  const label = calleeName(call);
  if (!label || /nonce|referer/.test(label) || !CAP_WRAPPER.test(label)) return false;
  return args.some((arg) => adminCapExpr(scope, arg));
}

// Czy wywołanie sprawdza uprawnienie administratora: current_user_can( 'manage_options' ), is_super_admin(),
// $user->has_cap( 'manage_options' ), sprawdzenie roli in_array( 'administrator', $user->roles ), funkcja o nazwie
// sprawdzenia administratora albo opakowanie, któremu podano stałe uprawnienie administratora.
function isAdminCheckCall(scope: AnyNode, call: AnyNode): boolean {
  const name = calledName(call);
  const args = callArgs(call);
  if (name === 'is_super_admin') return true;
  if (name === 'in_array') return literalString(args[0]) === 'administrator';
  if (name === 'current_user_can') return adminCapExpr(scope, args[0]);
  if (name === 'user_can' || name === 'current_user_can_for_blog') return adminCapExpr(scope, args[1]);
  if (!name && offsetName(asNode(call.what)?.offset) === 'has_cap') return adminCapExpr(scope, args[0]);
  const label = calleeName(call);
  return wrapsAdminCap(scope, call, args) || (label !== undefined && isAdminMethod(label));
}

const adminCache = new WeakMap<AnyNode, boolean>();
// Czy w zakresie jest bramka na uprawnienie administratora (patrz isAdminCheckCall).
export function requiresAdminCap(scope: AnyNode): boolean {
  const cached = adminCache.get(scope);
  if (cached !== undefined) return cached;
  let gated = false;
  walk(scope, (n) => {
    if (!gated && n.kind === 'call') gated = isAdminCheckCall(scope, n as AnyNode);
  });
  adminCache.set(scope, gated);
  return gated;
}

// Czy prawdziwy warunek znaczy, że użytkownik jest administratorem: samo sprawdzenie, koniunkcja z nim albo
// alternatywa, której obie strony je mają.
function holdsForAdmin(scope: AnyNode, test: AnyNode | undefined): boolean {
  if (!test) return false;
  if (test.kind === 'call') return isAdminCheckCall(scope, test);
  if (test.kind !== 'bin') return false;
  const left = asNode(test.left);
  const right = asNode(test.right);
  if (test.type === '&&' || test.type === 'and') return holdsForAdmin(scope, left) || holdsForAdmin(scope, right);
  if (test.type === '||' || test.type === 'or') return holdsForAdmin(scope, left) && holdsForAdmin(scope, right);
  return false;
}

// Czy prawdziwy warunek znaczy, że użytkownik nie jest administratorem: zaprzeczone sprawdzenie, alternatywa z takim
// składnikiem albo koniunkcja, której obie strony takie są. Po wyjściu z tym warunkiem dalszy kod widzi administratora.
function failsForAdmin(scope: AnyNode, test: AnyNode | undefined): boolean {
  if (!test) return false;
  if (test.kind === 'unary' && test.type === '!') return holdsForAdmin(scope, asNode(test.what));
  if (test.kind !== 'bin') return false;
  const left = asNode(test.left);
  const right = asNode(test.right);
  if (test.type === '||' || test.type === 'or') return failsForAdmin(scope, left) || failsForAdmin(scope, right);
  if (test.type === '&&' || test.type === 'and') return failsForAdmin(scope, left) && failsForAdmin(scope, right);
  return false;
}

// Rejestracja hooka, po której funkcja działa tylko dla administratora: add_action stoi w ciele if z jego sprawdzeniem
// albo po wczesnym wyjściu dla pozostałych. Samo is_admin() to pytanie o ekran panelu, a nie o uprawnienia.
function registrationGated(call: AnyNode, stack: readonly PhpNode[]): boolean {
  let from = 0;
  for (let i = stack.length - 1; i >= 0; i--) {
    if (SCOPE_KINDS.has(stack[i].kind)) {
      from = i;
      break;
    }
  }
  const scope = scopeOfStack(stack);
  return guardedAt(
    stack.slice(from) as AnyNode[],
    offsetOf(call, 'start'),
    (test) => holdsForAdmin(scope, test),
    (test) => failsForAdmin(scope, test),
  );
}

// Strony menu panelu: indeksy argumentów z uprawnieniem i z funkcją wyświetlającą stronę. WordPress nie wpuści
// na stronę bez tego uprawnienia, więc funkcja strony jest za bramką, choć sama nie woła current_user_can.
const MENU_PAGES: Record<string, { cap: number; callback: number }> = {
  add_menu_page: { cap: 2, callback: 4 },
  add_utility_page: { cap: 2, callback: 4 },
  add_submenu_page: { cap: 3, callback: 5 },
  add_options_page: { cap: 2, callback: 4 },
  add_management_page: { cap: 2, callback: 4 },
  add_theme_page: { cap: 2, callback: 4 },
  add_plugins_page: { cap: 2, callback: 4 },
  add_users_page: { cap: 2, callback: 4 },
  add_dashboard_page: { cap: 2, callback: 4 },
  add_posts_page: { cap: 2, callback: 4 },
  add_media_page: { cap: 2, callback: 4 },
  add_pages_page: { cap: 2, callback: 4 },
  add_comments_page: { cap: 2, callback: 4 },
};

// Definicje tras w drugim argumencie register_rest_route: jedna tablica z 'callback' albo lista takich tablic.
function routeDefinitions(arg: AnyNode): AnyNode[] {
  if (arg.kind !== 'array') return [];
  if (findEntry(arg, 'callback')) return [arg];
  return arrayItems(arg)
    .map((item) => asNode(item.value))
    .filter((route): route is AnyNode => !!route && route.kind === 'array' && !!findEntry(route, 'callback'));
}

// Funkcja uprawnień zdefiniowana poza tym plikiem: widzimy tylko jej nazwę, 'jkit_permission_check_admin' albo
// array( $this, 'checkAdmin' ). Nazwa, która mówi o administratorze, wystarcza do uznania trasy za zamkniętą.
function namedAdminPermission(callback: AnyNode): boolean {
  let name: string | undefined;
  if (callback.kind === 'string' && typeof callback.value === 'string') {
    name = callback.value.slice(Math.max(callback.value.lastIndexOf(':'), callback.value.lastIndexOf('\\')) + 1);
  } else if (callback.kind === 'array') {
    const items = arrayItems(callback);
    const method = items.length === 2 ? asNode(items[1].value) : undefined;
    if (method && method.kind === 'string' && typeof method.value === 'string') name = method.value;
  }
  return name !== undefined && isAdminMethod(snakeCase(name));
}

const HOOK_REGISTRARS = new Set(['add_action', 'add_filter']);

const registeredCache = new WeakMap<AnyNode, Set<AnyNode>>();
// Funkcje i metody z pliku, które WordPress woła dopiero po sprawdzeniu uprawnienia administratora przy rejestracji:
// strona menu z uprawnieniem 'manage_options', trasa REST, której permission_callback wymaga takiego uprawnienia,
// albo hook zarejestrowany w if ze sprawdzeniem administratora. Funkcja zarejestrowana także poza bramką jest
// otwarta, więc odpada. Callback zdefiniowany w innym pliku zostaje poza zasięgiem.
export function adminCallbacks(program: AnyNode): Set<AnyNode> {
  const cached = registeredCache.get(program);
  if (cached) return cached;
  const found = new Set<AnyNode>();
  registeredCache.set(program, found);
  const open = new Set<AnyNode>();
  const defs = collectDefinitions(program as PhpNode);
  walk(program, (node, stack: PhpNode[]) => {
    const n = node as AnyNode;
    if (n.kind !== 'call') return;
    const name = calledName(n);
    if (!name) return;
    const args = callArgs(n);
    if (HOOK_REGISTRARS.has(name)) {
      const fn = args[1] ? resolveCallbackNode(args[1], stack, defs) : undefined;
      if (fn) (registrationGated(n, stack) ? found : open).add(fn);
      return;
    }
    const page = MENU_PAGES[name];
    if (page) {
      const callback = args[page.callback];
      if (callback && adminCapExpr(scopeOfStack(stack), args[page.cap])) {
        const fn = resolveCallbackNode(callback, stack, defs);
        if (fn) found.add(fn);
      }
      return;
    }
    if (name !== 'register_rest_route' || !args[2]) return;
    for (const route of routeDefinitions(args[2])) {
      const permission = asNode(findEntry(route, 'permission_callback')?.value);
      const callback = asNode(findEntry(route, 'callback')?.value);
      if (!permission || !callback) continue;
      const gate = resolveCallbackNode(permission, stack, defs);
      if (gate ? !requiresAdminCap(gate) : !namedAdminPermission(permission)) continue;
      const fn = resolveCallbackNode(callback, stack, defs);
      if (fn) found.add(fn);
    }
  });
  for (const fn of open) found.delete(fn);
  return found;
}

// Czy zakres stoi za bramką administratora: sprawdza uprawnienie sam albo jest funkcją strony czy trasy REST,
// do której WordPress wpuszcza tylko administratora.
export function scopeGated(scope: AnyNode, program: AnyNode): boolean {
  return requiresAdminCap(scope) || adminCallbacks(program).has(scope);
}

const MAX_CHAIN = 24;

// Czy zakres stoi za bramką administratora sam albo przez wywołujących: pomocnik, który ten plik woła wyłącznie
// z zakresów za bramką (handler strony albo trasy woła pomocnika, ten woła kolejnego). Funkcja z wejściem, którego
// nie widzimy (callback hooka, wywołanie na obcym obiekcie, wywołanie spoza funkcji), nie przechodzi.
// Wywołania z innych plików są poza zasięgiem, więc publiczna metoda wołana z drugiego pliku bez bramki zostaje
// ukryta. Dlatego takie ujścia obniżamy, a nie usuwamy, tam gdzie reguła tak robi.
export function scopeGatedByCallers(scope: AnyNode, program: AnyNode, seen = new Set<AnyNode>()): boolean {
  if (scopeGated(scope, program)) return true;
  if (scope.kind !== 'function' && scope.kind !== 'method') return false;
  if (seen.has(scope)) return true;
  if (seen.size >= MAX_CHAIN) return false;
  seen.add(scope);
  const callers = callerScopes(program as PhpNode, scope);
  return !!callers && callers.every((caller) => caller !== program && scopeGatedByCallers(caller, program, seen));
}

// Czy ujście stoi za bramką administratora: we własnej funkcji, w funkcji, która przekazała mu dane, albo w pomocniku
// wołanym wyłącznie zza takiej bramki. Wywołanie z kodu poza funkcjami niczego nie potwierdza.
export function adminGated(scope: AnyNode, hit: TaintHit, analyzer: TaintAnalyzer): boolean {
  const program = analyzer.root;
  if (scopeGatedByCallers(scope, program)) return true;
  if (hit.source !== 'caller' || !hit.via) return false;
  const sites = analyzer.seedSites(scope, hit.via).filter((site) => site.kind !== 'program');
  return sites.length > 0 && sites.every((site) => scopeGatedByCallers(site, program));
}

// Funkcje i stałe, po których kod rozpoznaje środowisko deweloperskie.
const DEV_FUNCS = new Set(['wp_get_environment_type', 'wp_is_development_mode']);
const DEV_CONSTANTS = new Set(['WP_LOCAL_DEV', 'WP_ENVIRONMENT_TYPE', 'WP_DEBUG']);
const DEV_METHOD = /(?:^|_)(?:is_(?:local|dev|development|staging)(?:_\w+)?|dev_mode|local_env\w*)$/;

// Czy zakres sprawdza, że działa na środowisku deweloperskim. Pasek logowania "wejdź jako" dla developera
// kończy działanie na produkcji, więc nie jest drzwiami dla odwiedzającego.
export function devGated(scope: AnyNode): boolean {
  let found = false;
  walk(scope, (n) => {
    if (found) return;
    if (n.kind === 'call') {
      const name = calledName(n as AnyNode);
      if (name && DEV_FUNCS.has(name)) found = true;
    } else if (n.kind === 'name' && typeof n.name === 'string' && DEV_CONSTANTS.has(n.name.replace(/^\\/, ''))) {
      found = true;
    }
  });
  return found || calleeNames(scope).some((method) => DEV_METHOD.test(method));
}

// Adres z ustalonym hostem: po schemacie i hoście stoi ukośnik, pytajnik albo hash. Adres względny (od ukośnika) hosta nie ma.
export function hostIsFixed(text: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\/[^/?#]+[/?#]/i.test(text) || (text.startsWith('/') && !text.startsWith('//'));
}

// Składnik sklejanego tekstu po rozwinięciu zmiennych: literał (lit) albo wyrażenie do oceny (node). at to
// węzeł, wg którego liczymy pozycję przy ocenie skażenia.
export interface FlatPart {
  lit?: string;
  node?: AnyNode;
  at: unknown;
}

function offsetOf(node: unknown, edge: 'start' | 'end'): number {
  const loc = asNode(node)?.loc as { start?: { offset?: number }; end?: { offset?: number } } | undefined;
  return loc?.[edge]?.offset ?? (edge === 'start' ? Number.MAX_SAFE_INTEGER : 0);
}

// Zapis do zmiennej w zakresie: przypisanie ('=' albo '.=') z prawą stroną albo zapis, którego wartości nie znamy.
interface Write {
  end: number;
  op: '=' | '.=' | 'opaque';
  right?: AnyNode;
}

// Funkcje zapisujące wynik do argumentu przekazanego przez referencję.
const BY_REF_WRITERS = new Set(['preg_match', 'preg_match_all', 'parse_str', 'sscanf', 'settype']);

interface ScopeWrites {
  byName: Map<string, Write[]>;
  extracts: number[]; // pozycje extract(), po których dowolna zmienna mogła dostać nową wartość
}

const writesCache = new WeakMap<AnyNode, ScopeWrites>();
// Zapisy do zwykłych zmiennych w zakresie, bez zagnieżdżonych funkcji, po kolei wg pozycji w kodzie.
function writesOf(scope: AnyNode): ScopeWrites {
  const cached = writesCache.get(scope);
  if (cached) return cached;
  const byName = new Map<string, Write[]>();
  const extracts: number[] = [];
  const add = (name: string, write: Write): void => {
    const list = byName.get(name) ?? [];
    list.push(write);
    byName.set(name, list);
  };
  const opaque = (target: unknown, end: number): void => {
    const names = new Set<string>();
    collectVars(target, names);
    for (const name of names) add(name, { end, op: 'opaque' });
  };
  const visit = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const e of node as unknown[]) visit(e);
      return;
    }
    const n = asNode(node);
    if (!n || typeof n.kind !== 'string') return;
    if (n !== scope && SCOPE_KINDS.has(n.kind)) return;
    if (n.kind === 'assign') {
      const left = asNode(n.left);
      const right = asNode(n.right);
      if (left && left.kind === 'variable' && typeof left.name === 'string' && right) {
        const plain = n.operator === '=' || typeof n.operator !== 'string';
        const op = plain ? '=' : n.operator === '.=' ? '.=' : 'opaque';
        add(left.name, { end: offsetOf(n, 'end'), op, right });
      } else if (left && left.kind !== 'offsetlookup') {
        opaque(left, offsetOf(n, 'end')); // list( $a, $b ) = .. i [ $a, $b ] = ..
      }
    } else if (n.kind === 'assignref') {
      opaque(n.left, offsetOf(n, 'end'));
    } else if (n.kind === 'foreach') {
      opaque([n.key, n.value], offsetOf(asNode(n.source), 'end'));
    } else if (n.kind === 'global' || n.kind === 'static') {
      opaque(n.items ?? n.variables, offsetOf(n, 'end'));
    } else if (n.kind === 'call') {
      const name = calledName(n);
      if (name === 'extract') extracts.push(offsetOf(n, 'end'));
      else if (name && BY_REF_WRITERS.has(name)) opaque(n.arguments, offsetOf(n, 'end'));
    }
    for (const k of Object.keys(n)) {
      if (SKIP_KEYS.has(k)) continue;
      const v = n[k];
      if (v && typeof v === 'object') visit(v);
    }
  };
  visit(scope);
  for (const list of byName.values()) list.sort((a, b) => a.end - b.end);
  const writes = { byName, extracts };
  writesCache.set(scope, writes);
  return writes;
}

// Ostatnie przypisanie zmiennej przed pozycją i doklejenia (.=) po nim. Nie znamy wartości, gdy po drodze
// zmienna dostała inny zapis albo extract().
function reachingDefinition(scope: AnyNode, name: string, before: number): { right: AnyNode; appended: AnyNode[] } | undefined {
  const { byName, extracts } = writesOf(scope);
  const writes = (byName.get(name) ?? []).filter((w) => w.end <= before);
  const appended: AnyNode[] = [];
  for (let i = writes.length - 1; i >= 0; i--) {
    const w = writes[i];
    if (w.op === '.=' && w.right) {
      appended.unshift(w.right);
    } else if (w.op === '=' && w.right) {
      return extracts.some((off) => off > w.end && off <= before) ? undefined : { right: w.right, appended };
    } else {
      return undefined;
    }
  }
  return undefined;
}

// Opakowania, które nie zmieniają hosta ani końcówki adresu, więc oceniamy to, co jest w środku.
const VALUE_WRAPPERS = new Set([
  'esc_url_raw', 'esc_url', 'sanitize_url', 'trim', 'rtrim', 'ltrim', 'untrailingslashit', 'trailingslashit',
  'wp_unslash', 'strtolower', 'html_entity_decode', 'htmlspecialchars_decode', 'urldecode', 'rawurldecode',
]);
const MAX_DEPTH = 4;

// Prawa strona przypisania, którą warto rozwinąć: sklejanie, napis, alias zmiennej i opakowania wartości.
function expandable(node: AnyNode): boolean {
  if (node.kind === 'string' || node.kind === 'encapsed' || node.kind === 'variable') return true;
  if (node.kind === 'bin') return node.type === '.';
  if (node.kind !== 'call') return false;
  const name = calledName(node);
  return !!name && (VALUE_WRAPPERS.has(name) || name === 'add_query_arg' || name === 'sprintf');
}

// Specyfikacja formatu sprintf: %s, %1$s, %05.2f, %%.
const FORMAT_SPEC = /%(?:(\d+)\$)?[-+ 0]*(?:'.)?\d*(?:\.\d+)?([a-zA-Z%])/g;
const NUMERIC_CONVERSIONS = 'dueEfFgGboxXc';

function flattenInto(scope: AnyNode, expr: unknown, depth: number, out: FlatPart[]): void {
  const leaves: AnyNode[] = [];
  chainParts(expr, leaves);
  for (const leaf of leaves) {
    const lit = literalString(leaf);
    if (lit !== undefined) out.push({ lit, at: leaf });
    else if (depth <= 0 || !expandLeaf(scope, leaf, depth, out)) out.push({ node: leaf, at: leaf });
  }
}

function expandLeaf(scope: AnyNode, leaf: AnyNode, depth: number, out: FlatPart[]): boolean {
  if (leaf.kind === 'variable' && typeof leaf.name === 'string') {
    const def = reachingDefinition(scope, leaf.name, offsetOf(leaf, 'start'));
    if (!def || !expandable(def.right)) return false;
    flattenInto(scope, def.right, depth - 1, out);
    for (const extra of def.appended) flattenInto(scope, extra, depth - 1, out);
    return true;
  }
  if (leaf.kind !== 'call') return false;
  const name = calledName(leaf);
  if (!name) return false;
  const args = callArgs(leaf);
  if (VALUE_WRAPPERS.has(name) && args[0]) {
    flattenInto(scope, args[0], depth - 1, out);
    return true;
  }
  if (name === 'add_query_arg') {
    // Adres jest ostatnim argumentem. Bez niego dopisujemy do adresu bieżącej strony, czyli własnego hosta.
    const url = args.length >= 3 ? args[2] : args.length === 2 && args[0].kind === 'array' ? args[1] : undefined;
    if (url) flattenInto(scope, url, depth - 1, out);
    return true;
  }
  if (name === 'sprintf' && args[0]) {
    const fmt = literalString(args[0]);
    if (fmt === undefined) return false;
    let last = 0;
    let sequence = 0;
    for (const m of fmt.matchAll(FORMAT_SPEC)) {
      const text = fmt.slice(last, m.index);
      if (text) out.push({ lit: text, at: leaf });
      last = (m.index ?? 0) + m[0].length;
      if (m[2] === '%') {
        out.push({ lit: '%', at: leaf });
        continue;
      }
      const arg = args[m[1] ? Number(m[1]) : ++sequence];
      if (!arg) continue;
      if (NUMERIC_CONVERSIONS.includes(m[2])) out.push({ lit: '0', at: leaf });
      else flattenInto(scope, arg, depth - 1, out);
    }
    const rest = fmt.slice(last);
    if (rest) out.push({ lit: rest, at: leaf });
    return true;
  }
  return false;
}

// Sąsiednie literały łączymy w jeden, bo o hoście albo rozszerzeniu decyduje cały ciąg tekstu.
function mergeLiterals(parts: FlatPart[]): FlatPart[] {
  const out: FlatPart[] = [];
  for (const part of parts) {
    const prev = out[out.length - 1];
    if (part.lit !== undefined && prev && prev.lit !== undefined) prev.lit += part.lit;
    else out.push({ ...part });
  }
  return out;
}

function scopeOfStack(stack: readonly PhpNode[]): AnyNode {
  for (let i = stack.length - 1; i >= 0; i--) {
    if (SCOPE_KINDS.has(stack[i].kind)) return stack[i] as AnyNode;
  }
  return (stack[0] ?? {}) as AnyNode;
}

// Wartość wyrażenia jako lista składników: zmienne ze zwykłymi przypisaniami, sklejanie, sprintf i opakowania
// są rozwinięte do tego, z czego powstał tekst. Służy tylko do zdjęcia podejrzenia, nigdy do jego postawienia,
// bo sprawdzenia autora (in_array, walidator) widzi ocena wyrażenia w postaci, w jakiej je zapisano.
export function flattenValue(stack: readonly PhpNode[], expr: unknown): FlatPart[] {
  const out: FlatPart[] = [];
  flattenInto(scopeOfStack(stack), expr, MAX_DEPTH, out);
  return mergeLiterals(out);
}

function tainted(hit: TaintHit): boolean {
  return hit.direct || hit.viaVar;
}

// Rozszerzenie dopisane na stałe na końcu wartości (".jpg", ".pdf"), małymi literami, bez kropki.
export function fixedExtension(stack: readonly PhpNode[], expr: unknown): string | undefined {
  const parts = flattenValue(stack, expr);
  const last = parts[parts.length - 1];
  const m = last && last.lit !== undefined ? /\.([a-z0-9]{1,6})$/i.exec(last.lit) : null;
  return m ? m[1].toLowerCase() : undefined;
}

// Czy każdy skażony składnik ścieżki stoi tuż za fragmentem nazwy pliku ('/obraz-' . $id), a nie za katalogiem.
// Katalog o nazwie złożonej z fragmentu i ".." nie istnieje, więc taki składnik nie wyprowadzi poza katalog.
export function taintOnlyInNameFragments(analyzer: TaintAnalyzer, stack: PhpNode[], expr: unknown): boolean {
  const parts = flattenValue(stack, expr);
  let saw = false;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (part.node === undefined || !tainted(analyzer.analyze(part.node, stack, part.at))) continue;
    saw = true;
    const prev = parts[i - 1];
    if (!prev || prev.lit === undefined) return false;
    if (!/[^/\\]$/.test(prev.lit) || /(?:^|[/\\])\.{1,2}$/.test(prev.lit)) return false;
  }
  return saw;
}

// Ocena wartości, której początek rozstrzyga o skutku: host adresu albo przedrostek nazwy opcji. Literał,
// po którym wartość jest już ustalona, zamyka sprawę, więc dalsze składniki jej nie zmieniają. Pierwszy
// składnik, który nie jest literałem, decyduje: skażony to trafienie, nieskażony to wartość, której nie znamy.
// Najpierw oceniamy wyrażenie tak, jak je napisano (widać wtedy sprawdzenia autora), a potem, gdy jest
// podejrzane, początek wartości po rozwinięciu zmiennych. Jeśli on jest czysty, trafienie znika. Jeśli nie,
// zostaje pierwsza ocena, bo to ona niesie nazwę zmiennej do komunikatu.
export function leadingTaint(
  analyzer: TaintAnalyzer,
  expr: unknown,
  stack: PhpNode[],
  at: unknown,
  fixedAfter: (literalSoFar: string) => boolean,
): TaintHit {
  const plain: AnyNode[] = [];
  chainParts(expr, plain);
  const first = leadingOf(
    analyzer,
    plain.map((node) => {
      const lit = literalString(node);
      return lit !== undefined ? { lit, at } : { node, at };
    }),
    stack,
    fixedAfter,
  );
  if (!tainted(first)) return first;
  const refined = leadingOf(analyzer, flattenValue(stack, expr), stack, fixedAfter);
  return tainted(refined) ? first : NO_HIT;
}

function leadingOf(analyzer: TaintAnalyzer, parts: FlatPart[], stack: PhpNode[], fixedAfter: (text: string) => boolean): TaintHit {
  let text = '';
  for (const part of parts) {
    if (part.lit !== undefined) {
      text += part.lit;
      if (fixedAfter(text)) return NO_HIT;
      continue;
    }
    if (part.node) return analyzer.analyze(part.node, stack, part.at);
  }
  return NO_HIT;
}
