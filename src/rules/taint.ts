// Lekka analiza skażenia danych w obrębie jednej funkcji (albo pliku).
// Nie jest to pełna analiza przepływu. Śledzimy tylko to, co widać w jednym
// zakresie: dane wprost z superglobala oraz zmienne, do których ostatnio
// przypisano takie dane. Kolejność przypisań liczy się wg pozycji w kodzie,
// więc `$id = absint( $id )` zdejmuje skażenie. Funkcje nieznane nie przenoszą
// skażenia. To celowo ostrożne podejście: wolimy przeoczyć niż zalać
// użytkownika fałszywymi alarmami. Analizę między funkcjami zostawiamy na Pro.
import { asNode, baseVariable, calledName, offsetName, SUPERGLOBALS, type AnyNode } from './ast-utils';
import type { PhpNode } from './types';

export interface TaintHit {
  direct: boolean; // superglobal (albo filter_input, php://input) bezpośrednio w wyrażeniu
  viaVar: boolean; // zmienna skażona wcześniejszym przypisaniem albo parametr żądania REST
  via?: string; // nazwa pierwszej skażonej zmiennej
  source?: TaintSource; // pochodzenie, gdy nie jest to zwykły superglobal
}

// request: obiekt żądania REST. url: add_query_arg bez adresu, czyli bieżący adres strony.
// param: parametr funkcji (tylko w trybie rozszerzonym).
// shortcode: atrybuty shortcode, które autor wpisu (Contributor) wpisuje bez filtrowania.
export type TaintSource = 'request' | 'url' | 'param' | 'shortcode';

// Czy zmienna jest skażona i skąd. Żądanie REST daje tylko heurystykę, bo trasa
// może walidować argumenty przez args (type, sanitize_callback), czego nie widzimy.
type Origin = 'none' | 'superglobal' | TaintSource;

interface Env {
  origin(name: string): Origin;
  // Skażenie elementu tablicy pod literalnym kluczem. undefined, gdy nie znamy tego klucza.
  originKey(name: string, key: string): Origin | undefined;
  isRequestVar(name: string): boolean;
}

export interface TaintSpec {
  // Funkcje, po których wartość jest bezpieczna dla danej klasy ujścia.
  clean: ReadonlySet<string>;
  // Metody obiektu $wpdb zwracające bezpieczną wartość (prepare).
  methodClean?: ReadonlySet<string>;
  // add_query_arg i remove_query_arg bez adresu zwracają bieżący adres strony,
  // który kontroluje atakujący. Dla XSS to źródło danych.
  queryArgSource?: boolean;
  // Parametry funkcji liczymy jako dane o nieznanym pochodzeniu (tryb rozszerzony).
  paramSource?: boolean;
}

const NONE: TaintHit = { direct: false, viaVar: false };

// Metody WP_REST_Request zwracające dane od klienta.
const REST_GETTERS = new Set([
  'get_param', 'get_params', 'get_json_params', 'get_body_params', 'get_query_params',
  'get_url_params', 'get_default_params', 'get_body', 'get_file_params',
]);

// Wartości trzeciego argumentu filter_input, które nie czyszczą danych.
const FILTER_UNSAFE = new Set([
  'FILTER_DEFAULT', 'FILTER_UNSAFE_RAW', 'FILTER_SANITIZE_STRING', 'FILTER_SANITIZE_STRIPPED',
]);

const SCOPE_KINDS = new Set(['function', 'closure', 'method', 'arrowfunc']);
const SKIP_KEYS = new Set(['loc', 'leadingComments', 'trailingComments']);
const NEUTRAL_CASTS = new Set(['int', 'integer', 'float', 'double', 'real', 'bool', 'boolean']);

// Rodzaje węzłów, które nie niosą skażenia do wyniku wyrażenia.
const NO_TAINT_KINDS = new Set([
  'string',
  'number',
  'boolean',
  'nowdoc',
  'name',
  'identifier',
  'isset',
  'empty',
  'unary',
  'closure',
  'arrowfunc',
  'new',
  'instanceof',
]);

// Klucze $_SERVER ustawiane przez serwer, nie przez atakującego.
const SERVER_SAFE_KEYS = new Set([
  'DOCUMENT_ROOT',
  'SCRIPT_FILENAME',
  'SCRIPT_NAME',
  'SERVER_ADDR',
  'SERVER_PORT',
  'SERVER_SOFTWARE',
  'GATEWAY_INTERFACE',
  'REMOTE_ADDR',
  'REMOTE_PORT',
  'REQUEST_TIME',
  'REQUEST_TIME_FLOAT',
  'HTTPS',
  'argv',
  'argc',
]);

// Funkcje, które przenoszą skażenie z argumentów na wynik.
const PASSTHROUGH = new Set([
  'trim', 'ltrim', 'rtrim', 'chop',
  'stripslashes', 'stripcslashes', 'wp_unslash', 'stripslashes_deep',
  'strtolower', 'strtoupper', 'mb_strtolower', 'mb_strtoupper',
  'ucfirst', 'ucwords', 'lcfirst',
  'urldecode', 'rawurldecode', 'base64_decode',
  'html_entity_decode', 'htmlspecialchars_decode', 'wp_specialchars_decode',
  'nl2br', 'substr', 'mb_substr', 'str_replace', 'str_ireplace', 'substr_replace',
  'preg_replace', 'sprintf', 'vsprintf', 'implode', 'join', 'explode',
  'strip_tags', 'wp_strip_all_tags', 'add_query_arg', 'remove_query_arg',
  'json_encode', 'json_decode', 'serialize', 'maybe_serialize',
  'array_map', 'array_filter', 'array_values', 'array_merge', 'array_slice',
  'array_unique', 'array_reverse', 'array_keys', 'array_combine', 'shortcode_atts',
  // Czyszczenie pod XSS nie chroni przed SQL, ścieżką ani poleceniem. Dla
  // tamtych ujść te funkcje przenoszą skażenie. Dla XSS są w zbiorze clean,
  // który sprawdzamy wcześniej.
  'sanitize_text_field', 'sanitize_textarea_field', 'sanitize_email', 'sanitize_user',
  'esc_html', 'esc_attr', 'esc_url', 'esc_url_raw', 'esc_js', 'esc_textarea',
  'wp_kses', 'wp_kses_post', 'wp_kses_data', 'htmlspecialchars', 'htmlentities',
  'wp_json_encode', 'addslashes',
]);

// Czyszczenie wspólne dla wszystkich klas ujść: wynik jest liczbą, skrótem,
// długością albo kodowaniem URL, więc nie niesie niebezpiecznych znaków.
const COMMON_CLEAN = [
  'intval', 'absint', 'floatval', 'doubleval', 'boolval', 'abs', 'round', 'floor', 'ceil',
  'count', 'sizeof', 'strlen', 'mb_strlen', 'md5', 'sha1', 'crc32', 'hash', 'wp_hash',
  'urlencode', 'rawurlencode', 'is_numeric', 'is_array', 'is_string', 'in_array',
  'number_format', 'time', 'date', 'gmdate', 'strtotime', 'mktime', 'uniqid',
  'wp_generate_uuid4', 'bin2hex', 'dechex', 'hexdec', 'ctype_digit', 'ctype_alnum',
];

const SQL_CLEAN = [
  ...COMMON_CLEAN,
  'esc_sql', 'mysqli_real_escape_string', 'addslashes', 'sanitize_key', 'sanitize_title',
  'sanitize_title_with_dashes', 'wp_parse_id_list', 'sanitize_sql_orderby',
];

const INCLUDE_CLEAN = [
  ...COMMON_CLEAN,
  'basename', 'sanitize_file_name', 'sanitize_key', 'sanitize_title', 'sanitize_html_class',
];

const EXEC_CLEAN = [...COMMON_CLEAN, 'escapeshellarg', 'escapeshellcmd', 'sanitize_key'];

const XSS_CLEAN = [
  ...COMMON_CLEAN,
  'esc_html', 'esc_attr', 'esc_url', 'esc_url_raw', 'esc_js', 'esc_textarea',
  'esc_html__', 'esc_html_e', 'esc_html_x', 'esc_attr__', 'esc_attr_e', 'esc_attr_x',
  'wp_kses', 'wp_kses_post', 'wp_kses_data',
  'sanitize_text_field', 'sanitize_textarea_field', 'sanitize_email', 'sanitize_key',
  'sanitize_title', 'sanitize_user', 'sanitize_file_name', 'sanitize_html_class',
  'wp_json_encode', 'htmlspecialchars', 'htmlentities',
];

// Kod wykonywany przez eval: czyści tylko to, co daje liczbę albo skrót.
export const CODE_SPEC: TaintSpec = { clean: new Set(COMMON_CLEAN) };

export const SQL_SPEC: TaintSpec = {
  clean: new Set(SQL_CLEAN),
  methodClean: new Set(['prepare', '_escape', '_real_escape', 'escape']),
};
// Tryb rozszerzony: jak SQL_SPEC, ale parametry funkcji też są źródłem.
export const SQL_PARAM_SPEC: TaintSpec = { ...SQL_SPEC, paramSource: true };
export const INCLUDE_SPEC: TaintSpec = { clean: new Set(INCLUDE_CLEAN) };
export const EXEC_SPEC: TaintSpec = { clean: new Set(EXEC_CLEAN) };
export const XSS_SPEC: TaintSpec = { clean: new Set(XSS_CLEAN), queryArgSource: true };

function merge(a: TaintHit, b: TaintHit): TaintHit {
  if (!a.direct && !a.viaVar) return b;
  if (!b.direct && !b.viaVar) return a;
  const first = a.direct ? a : b.direct ? b : a;
  return {
    direct: a.direct || b.direct,
    viaVar: a.viaVar || b.viaVar,
    via: a.via ?? b.via,
    source: first.source,
  };
}

function literalString(v: unknown): string | undefined {
  const n = asNode(v);
  return n && n.kind === 'string' && typeof n.value === 'string' ? n.value : undefined;
}

// filter_input bez filtra czyszczącego oraz php://input to dane od klienta wprost.
function isRawInputCall(name: string, args: unknown[]): boolean {
  if (name === 'filter_input' || name === 'filter_input_array') {
    const filter = asNode(args[2]);
    if (!filter) return true;
    return filter.kind === 'name' && typeof filter.name === 'string' && FILTER_UNSAFE.has(filter.name.replace(/^\\/, ''));
  }
  if (name === 'file_get_contents') {
    const src = literalString(args[0]);
    return src !== undefined && src.toLowerCase() === 'php://input';
  }
  return false;
}

// add_query_arg( klucz, wartość ) i add_query_arg( tablica ) bez adresu, remove_query_arg( klucze ) bez adresu.
function queryArgWithoutUrl(name: string, args: unknown[]): boolean {
  if (name === 'remove_query_arg') return args.length === 1;
  if (name !== 'add_query_arg') return false;
  const first = asNode(args[0]);
  if (!first) return false;
  if (first.kind === 'array') return args.length === 1;
  if (first.kind === 'string') return args.length === 2;
  return args.length === 1;
}

function fromOrigin(name: string, origin: Origin): TaintHit {
  if (origin === 'none') return NONE;
  return { direct: false, viaVar: true, via: name, source: origin === 'superglobal' ? undefined : origin };
}

// Klucz tablicy będący literałem tekstowym albo liczbowym.
function literalKey(v: unknown): string | undefined {
  const n = asNode(v);
  if (!n) return undefined;
  if (n.kind === 'string' && typeof n.value === 'string') return n.value;
  if (n.kind === 'number' && typeof n.value === 'string') return n.value;
  return undefined;
}

function requestHit(name: string): TaintHit {
  return { direct: false, viaVar: true, via: name, source: 'request' };
}

function evalTaint(node: unknown, spec: TaintSpec, env: Env): TaintHit {
  if (Array.isArray(node)) {
    let acc = NONE;
    for (const e of node as unknown[]) acc = merge(acc, evalTaint(e, spec, env));
    return acc;
  }
  const n = asNode(node);
  if (!n || typeof n.kind !== 'string') return NONE;
  if (NO_TAINT_KINDS.has(n.kind)) return NONE;

  switch (n.kind) {
    case 'variable': {
      const name = n.name;
      if (typeof name !== 'string') return NONE;
      if (SUPERGLOBALS.has(name)) return { direct: true, viaVar: false };
      return fromOrigin(name, env.origin(name));
    }
    case 'offsetlookup': {
      const base = baseVariable(n);
      if (base && base.kind === 'variable' && typeof base.name === 'string') {
        if (base.name === '_SERVER') {
          const key = literalString(n.offset);
          if (key !== undefined && SERVER_SAFE_KEYS.has(key)) return NONE;
        }
        if (env.isRequestVar(base.name as string)) return requestHit(base.name as string);
        const inner = asNode(n.what);
        if (inner && inner.kind === 'variable') {
          // $tablica['klucz']: jeśli znamy ten element, oceniamy tylko jego, nie całą tablicę.
          const key = literalKey(n.offset);
          const known = key === undefined ? undefined : env.originKey(base.name as string, key);
          if (known !== undefined) return fromOrigin(base.name as string, known);
          return evalTaint(base, spec, env);
        }
        // $tablica['a']['b']: precyzja na pierwszym poziomie, dalsze klucze dziedziczą.
        if (inner && inner.kind === 'offsetlookup') return evalTaint(inner, spec, env);
        return evalTaint(base, spec, env);
      }
      return evalTaint(n.what, spec, env);
    }
    case 'cast':
      return NEUTRAL_CASTS.has(String(n.type ?? '').toLowerCase())
        ? NONE
        : evalTaint(n.expr, spec, env);
    case 'silent':
      return evalTaint(n.expr, spec, env);
    case 'assign':
      return evalTaint(n.right, spec, env);
    case 'bin':
      return n.type === '.' || n.type === '??'
        ? merge(evalTaint(n.left, spec, env), evalTaint(n.right, spec, env))
        : NONE;
    case 'retif':
      return merge(
        evalTaint(n.trueExpr ?? n.test, spec, env),
        evalTaint(n.falseExpr, spec, env),
      );
    case 'call': {
      const name = calledName(n);
      if (name) {
        if (spec.clean.has(name)) return NONE;
        const args = Array.isArray(n.arguments) ? (n.arguments as unknown[]) : [];
        if (isRawInputCall(name, args)) return { direct: true, viaVar: false };
        if (spec.queryArgSource && queryArgWithoutUrl(name, args)) {
          const inner = evalTaint(args, spec, env);
          return inner.direct ? inner : { direct: true, viaVar: false, source: 'url' };
        }
        if (name === 'array_map') {
          const fn = literalString(args[0]);
          if (fn !== undefined && spec.clean.has(fn.toLowerCase())) return NONE;
        }
        return PASSTHROUGH.has(name) ? evalTaint(args, spec, env) : NONE;
      }
      // Wywołanie metody. Interesuje nas tylko $wpdb->prepare i pokrewne.
      const callee = asNode(n.what);
      if (callee && callee.kind === 'propertylookup') {
        const base = asNode(callee.what);
        const method = offsetName(callee.offset);
        if (base && base.kind === 'variable' && typeof base.name === 'string' && method && REST_GETTERS.has(method)) {
          if (env.isRequestVar(base.name)) return requestHit(base.name);
        }
        if (base && base.kind === 'variable' && base.name === 'wpdb' && method && spec.methodClean?.has(method)) {
          return NONE;
        }
      }
      return NONE;
    }
    default: {
      let acc = NONE;
      for (const k of Object.keys(n)) {
        if (SKIP_KEYS.has(k)) continue;
        const v = n[k];
        if (v && typeof v === 'object') acc = merge(acc, evalTaint(v, spec, env));
      }
      return acc;
    }
  }
}

// Zdarzenie zmieniające stan skażenia zmiennej.
interface TaintEvent {
  off: number; // pozycja końca przypisania, żeby prawa strona widziała stan sprzed
  names: string[];
  expr: unknown;
  compound: boolean;
  key?: string; // zdarzenie dotyczy elementu names[0][key], nie całej zmiennej
}

function keyName(name: string, key: string): string {
  return name + '[' + key + ']';
}

function endOffset(node: AnyNode | undefined): number {
  const loc = node?.loc as { end?: { offset?: number } } | undefined;
  return loc?.end?.offset ?? 0;
}

function startOffset(node: unknown): number {
  const loc = asNode(node)?.loc as { start?: { offset?: number } } | undefined;
  return loc?.start?.offset ?? Number.MAX_SAFE_INTEGER;
}

function collectEvents(node: unknown, root: AnyNode, out: TaintEvent[]): void {
  if (Array.isArray(node)) {
    for (const e of node as unknown[]) collectEvents(e, root, out);
    return;
  }
  const n = asNode(node);
  if (!n || typeof n.kind !== 'string') return;
  if (n !== root && SCOPE_KINDS.has(n.kind)) return; // zagnieżdżony zakres ma własny stan

  if (n.kind === 'assign') {
    const left = asNode(n.left);
    if (left) {
      const isElement = left.kind === 'offsetlookup';
      const target = isElement ? baseVariable(left) : left;
      if (target && target.kind === 'variable' && typeof target.name === 'string') {
        const plain = n.operator === '=' || typeof n.operator !== 'string';
        out.push({
          off: endOffset(n),
          names: [target.name],
          expr: n.right,
          compound: isElement || !plain,
        });
        // Elementy o literalnych kluczach śledzimy osobno, żeby jeden skażony
        // element nie skażał całej tablicy przy odczycie innego klucza.
        const right = asNode(n.right);
        if (isElement) {
          const innerNode = asNode(left.what);
          const key = literalKey(left.offset);
          if (innerNode && innerNode.kind === 'variable' && key !== undefined) {
            out.push({ off: endOffset(n), names: [keyName(target.name, key)], expr: n.right, compound: !plain, key });
          }
        } else if (plain && right && right.kind === 'array') {
          const items = Array.isArray(right.items) ? (right.items as unknown[]) : [];
          for (const it of items) {
            const entry = asNode(it);
            const key = entry ? literalKey(entry.key) : undefined;
            if (entry && key !== undefined) {
              out.push({ off: endOffset(n), names: [keyName(target.name, key)], expr: entry.value, compound: false, key });
            }
          }
        }
      }
    }
  } else if (n.kind === 'call' && calledName(n) === 'extract') {
    // extract( shortcode_atts( array( 'a' => .., 'b' => .. ), $atts ) ) tworzy zmienne $a i $b.
    const inner = asNode(Array.isArray(n.arguments) ? (n.arguments as unknown[])[0] : undefined);
    const pairs = inner && calledName(inner) === 'shortcode_atts' && Array.isArray(inner.arguments) ? asNode((inner.arguments as unknown[])[0]) : undefined;
    if (inner && pairs && pairs.kind === 'array') {
      const names: string[] = [];
      for (const it of Array.isArray(pairs.items) ? (pairs.items as unknown[]) : []) {
        const key = literalKey(asNode(it)?.key);
        if (key !== undefined && /^[A-Za-z_]\w*$/.test(key)) names.push(key);
      }
      if (names.length) out.push({ off: endOffset(n), names, expr: inner, compound: false });
    }
  } else if (n.kind === 'foreach') {
    const names: string[] = [];
    for (const v of [asNode(n.key), asNode(n.value)]) {
      if (v && v.kind === 'variable' && typeof v.name === 'string') names.push(v.name);
    }
    if (names.length) out.push({ off: endOffset(asNode(n.source)), names, expr: n.source, compound: false });
  }

  for (const k of Object.keys(n)) {
    if (SKIP_KEYS.has(k)) continue;
    const v = n[k];
    if (v && typeof v === 'object') collectEvents(v, root, out);
  }
}

interface Scoped {
  // Dla zmiennych: reset=true, gdy zdarzenie zastępuje całą wartość (zwykłe przypisanie).
  history: Map<string, Array<{ off: number; origin: Origin; reset: boolean }>>;
  requests: Set<string>;
}

// Parametry funkcji, które są obiektem żądania REST: typ WP_REST_Request
// albo zwyczajowa nazwa $request.
function requestParams(scope: AnyNode): Set<string> {
  const out = new Set<string>();
  const params = Array.isArray(scope.arguments) ? (scope.arguments as unknown[]) : [];
  for (const p of params) {
    const param = asNode(p);
    const id = asNode(param?.name);
    const name = typeof id?.name === 'string' ? id.name : typeof param?.name === 'string' ? param.name : undefined;
    if (!name) continue;
    const type = asNode(param?.type);
    const typeName = typeof type?.name === 'string' ? type.name.replace(/^\\/, '') : '';
    if (typeName === 'WP_REST_Request' || (name === 'request' && !typeName)) out.add(name);
  }
  return out;
}

// Parametry funkcji, które mogą nieść tekst. Typ liczbowy albo logiczny je wyklucza.
const SCALAR_TYPES = new Set(['int', 'integer', 'float', 'double', 'bool', 'boolean']);

// Parametry o takich nazwach to zwykle nazwa tabeli albo gotowe zapytanie przekazane dalej.
const BENIGN_PARAM = /^(?:table|table_name|tablename|tbl|prefix|query|sql|sql_query|mysql_query|request)$/i;

export function untypedParams(scope: AnyNode): string[] {
  const out: string[] = [];
  const params = Array.isArray(scope.arguments) ? (scope.arguments as unknown[]) : [];
  for (const p of params) {
    const param = asNode(p);
    const id = asNode(param?.name);
    const name = typeof id?.name === 'string' ? id.name : typeof param?.name === 'string' ? param.name : undefined;
    if (!name) continue;
    const type = asNode(param?.type);
    const typeName = typeof type?.name === 'string' ? type.name.toLowerCase() : '';
    if (SCALAR_TYPES.has(typeName) || BENIGN_PARAM.test(name)) continue;
    out.push(name);
  }
  return out;
}

type Seeds = Array<{ name: string; source: TaintSource }>;

function buildScope(scope: AnyNode, spec: TaintSpec, seeds: Seeds = []): Scoped {
  const events: TaintEvent[] = [];
  collectEvents(scope, scope, events);
  events.sort((a, b) => a.off - b.off);

  const requests = requestParams(scope);
  const current = new Map<string, Origin>();
  const currentKeys = new Map<string, Origin>();
  const history: Scoped['history'] = new Map();
  if (spec.paramSource) {
    for (const name of untypedParams(scope)) {
      current.set(name, 'param');
      history.set(name, [{ off: -1, origin: 'param', reset: true }]);
    }
  }
  for (const seed of seeds) {
    current.set(seed.name, seed.source);
    history.set(seed.name, [{ off: -1, origin: seed.source, reset: true }]);
  }
  const env: Env = {
    origin: (name) => current.get(name) ?? 'none',
    originKey: (name, key) => currentKeys.get(keyName(name, key)),
    isRequestVar: (name) => requests.has(name) && (current.get(name) ?? 'none') === 'none',
  };
  for (const ev of events) {
    const hit = evalTaint(ev.expr, spec, env);
    let incoming: Origin = 'none';
    if (hit.direct) incoming = 'superglobal';
    else if (hit.viaVar) incoming = hit.source ?? 'superglobal';
    for (const name of ev.names) {
      const store = ev.key !== undefined ? currentKeys : current;
      let previous = store.get(name) ?? 'none';
      if (ev.key !== undefined && !store.has(name)) {
        // Pierwsze przypisanie do klucza: poprzednia wartość to stan całej tablicy.
        previous = current.get(name.slice(0, name.length - ev.key.length - 2)) ?? 'none';
      }
      const origin = incoming !== 'none' ? incoming : ev.compound ? previous : 'none';
      store.set(name, origin);
      const reset = ev.key === undefined && !ev.compound;
      if (reset) {
        // Nowa wartość całej zmiennej unieważnia znane elementy.
        const prefix = name + '[';
        for (const k of [...currentKeys.keys()]) if (k.startsWith(prefix)) currentKeys.delete(k);
      }
      const list = history.get(name) ?? [];
      list.push({ off: ev.off, origin, reset });
      history.set(name, list);
    }
  }
  return { history, requests };
}

function originAt(scoped: Scoped, name: string, off: number): Origin {
  const list = scoped.history.get(name);
  if (!list) return 'none';
  for (let i = list.length - 1; i >= 0; i--) {
    if (list[i].off <= off) return list[i].origin;
  }
  return 'none';
}

// Skażenie elementu o literalnym kluczu w danym miejscu kodu. undefined, gdy
// klucz nie był przypisywany po ostatnim nadpisaniu całej zmiennej.
function originKeyAt(scoped: Scoped, name: string, key: string, off: number): Origin | undefined {
  const keyList = scoped.history.get(keyName(name, key));
  if (!keyList) return undefined;
  let found: { off: number; origin: Origin } | undefined;
  for (let i = keyList.length - 1; i >= 0; i--) {
    if (keyList[i].off <= off) {
      found = keyList[i];
      break;
    }
  }
  if (!found) return undefined;
  const whole = scoped.history.get(name);
  if (whole) {
    for (let i = whole.length - 1; i >= 0; i--) {
      if (whole[i].off > off || !whole[i].reset) continue;
      if (whole[i].off > found.off) return undefined;
      break;
    }
  }
  return found.origin;
}

// Analizator dla jednego pliku i jednej klasy ujścia. Stan zakresu liczymy
// raz i pamiętamy, więc wiele ujść w jednej funkcji nie liczy się wielokrotnie.
export class TaintAnalyzer {
  private readonly cache = new WeakMap<AnyNode, Scoped>();
  private readonly seeds = new Map<AnyNode, Seeds>();

  constructor(
    private readonly program: AnyNode,
    private readonly spec: TaintSpec,
  ) {}

  // Oznacza parametr funkcji jako źródło danych (na przykład $atts w callbacku shortcode).
  // Trzeba to zrobić przed pierwszą analizą w tym zakresie.
  seed(scope: AnyNode, name: string, source: TaintSource): void {
    const list = this.seeds.get(scope) ?? [];
    list.push({ name, source });
    this.seeds.set(scope, list);
  }

  private scopeOf(stack: PhpNode[]): AnyNode {
    for (let i = stack.length - 1; i >= 0; i--) {
      if (SCOPE_KINDS.has(stack[i].kind)) return stack[i] as AnyNode;
    }
    return this.program;
  }

  // stack to przodkowie ujścia z obchodu AST. expr to wyrażenie do oceny.
  // at wskazuje węzeł, wg którego liczymy pozycję (domyślnie sam expr).
  analyze(expr: unknown, stack: PhpNode[], at?: unknown): TaintHit {
    const scope = this.scopeOf(stack);
    let scoped = this.cache.get(scope);
    if (!scoped) {
      scoped = buildScope(scope, this.spec, this.seeds.get(scope));
      this.cache.set(scope, scoped);
    }
    const off = startOffset(at ?? expr);
    const s = scoped;
    return evalTaint(expr, this.spec, {
      origin: (name) => originAt(s, name, off),
      originKey: (name, key) => originKeyAt(s, name, key, off),
      // Zmienna żądania traci ten status po nadpisaniu przez przypisanie.
      isRequestVar: (name) => s.requests.has(name) && !s.history.has(name),
    });
  }
}

// Opis źródła danych do komunikatów reguł.
export function originText(hit: TaintHit): string {
  if (hit.source === 'request') return 'z żądania REST';
  if (hit.source === 'url') return 'z adresu bieżącej strony (add_query_arg bez adresu)';
  if (hit.source === 'param') return 'z parametru funkcji';
  if (hit.source === 'shortcode') return 'z atrybutów shortcode';
  return 'od użytkownika';
}
