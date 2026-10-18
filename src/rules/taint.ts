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
  direct: boolean; // superglobal bezpośrednio w wyrażeniu
  viaVar: boolean; // zmienna skażona wcześniejszym przypisaniem
  via?: string; // nazwa pierwszej skażonej zmiennej
}

export interface TaintSpec {
  // Funkcje, po których wartość jest bezpieczna dla danej klasy ujścia.
  clean: ReadonlySet<string>;
  // Metody obiektu $wpdb zwracające bezpieczną wartość (prepare).
  methodClean?: ReadonlySet<string>;
}

const NONE: TaintHit = { direct: false, viaVar: false };

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
  'array_unique', 'array_reverse', 'array_keys', 'array_combine',
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
export const INCLUDE_SPEC: TaintSpec = { clean: new Set(INCLUDE_CLEAN) };
export const EXEC_SPEC: TaintSpec = { clean: new Set(EXEC_CLEAN) };
export const XSS_SPEC: TaintSpec = { clean: new Set(XSS_CLEAN) };

function merge(a: TaintHit, b: TaintHit): TaintHit {
  if (!a.direct && !a.viaVar) return b;
  if (!b.direct && !b.viaVar) return a;
  return { direct: a.direct || b.direct, viaVar: a.viaVar || b.viaVar, via: a.via ?? b.via };
}

function literalString(v: unknown): string | undefined {
  const n = asNode(v);
  return n && n.kind === 'string' && typeof n.value === 'string' ? n.value : undefined;
}

function evalTaint(node: unknown, spec: TaintSpec, isTainted: (name: string) => boolean): TaintHit {
  if (Array.isArray(node)) {
    let acc = NONE;
    for (const e of node as unknown[]) acc = merge(acc, evalTaint(e, spec, isTainted));
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
      return isTainted(name) ? { direct: false, viaVar: true, via: name } : NONE;
    }
    case 'offsetlookup': {
      const base = baseVariable(n);
      if (base && base.kind === 'variable' && typeof base.name === 'string') {
        if (base.name === '_SERVER') {
          const key = literalString(n.offset);
          if (key !== undefined && SERVER_SAFE_KEYS.has(key)) return NONE;
        }
        return evalTaint(base, spec, isTainted);
      }
      return evalTaint(n.what, spec, isTainted);
    }
    case 'cast':
      return NEUTRAL_CASTS.has(String(n.type ?? '').toLowerCase())
        ? NONE
        : evalTaint(n.expr, spec, isTainted);
    case 'silent':
      return evalTaint(n.expr, spec, isTainted);
    case 'assign':
      return evalTaint(n.right, spec, isTainted);
    case 'bin':
      return n.type === '.' || n.type === '??'
        ? merge(evalTaint(n.left, spec, isTainted), evalTaint(n.right, spec, isTainted))
        : NONE;
    case 'retif':
      return merge(
        evalTaint(n.trueExpr ?? n.test, spec, isTainted),
        evalTaint(n.falseExpr, spec, isTainted),
      );
    case 'call': {
      const name = calledName(n);
      if (name) {
        if (spec.clean.has(name)) return NONE;
        const args = Array.isArray(n.arguments) ? (n.arguments as unknown[]) : [];
        if (name === 'array_map') {
          const fn = literalString(args[0]);
          if (fn !== undefined && spec.clean.has(fn.toLowerCase())) return NONE;
        }
        return PASSTHROUGH.has(name) ? evalTaint(args, spec, isTainted) : NONE;
      }
      // Wywołanie metody. Interesuje nas tylko $wpdb->prepare i pokrewne.
      const callee = asNode(n.what);
      if (callee && callee.kind === 'propertylookup') {
        const base = asNode(callee.what);
        const method = offsetName(callee.offset);
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
        if (v && typeof v === 'object') acc = merge(acc, evalTaint(v, spec, isTainted));
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
        out.push({
          off: endOffset(n),
          names: [target.name],
          expr: n.right,
          compound: isElement || (typeof n.operator === 'string' && n.operator !== '='),
        });
      }
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

type History = Map<string, Array<{ off: number; tainted: boolean }>>;

function buildHistory(scope: AnyNode, spec: TaintSpec): History {
  const events: TaintEvent[] = [];
  collectEvents(scope, scope, events);
  events.sort((a, b) => a.off - b.off);

  const current = new Map<string, boolean>();
  const history: History = new Map();
  for (const ev of events) {
    const hit = evalTaint(ev.expr, spec, (name) => current.get(name) ?? false);
    const incoming = hit.direct || hit.viaVar;
    for (const name of ev.names) {
      const tainted = incoming || (ev.compound && (current.get(name) ?? false));
      current.set(name, tainted);
      const list = history.get(name) ?? [];
      list.push({ off: ev.off, tainted });
      history.set(name, list);
    }
  }
  return history;
}

function taintedAt(history: History, name: string, off: number): boolean {
  const list = history.get(name);
  if (!list) return false;
  for (let i = list.length - 1; i >= 0; i--) {
    if (list[i].off <= off) return list[i].tainted;
  }
  return false;
}

// Analizator dla jednego pliku i jednej klasy ujścia. Stan zakresu liczymy
// raz i pamiętamy, więc wiele ujść w jednej funkcji nie liczy się wielokrotnie.
export class TaintAnalyzer {
  private readonly cache = new WeakMap<AnyNode, History>();

  constructor(
    private readonly program: AnyNode,
    private readonly spec: TaintSpec,
  ) {}

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
    let history = this.cache.get(scope);
    if (!history) {
      history = buildHistory(scope, this.spec);
      this.cache.set(scope, history);
    }
    const off = startOffset(at ?? expr);
    return evalTaint(expr, this.spec, (name) => taintedAt(history!, name, off));
  }
}
