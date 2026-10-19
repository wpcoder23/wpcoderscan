// Lekka analiza skażenia danych w obrębie jednej funkcji (albo pliku).
// Nie jest to pełna analiza przepływu. Śledzimy tylko to, co widać w jednym
// zakresie: dane wprost z superglobala oraz zmienne, do których ostatnio
// przypisano takie dane. Kolejność przypisań liczy się wg pozycji w kodzie,
// więc `$id = absint( $id )` zdejmuje skażenie. Funkcje nieznane nie przenoszą
// skażenia. To celowo ostrożne podejście: wolimy przeoczyć niż zalać
// użytkownika fałszywymi alarmami. Przepływ przez wywołania funkcji z tego
// samego pliku dokłada callers.ts, przez zasianie parametrów (seed).
import { asNode, baseVariable, calledName, offsetName, SUPERGLOBALS, type AnyNode } from './ast-utils';
import { confirmedBy, confirmedByNegation, elementPath, guardedNames } from './guards';
import type { Translate } from '../i18n';
import type { PhpNode } from './types';

export interface TaintHit {
  direct: boolean; // superglobal (albo filter_input, php://input) bezpośrednio w wyrażeniu
  viaVar: boolean; // zmienna skażona wcześniejszym przypisaniem albo parametr żądania REST
  via?: string; // nazwa pierwszej skażonej zmiennej
  source?: TaintSource; // pochodzenie, gdy nie jest to zwykły superglobal
  // Całe skażenie przeszło przez funkcję ucieczki cudzysłowów (esc_sql, addslashes). Chroni ona wartość
  // ujętą w cudzysłowy zapytania, więc takie trafienie uznajemy za czyste, dopóki nie trafi poza cudzysłów.
  escaped?: boolean;
  // Wartość po ucieczce cudzysłowów stoi w zapytaniu poza cudzysłowem (liczba, kolumna, ORDER BY).
  unquoted?: boolean;
}

// request: obiekt żądania REST. url: add_query_arg bez adresu, czyli bieżący adres strony.
// param: parametr funkcji (tylko w trybie rozszerzonym).
// shortcode: atrybuty shortcode, które autor wpisu (Contributor) wpisuje bez filtrowania.
// caller: parametr funkcji, któremu wywołanie z tego samego pliku przekazuje dane użytkownika.
export type TaintSource = 'request' | 'url' | 'param' | 'shortcode' | 'caller';

// Czy zmienna jest skażona i skąd. Żądanie REST daje tylko heurystykę, bo trasa
// może walidować argumenty przez args (type, sanitize_callback), czego nie widzimy.
type Origin = 'none' | 'superglobal' | TaintSource | EscapedOrigin;
// Zmienna, która przechowuje dane po ucieczce cudzysłowów. Znacznik ~ odróżnia je od zwykłego skażenia.
type EscapedOrigin = `${'superglobal' | TaintSource}~`;

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
  // Funkcje ucieczki cudzysłowów (esc_sql, addslashes). Chronią wartość wstawioną w cudzysłowy zapytania,
  // ale nie liczbę, nazwę kolumny ani kierunek sortowania wklejone bez cudzysłowu.
  escapers?: ReadonlySet<string>;
  // add_query_arg i remove_query_arg bez adresu zwracają bieżący adres strony,
  // który kontroluje atakujący. Dla XSS to źródło danych.
  queryArgSource?: boolean;
  // Parametry funkcji liczymy jako dane o nieznanym pochodzeniu (tryb rozszerzony).
  paramSource?: boolean;
  // Rzutowanie na liczbę nie zdejmuje skażenia. Tak jest, gdy liczba wybiera zasób (identyfikator
  // użytkownika), więc atakujący nadal decyduje o wyniku mimo (int).
  keepCasts?: boolean;
  // Funkcje, które przenoszą skażenie z argumentów na wynik poza wspólną listą (na przykład wyszukanie
  // użytkownika po adresie e-mail z żądania).
  extraPassthrough?: ReadonlySet<string>;
  // foreach po tablicy zbudowanej z literalnymi kluczami nie skaża zmiennej klucza, bo klucze wybiera autor
  // kodu, a od użytkownika pochodzą tylko wartości.
  literalKeys?: boolean;
  // $plik['tmp_name'], $plik['size'] i $plik['error'] w zmiennej to wpis tablicy wysłanego pliku. Te pola
  // ustawia serwer, więc ścieżka pliku tymczasowego nie jest ścieżką od użytkownika.
  fileEntriesClean?: boolean;
  // preg_replace( '/[^a-z0-9_-]/i', '', $nazwa ) zostawia tylko znaki z klasy. Bez ukośnika w klasie wynik
  // nie ma separatora, więc nie jest ścieżką wychodzącą poza katalog.
  pathSanitizer?: boolean;
  // Sprawdzenie stałego przedrostka (str_starts_with, strpos( $v, 'abc_' ) === 0) zawęża wartość na tyle, że nie jest
  // już dowolna. Dotyczy nazw opcji: przedrostek wtyczki ogranicza zapis do jej własnych opcji.
  prefixGuards?: boolean;
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

// Elementy $_FILES ustawiane przez serwer: nazwa pliku tymczasowego, rozmiar i kod błędu. Nazwa pliku z komputera
// użytkownika (name, full_path) i typ MIME to dane od klienta, więc zostają skażone.
const FILES_SERVER_KEYS = new Set(['tmp_name', 'size', 'error']);

// $_FILES[ pole ][ 'tmp_name' ] i dalsze indeksy (przy wielu plikach): drugi poziom kluczy to właściwość pliku.
function isServerFilesElement(n: AnyNode): boolean {
  const keys: Array<string | undefined> = [];
  let cur: AnyNode | undefined = n;
  while (cur && cur.kind === 'offsetlookup') {
    const k = asNode(cur.offset);
    keys.unshift(k && k.kind === 'string' && typeof k.value === 'string' ? k.value : undefined);
    cur = asNode(cur.what);
  }
  const key = keys[1];
  return !!cur && cur.kind === 'variable' && cur.name === '_FILES' && key !== undefined && FILES_SERVER_KEYS.has(key);
}

// Superglobale, w których pole tmp_name oznaczałoby dane podane przez atakującego, a nie wpis $_FILES.
const REQUEST_GLOBALS = new Set(['_GET', '_POST', '_REQUEST', '_COOKIE']);

// $plik['tmp_name'] i $pliki['pole']['tmp_name'][ $i ] w zmiennej, która najpewniej trzyma wpis $_FILES
// (przypisany wcześniej albo przekazany do funkcji).
function isFilesEntryOfVariable(n: AnyNode): boolean {
  let found = false;
  let cur: AnyNode | undefined = n;
  while (cur && cur.kind === 'offsetlookup') {
    const k = asNode(cur.offset);
    if (k && k.kind === 'string' && typeof k.value === 'string' && FILES_SERVER_KEYS.has(k.value)) found = true;
    cur = asNode(cur.what);
  }
  return found && !!cur && cur.kind === 'variable' && typeof cur.name === 'string' && !REQUEST_GLOBALS.has(cur.name);
}

// Czy klasa znaków [^...] pozwala na ukośnik albo odwrotny ukośnik (zapisany wprost albo z ucieczką).
function classAllowsSeparator(body: string): boolean {
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '/') return true;
    if (c === '\\') {
      if (body[i + 1] === '/' || body[i + 1] === '\\') return true;
      i++;
    }
  }
  return false;
}

// preg_replace( '/[^a-z0-9_-]/i', '', $nazwa ): usuwa wszystko poza klasą, a w klasie nie ma separatora ścieżki.
function stripsPathSeparators(pattern: unknown, replacement: unknown): boolean {
  const p = literalString(pattern);
  const r = literalString(replacement);
  if (p === undefined || r === undefined || /[\\/]/.test(r)) return false;
  for (const m of p.matchAll(/\[\^((?:\\.|[^\]\\])*)\]/g)) {
    if (!classAllowsSeparator(m[1])) return true;
  }
  return false;
}

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
  'sanitize_text_field', 'sanitize_textarea_field', 'sanitize_email', 'sanitize_user', 'wc_clean',
  'esc_html', 'esc_attr', 'esc_url', 'esc_url_raw', 'esc_js', 'esc_textarea',
  'wp_kses', 'wp_kses_post', 'wp_kses_data', 'htmlspecialchars', 'htmlentities',
  'wp_json_encode', 'addslashes',
  // Przekształcenia tekstu i tablic, które zwracają fragment albo kopię argumentu.
  'strval', 'str_pad', 'strrev', 'wordwrap', 'addcslashes', 'quotemeta', 'chunk_split', 'strtr', 'strstr', 'stristr',
  'strrchr', 'strtok', 'str_split', 'mb_str_split', 'preg_split', 'preg_replace_callback', 'preg_filter', 'preg_quote',
  'utf8_decode', 'utf8_encode', 'mb_convert_encoding', 'mb_convert_case', 'mb_strimwidth', 'iconv',
  'array_pop', 'array_shift', 'array_diff', 'array_flip', 'array_merge_recursive', 'array_replace', 'array_pad',
  'array_chunk', 'array_column', 'array_fill_keys', 'array_splice', 'current', 'reset', 'end', 'next', 'prev',
  'wp_parse_args', 'wp_slash', 'parse_url',
  // Ścieżki sklejane z argumentu bez żadnej ucieczki.
  'dirname', 'wp_normalize_path', 'trailingslashit', 'untrailingslashit',
]);

// Funkcje budujące adres witryny z fragmentu podanego w argumencie. Dla XSS niosą skażenie dalej (adres wypisany
// bez esc_url), ale host takiego adresu zawsze jest naszą witryną, więc dla SSRF nie są przepustką.
const URL_BUILDERS = new Set([
  'admin_url', 'site_url', 'home_url', 'network_admin_url', 'network_site_url', 'network_home_url',
  'self_admin_url', 'get_admin_url', 'get_site_url', 'get_home_url', 'plugins_url', 'content_url',
  'includes_url', 'wp_login_url', 'wp_logout_url', 'wp_lostpassword_url',
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
  'sanitize_key', 'sanitize_title', 'sanitize_title_with_dashes', 'wp_parse_id_list', 'sanitize_sql_orderby',
];

const SQL_ESCAPERS = ['esc_sql', 'mysqli_real_escape_string', 'mysqli_escape_string', 'addslashes'];

// Metody $wpdb ucinające cudzysłowy, odpowiedniki esc_sql.
const WPDB_ESCAPE_METHODS = new Set(['_escape', '_real_escape', 'escape']);

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
  'sanitize_text_field', 'sanitize_textarea_field', 'sanitize_email', 'sanitize_key', 'wc_clean',
  'sanitize_title', 'sanitize_user', 'sanitize_file_name', 'sanitize_html_class',
  'wp_json_encode', 'htmlspecialchars', 'htmlentities',
];

// Kod wykonywany przez eval: czyści tylko to, co daje liczbę albo skrót.
export const CODE_SPEC: TaintSpec = { clean: new Set(COMMON_CLEAN) };

export const SQL_SPEC: TaintSpec = {
  clean: new Set(SQL_CLEAN),
  methodClean: new Set(['prepare']),
  escapers: new Set(SQL_ESCAPERS),
};
// Tryb rozszerzony: jak SQL_SPEC, ale parametry funkcji też są źródłem.
export const SQL_PARAM_SPEC: TaintSpec = { ...SQL_SPEC, paramSource: true };
export const INCLUDE_SPEC: TaintSpec = { clean: new Set(INCLUDE_CLEAN) };
export const EXEC_SPEC: TaintSpec = { clean: new Set(EXEC_CLEAN) };
export const XSS_SPEC: TaintSpec = { clean: new Set(XSS_CLEAN), queryArgSource: true, extraPassthrough: URL_BUILDERS };

// Ścieżka pliku: basename i sanitize_file_name zostawiają z nazwy tylko jej ostatni człon, więc nie da się
// wyjść poza katalog. Wynik wp_unique_filename też jest oczyszczoną nazwą.
export const PATH_SPEC: TaintSpec = {
  clean: new Set([...INCLUDE_CLEAN, 'wp_basename', 'wp_unique_filename']),
  literalKeys: true,
  fileEntriesClean: true,
  pathSanitizer: true,
};
// Adres URL, nazwa opcji, rola: liczby są czyste, a oczyszczanie tekstu niczego nie zmienia.
export const KEY_SPEC: TaintSpec = { clean: new Set(COMMON_CLEAN), literalKeys: true, prefixGuards: true };
// Nazwa wysyłanego pliku: basename, sanitize_file_name i wp_unique_filename zostawiają rozszerzenie, więc
// skażenie przechodzi dalej. O skutku decyduje rozszerzenie, nie sama ścieżka.
export const UPLOAD_SPEC: TaintSpec = {
  clean: new Set(COMMON_CLEAN),
  extraPassthrough: new Set(['basename', 'wp_basename', 'sanitize_file_name', 'wp_unique_filename', 'pathinfo']),
  literalKeys: true,
};
// Wyszukanie użytkownika po danych z żądania i rzutowanie na liczbę nie zmieniają tego, że wybiera go atakujący.
export const LOGIN_SPEC: TaintSpec = {
  clean: new Set(),
  keepCasts: true,
  literalKeys: true,
  extraPassthrough: new Set([
    'intval', 'absint', 'get_user_by', 'get_userdata', 'get_user_by_email', 'get_userbylogin',
    'email_exists', 'username_exists', 'get_user',
  ]),
};

// Jak groźne jest skażenie: 0 po ucieczce cudzysłowów (bezpieczne w cudzysłowie), 1 po ucieczce poza
// cudzysłowem, 2 zwykłe. Przy łączeniu wygrywa groźniejsze, bo jeden niezabezpieczony składnik wystarcza.
function danger(h: TaintHit): number {
  return h.escaped ? 0 : h.unquoted ? 1 : 2;
}

function merge(a: TaintHit, b: TaintHit): TaintHit {
  if (!a.direct && !a.viaVar) return b;
  if (!b.direct && !b.viaVar) return a;
  const da = danger(a);
  const db = danger(b);
  if (da !== db) return da > db ? a : b;
  const first = a.direct ? a : b.direct ? b : a;
  return {
    direct: a.direct || b.direct,
    viaVar: a.viaVar || b.viaVar,
    via: a.via ?? b.via,
    source: first.source,
    ...(a.escaped ? { escaped: true } : {}),
    ...(a.unquoted ? { unquoted: true } : {}),
  };
}

// Skażenie, które przeszło przez funkcję ucieczki cudzysłowów.
function escapedHit(inner: TaintHit): TaintHit {
  return inner.direct || inner.viaVar ? { ...inner, escaped: true } : NONE;
}

// Czy tekst zapytania kończy się w środku literału tekstowego. Backtick oznacza identyfikator, który esc_sql
// nie chroni, więc w nim wartość uznajemy za niezabezpieczoną.
function insideQuotes(sql: string): boolean {
  let single = 0;
  let double = 0;
  let tick = 0;
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    if (c === '\\') i++;
    else if (c === "'") single++;
    else if (c === '"') double++;
    else if (c === '`') tick++;
  }
  return tick % 2 === 0 && (single % 2 === 1 || double % 2 === 1);
}

// Składniki sklejanego tekstu po kolei: operandy łańcucha kropek i części napisu w cudzysłowie.
export function chainParts(node: unknown, out: AnyNode[]): void {
  const n = asNode(node);
  if (!n) return;
  if (n.kind === 'bin' && n.type === '.') {
    chainParts(n.left, out);
    chainParts(n.right, out);
  } else if (n.kind === 'encapsed' && (n.type === 'string' || n.type === 'heredoc') && Array.isArray(n.value)) {
    for (const part of n.value as unknown[]) chainParts(asNode(part)?.expression, out);
  } else {
    out.push(n);
  }
}

export function literalString(v: unknown): string | undefined {
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
  const escaped = origin.endsWith('~');
  const base = (escaped ? origin.slice(0, -1) : origin) as 'superglobal' | TaintSource;
  return {
    direct: false,
    viaVar: true,
    via: name,
    source: base === 'superglobal' ? undefined : base,
    ...(escaped ? { escaped } : {}),
  };
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
        if (base.name === '_FILES' && isServerFilesElement(n)) return NONE;
        if (spec.fileEntriesClean && isFilesEntryOfVariable(n)) return NONE;
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
        // $tablica['a']['b']: sprawdzony cały element jest czysty, a poza tym precyzja jest na pierwszym
        // poziomie i dalsze klucze dziedziczą.
        if (inner && inner.kind === 'offsetlookup') {
          const el = elementPath(n);
          if (el && env.originKey(el.base, el.path) === 'none') return NONE;
          return evalTaint(inner, spec, env);
        }
        return evalTaint(base, spec, env);
      }
      return evalTaint(n.what, spec, env);
    }
    case 'cast':
      return NEUTRAL_CASTS.has(String(n.type ?? '').toLowerCase()) && !spec.keepCasts
        ? NONE
        : evalTaint(n.expr, spec, env);
    case 'silent':
      return evalTaint(n.expr, spec, env);
    case 'assign':
      return evalTaint(n.right, spec, env);
    case 'bin':
      if (n.type === '.') return evalChain(n, spec, env);
      return n.type === '??' ? merge(evalTaint(n.left, spec, env), evalTaint(n.right, spec, env)) : NONE;
    case 'encapsed':
      if (n.type === 'string' || n.type === 'heredoc') return evalChain(n, spec, env);
      return evalTaint(n.value, spec, env);
    case 'retif': {
      // W gałęziach warunku działa to, co sam warunek potwierdza: is_numeric( $v ) ? $v : 0.
      const yes = n.trueExpr ? confirmedBy(n.test, undefined, spec.prefixGuards) : undefined;
      const no = confirmedByNegation(n.test, undefined, spec.prefixGuards);
      return merge(
        evalTaint(n.trueExpr ?? n.test, spec, yes ? withGuard(env, yes) : env),
        evalTaint(n.falseExpr, spec, withGuard(env, no)),
      );
    }
    case 'call': {
      const name = calledName(n);
      if (name) {
        if (spec.clean.has(name)) return NONE;
        const args = Array.isArray(n.arguments) ? (n.arguments as unknown[]) : [];
        if (spec.pathSanitizer && name === 'preg_replace' && stripsPathSeparators(args[0], args[1])) return NONE;
        if (spec.escapers?.has(name)) return escapedHit(evalTaint(args[0], spec, env));
        if (isRawInputCall(name, args)) return { direct: true, viaVar: false };
        if (spec.queryArgSource && queryArgWithoutUrl(name, args)) {
          const inner = evalTaint(args, spec, env);
          return inner.direct ? inner : { direct: true, viaVar: false, source: 'url' };
        }
        if (name === 'array_map') {
          const fn = literalString(args[0]);
          if (fn !== undefined && spec.clean.has(fn.toLowerCase())) return NONE;
          if (fn !== undefined && spec.escapers?.has(fn.toLowerCase())) return escapedHit(evalTaint(args[1], spec, env));
        }
        // array_filter( $lista, 'is_numeric' ) zostawia tylko wartości liczbowe.
        if (name === 'array_filter') {
          const fn = literalString(args[1]);
          if (fn !== undefined && spec.clean.has(fn.toLowerCase())) return NONE;
        }
        return PASSTHROUGH.has(name) || spec.extraPassthrough?.has(name) ? evalTaint(args, spec, env) : NONE;
      }
      // Wywołanie metody. Interesuje nas tylko $wpdb->prepare i pokrewne.
      const callee = asNode(n.what);
      if (callee && callee.kind === 'propertylookup') {
        const base = asNode(callee.what);
        const method = offsetName(callee.offset);
        if (base && base.kind === 'variable' && typeof base.name === 'string' && method && REST_GETTERS.has(method)) {
          if (env.isRequestVar(base.name)) return requestHit(base.name);
        }
        if (base && base.kind === 'variable' && base.name === 'wpdb' && method && spec.escapers && WPDB_ESCAPE_METHODS.has(method)) {
          return escapedHit(evalTaint((Array.isArray(n.arguments) ? (n.arguments as unknown[]) : [])[0], spec, env));
        }
        if (base && base.kind === 'variable' && base.name === 'wpdb' && method && spec.methodClean?.has(method)) {
          // prepare chroni wartości podane jako kolejne argumenty. Tekst zapytania sklejony z danych
          // (ORDER BY $kolumna, nazwa tabeli, fragment WHERE) zostaje po stronie wywołującego.
          if (method === 'prepare') return evalTaint((Array.isArray(n.arguments) ? (n.arguments as unknown[]) : [])[0], spec, env);
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

// Tekst sklejany z literałów i wyrażeń. Wartość po ucieczce cudzysłowów jest bezpieczna tylko w cudzysłowie,
// więc dla każdego składnika sprawdzamy, czy literały przed nim zostawiają otwarty cudzysłów. Gdy przed
// składnikiem nie ma żadnego literału, nie znamy kontekstu i zostawiamy wartość jako ochronioną, żeby
// ocenił ją tekst wokół całego wyrażenia. Rozstrzygnięta wartość w cudzysłowie jest czysta (NONE), więc
// zagnieżdżony łańcuch w nawiasie albo gałęzi warunku nie jest oceniany drugi raz.
function evalChain(node: AnyNode, spec: TaintSpec, env: Env): TaintHit {
  const parts: AnyNode[] = [];
  chainParts(node, parts);
  let acc = NONE;
  let text = '';
  for (const part of parts) {
    const lit = literalString(part);
    if (lit !== undefined) {
      text += lit;
      continue;
    }
    let hit = evalTaint(part, spec, env);
    if (hit.escaped && text !== '') {
      hit = insideQuotes(text)
        ? NONE
        : { direct: hit.direct, viaVar: hit.viaVar, via: hit.via, source: hit.source, unquoted: true };
    }
    acc = merge(acc, hit);
  }
  return acc;
}

// Zdarzenie zmieniające stan skażenia zmiennej.
interface TaintEvent {
  off: number; // pozycja końca przypisania, żeby prawa strona widziała stan sprzed
  names: string[];
  expr: unknown;
  compound: boolean;
  key?: string; // zdarzenie dotyczy elementu names[0][key], nie całej zmiennej
  guarded?: ReadonlySet<string>; // zmienne sprawdzone listą dozwolonych wartości przed tym miejscem
  path: BranchStep[]; // gałęzie warunków i pętli, w których leży zdarzenie
}

// Gałąź konstrukcji warunkowej (if, switch, pętla, try), w której leży miejsce w kodzie.
interface BranchStep {
  construct: number; // początek konstrukcji
  branch: number; // początek gałęzi
  tests: AnyNode[]; // wyrażenia, od których zależy wejście do gałęzi
}

function rangeOf(node: AnyNode | undefined): [number, number] | undefined {
  const loc = node?.loc as { start?: { offset?: number }; end?: { offset?: number } } | undefined;
  const s = loc?.start?.offset;
  const e = loc?.end?.offset;
  return typeof s === 'number' && typeof e === 'number' ? [s, e] : undefined;
}

function within(node: AnyNode | undefined, off: number): boolean {
  const r = rangeOf(node);
  return !!r && off >= r[0] && off < r[1];
}

// Gałęzie warunków i pętli, przez które przechodzi miejsce o pozycji off, od zewnętrznej do wewnętrznej.
// ancestors to przodkowie od zakresu w dół. Test warunku i nagłówek pętli nie należą do żadnej gałęzi.
function branchPath(ancestors: readonly AnyNode[], off: number): BranchStep[] {
  const path: BranchStep[] = [];
  const step = (construct: AnyNode, branch: AnyNode | undefined, tests: Array<AnyNode | undefined>): boolean => {
    if (!branch || !within(branch, off)) return false;
    path.push({ construct: startOffset(construct), branch: startOffset(branch), tests: tests.filter((t): t is AnyNode => !!t) });
    return true;
  };
  for (const n of ancestors) {
    switch (n.kind) {
      case 'if':
        if (!step(n, asNode(n.body), [asNode(n.test)])) step(n, asNode(n.alternate), [asNode(n.test)]);
        break;
      case 'switch': {
        const body = asNode(n.body);
        const cases = body && Array.isArray(body.children) ? (body.children as unknown[]) : [];
        for (const c of cases) {
          const cs = asNode(c);
          if (cs && step(n, cs, [asNode(n.test), asNode(cs.test)])) break;
        }
        break;
      }
      case 'while':
      case 'for':
        step(n, asNode(n.body), [asNode(n.test)]);
        break;
      case 'foreach':
        step(n, asNode(n.body), [asNode(n.source)]);
        break;
      case 'try':
        // Treść try wykonuje się zwykle do końca, więc nie jest gałęzią. Gałęzią jest dopiero obsługa wyjątku.
        for (const c of Array.isArray(n.catches) ? (n.catches as unknown[]) : []) if (step(n, asNode(c), [])) break;
        break;
      default:
        break;
    }
  }
  return path;
}

const mentionCache = new WeakMap<AnyNode, Set<string>>();

// Nazwy zmiennych użytych w wyrażeniu.
function mentionedVars(node: AnyNode): Set<string> {
  const cached = mentionCache.get(node);
  if (cached) return cached;
  const out = new Set<string>();
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const e of value as unknown[]) visit(e);
      return;
    }
    const v = asNode(value);
    if (!v) return;
    if (v.kind === 'variable' && typeof v.name === 'string') out.add(v.name);
    for (const k of Object.keys(v)) {
      if (SKIP_KEYS.has(k)) continue;
      const child = v[k];
      if (child && typeof child === 'object') visit(child);
    }
  };
  visit(node);
  mentionCache.set(node, out);
  return out;
}

// Warunek, który sprawdza samą zmienną (if ( $x ), if ( ! empty( $x ) )), rozstrzyga o jej wartości w obu gałęziach,
// więc przypisanie w takiej gałęzi uznajemy za pełne, a nie za jedną z możliwości.
function stepMentions(step: BranchStep, name: string): boolean {
  return step.tests.some((t) => mentionedVars(t).has(name));
}

type Relation = 'dominates' | 'may' | 'exclusive';

// Jak zdarzenie z gałęzi ev odnosi się do ujścia w gałęzi sink. dominates: zdarzenie wykonuje się przed każdym
// ujściem. may: wykona się tylko w części przebiegów. exclusive: leży w innej gałęzi tej samej konstrukcji.
function relate(ev: BranchStep[], sink: BranchStep[], name: string): Relation {
  if (ev.length === 0) return 'dominates';
  let i = 0;
  while (i < ev.length && i < sink.length && ev[i].construct === sink[i].construct && ev[i].branch === sink[i].branch) i++;
  if (i === ev.length) return 'dominates';
  if (i < sink.length && ev[i].construct === sink[i].construct) return 'exclusive';
  for (let j = i; j < ev.length; j++) if (!stepMentions(ev[j], name)) return 'may';
  return 'dominates';
}

// Łączy stan z dwóch zdarzeń. Późniejsze wygrywa, ale wartość po ucieczce cudzysłowów nie zasłania zwykłego skażenia.
function joinOrigin(later: Origin, earlier: Origin): Origin {
  if (later === 'none') return earlier;
  if (earlier === 'none') return later;
  if (later.endsWith('~') && !earlier.endsWith('~')) return earlier;
  return later;
}

// Środowisko, w którym sprawdzone zmienne uchodzą za czyste.
function withGuard(env: Env, guarded: ReadonlySet<string> | undefined): Env {
  if (!guarded || guarded.size === 0) return env;
  return {
    origin: (name) => (guarded.has(name) ? 'none' : env.origin(name)),
    originKey: (name, key) => (guarded.has(name) || guarded.has(keyName(name, key)) ? 'none' : env.originKey(name, key)),
    isRequestVar: (name) => !guarded.has(name) && env.isRequestVar(name),
  };
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

// Czy wyrażenie sięga po jakikolwiek superglobal.
function mentionsSuperglobal(node: unknown): boolean {
  if (Array.isArray(node)) return (node as unknown[]).some(mentionsSuperglobal);
  const n = asNode(node);
  if (!n) return false;
  if (n.kind === 'variable') return typeof n.name === 'string' && SUPERGLOBALS.has(n.name);
  for (const k of Object.keys(n)) {
    if (SKIP_KEYS.has(k)) continue;
    const v = n[k];
    if (v && typeof v === 'object' && mentionsSuperglobal(v)) return true;
  }
  return false;
}

// Tablica zapisana wprost, której wszystkie wpisy mają klucz literalny albo nie mają klucza wcale.
function literalEntries(arr: AnyNode): boolean {
  const items = Array.isArray(arr.items) ? (arr.items as unknown[]) : [];
  return items.every((it) => {
    const entry = asNode(it);
    if (!entry || entry.unpack === true) return false;
    const key = asNode(entry.key);
    return !key || literalKey(key) !== undefined;
  });
}

// Czy zmienna jest tablicą, którą w całym zakresie budują tylko zapisy z literalnymi kluczami: przypisanie
// tablicy zapisanej wprost albo $tablica['klucz'] = .. i $tablica[] = .. . Parametr funkcji i każdy inny zapis
// (wynik funkcji, żądanie, klucz ze zmiennej) wyklucza tę pewność.
function literalKeyedVariable(root: AnyNode, name: string): boolean {
  if (paramInfos(root).some((p) => p.name === name)) return false;
  let writes = 0;
  let ok = true;
  const visit = (node: unknown): void => {
    if (!ok) return;
    if (Array.isArray(node)) {
      for (const e of node as unknown[]) visit(e);
      return;
    }
    const n = asNode(node);
    if (!n) return;
    if (n.kind === 'assign') {
      const left = asNode(n.left);
      const base = left ? baseVariable(left) : undefined;
      if (left && base && base.kind === 'variable' && base.name === name) {
        writes++;
        if (left.kind === 'variable') {
          const right = asNode(n.right);
          if (!right || right.kind !== 'array' || !literalEntries(right)) ok = false;
        } else if (left.kind === 'offsetlookup') {
          let cur: AnyNode = left;
          for (let inner = asNode(cur.what); inner && inner.kind === 'offsetlookup'; inner = asNode(cur.what)) cur = inner;
          if (cur.offset && literalKey(cur.offset) === undefined) ok = false;
        } else {
          ok = false;
        }
      }
    } else if (n.kind === 'foreach') {
      for (const v of [asNode(n.key), asNode(n.value)]) if (v && v.kind === 'variable' && v.name === name) ok = false;
    }
    for (const k of Object.keys(n)) {
      if (SKIP_KEYS.has(k)) continue;
      const v = n[k];
      if (v && typeof v === 'object') visit(v);
    }
  };
  visit(root);
  return ok && writes > 0;
}

// Czy klucze tablicy po której iteruje foreach wybiera autor kodu, a nie użytkownik.
function keysAreLiteral(source: unknown, root: AnyNode): boolean {
  const src = asNode(source);
  if (!src) return false;
  if (src.kind === 'array') return literalEntries(src);
  if (src.kind === 'variable' && typeof src.name === 'string') return literalKeyedVariable(root, src.name);
  return false;
}

function collectEvents(node: unknown, root: AnyNode, out: TaintEvent[], anc: AnyNode[] = [], literalKeys = false, prefix = false): void {
  if (Array.isArray(node)) {
    for (const e of node as unknown[]) collectEvents(e, root, out, anc, literalKeys, prefix);
    return;
  }
  const n = asNode(node);
  if (!n || typeof n.kind !== 'string') return;
  if (n !== root && SCOPE_KINDS.has(n.kind)) return; // zagnieżdżony zakres ma własny stan

  const guardHere = (): ReadonlySet<string> | undefined => {
    const g = guardedNames(anc, startOffset(n), prefix);
    return g.size > 0 ? g : undefined;
  };
  let pathMemo: BranchStep[] | undefined;
  const pathHere = (): BranchStep[] => (pathMemo ??= branchPath(anc, startOffset(n)));

  if (n.kind === 'assign') {
    const left = asNode(n.left);
    if (left) {
      const isElement = left.kind === 'offsetlookup';
      const target = isElement ? baseVariable(left) : left;
      // Wartość domyślna wpisana do superglobala w jednej gałęzi ($_REQUEST['orderby'] = 'id' po empty())
      // nie czyści go dla reszty kodu, bo w drugiej gałęzi zostaje to, co przysłał użytkownik. Zapis, który
      // sam sięga po superglobal (sanitize_text_field( $_GET['x'] ), (int) $_GET['x']), nadal czyści.
      const keepsRequest = !!target && target.kind === 'variable' && SUPERGLOBALS.has(target.name as string) && !mentionsSuperglobal(n.right);
      if (target && target.kind === 'variable' && typeof target.name === 'string' && !keepsRequest) {
        const plain = n.operator === '=' || typeof n.operator !== 'string';
        out.push({
          off: endOffset(n),
          names: [target.name],
          expr: n.right,
          compound: isElement || !plain,
          guarded: guardHere(),
          path: pathHere(),
        });
        // Elementy o literalnych kluczach śledzimy osobno, żeby jeden skażony
        // element nie skażał całej tablicy przy odczycie innego klucza.
        const right = asNode(n.right);
        if (isElement) {
          const innerNode = asNode(left.what);
          const key = literalKey(left.offset);
          if (innerNode && innerNode.kind === 'variable' && key !== undefined) {
            out.push({ off: endOffset(n), names: [keyName(target.name, key)], expr: n.right, compound: !plain, key, guarded: guardHere(), path: pathHere() });
          }
        } else if (plain && right && right.kind === 'array') {
          const items = Array.isArray(right.items) ? (right.items as unknown[]) : [];
          for (const it of items) {
            const entry = asNode(it);
            const key = entry ? literalKey(entry.key) : undefined;
            if (entry && key !== undefined) {
              out.push({ off: endOffset(n), names: [keyName(target.name, key)], expr: entry.value, compound: false, key, guarded: guardHere(), path: pathHere() });
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
      if (names.length) out.push({ off: endOffset(n), names, expr: inner, compound: false, guarded: guardHere(), path: pathHere() });
    }
  } else if (n.kind === 'foreach') {
    const names: string[] = [];
    const keyVar = asNode(n.key);
    // Klucze tablicy z literalnymi kluczami wybiera autor kodu, więc zmienna klucza zostaje czysta.
    const cleanKey = literalKeys && keyVar?.kind === 'variable' && keysAreLiteral(n.source, root);
    for (const v of cleanKey ? [asNode(n.value)] : [keyVar, asNode(n.value)]) {
      if (v && v.kind === 'variable' && typeof v.name === 'string') names.push(v.name);
    }
    if (names.length) out.push({ off: endOffset(asNode(n.source)), names, expr: n.source, compound: false, guarded: guardHere(), path: pathHere() });
    if (cleanKey && typeof keyVar?.name === 'string') {
      out.push({ off: endOffset(asNode(n.source)), names: [keyVar.name], expr: undefined, compound: false, guarded: guardHere(), path: pathHere() });
    }
  }

  anc.push(n);
  for (const k of Object.keys(n)) {
    if (SKIP_KEYS.has(k)) continue;
    const v = n[k];
    if (v && typeof v === 'object') collectEvents(v, root, out, anc, literalKeys, prefix);
  }
  anc.pop();
}

// Jeden zapis do zmiennej. Dla zmiennych bez klucza origin to wkład samego zapisu (wynik prawej strony),
// a stan zmiennej w danym miejscu składa resolveOrigin. Dla elementów o literalnym kluczu origin to stan elementu.
interface HistoryEntry {
  off: number;
  origin: Origin;
  reset: boolean; // zapis zastępuje całą wartość (zwykłe przypisanie)
  compound: boolean; // zapis dopisuje do wartości (.=, +=, $a[] = ..)
  path: BranchStep[];
}

interface Scoped {
  history: Map<string, HistoryEntry[]>;
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

export interface ParamInfo {
  name: string; // bez dolara
  scalar: boolean; // typ liczbowy albo logiczny, więc nie niesie tekstu
}

// Parametry funkcji w kolejności deklaracji.
export function paramInfos(scope: AnyNode): ParamInfo[] {
  const out: ParamInfo[] = [];
  const params = Array.isArray(scope.arguments) ? (scope.arguments as unknown[]) : [];
  for (const p of params) {
    const param = asNode(p);
    const id = asNode(param?.name);
    const name = typeof id?.name === 'string' ? id.name : typeof param?.name === 'string' ? param.name : undefined;
    if (!name) continue;
    const type = asNode(param?.type);
    const typeName = typeof type?.name === 'string' ? type.name.toLowerCase() : '';
    out.push({ name, scalar: SCALAR_TYPES.has(typeName) });
  }
  return out;
}

export function untypedParams(scope: AnyNode): string[] {
  return paramInfos(scope)
    .filter((p) => !p.scalar && !BENIGN_PARAM.test(p.name))
    .map((p) => p.name);
}

// cleanKeys: elementy parametru znane jako czyste już w wywołaniu (na przykład klucz z literału).
// site: zakres, z którego wywołanie przekazało dane (dla źródła caller).
type Seeds = Array<{ name: string; source: TaintSource; cleanKeys?: string[]; site?: AnyNode }>;

function buildScope(scope: AnyNode, spec: TaintSpec, seeds: Seeds = []): Scoped {
  const events: TaintEvent[] = [];
  collectEvents(scope, scope, events, [], spec.literalKeys === true, spec.prefixGuards === true);
  events.sort((a, b) => a.off - b.off);

  const requests = requestParams(scope);
  const currentKeys = new Map<string, Origin>();
  const history: Scoped['history'] = new Map();
  if (spec.paramSource) {
    for (const name of untypedParams(scope)) {
      history.set(name, [{ off: -1, origin: 'param', reset: true, compound: false, path: [] }]);
    }
  }
  for (const seed of seeds) {
    history.set(seed.name, [{ off: -1, origin: seed.source, reset: true, compound: false, path: [] }]);
    for (const key of seed.cleanKeys ?? []) {
      const name = keyName(seed.name, key);
      currentKeys.set(name, 'none');
      history.set(name, [{ off: -1, origin: 'none', reset: false, compound: false, path: [] }]);
    }
  }
  // Zdarzenie, które właśnie liczymy: jego prawa strona czyta zmienne tak, jak wyglądały tuż przed nim.
  let cursorOff = 0;
  let cursorPath: BranchStep[] = [];
  const stateOf = (name: string): Origin => resolveOrigin(history.get(name), cursorOff, cursorPath, name);
  const env: Env = {
    origin: stateOf,
    originKey: (name, key) => currentKeys.get(keyName(name, key)),
    isRequestVar: (name) => requests.has(name) && stateOf(name) === 'none',
  };
  for (const ev of events) {
    cursorOff = ev.off;
    cursorPath = ev.path;
    const hit = evalTaint(ev.expr, spec, withGuard(env, ev.guarded));
    let incoming: Origin = 'none';
    if (hit.direct) incoming = 'superglobal';
    else if (hit.viaVar) incoming = hit.source ?? 'superglobal';
    if (incoming !== 'none' && hit.escaped) incoming = `${incoming as 'superglobal' | TaintSource}~`;
    for (const name of ev.names) {
      let origin = incoming;
      if (ev.key !== undefined) {
        // Elementy o literalnych kluczach liczymy liniowo, bez gałęzi.
        let previous = currentKeys.get(name);
        if (previous === undefined) {
          // Pierwsze przypisanie do klucza: poprzednia wartość to stan całej tablicy.
          previous = stateOf(name.slice(0, name.length - ev.key.length - 2));
        }
        // Dopisanie wartości po ucieczce cudzysłowów nie zdejmuje wcześniejszego, zwykłego skażenia.
        const keepsPrevious = ev.compound && previous !== 'none' && incoming.endsWith('~') && !previous.endsWith('~');
        origin = keepsPrevious ? previous : incoming !== 'none' ? incoming : ev.compound ? previous : 'none';
        currentKeys.set(name, origin);
      }
      const reset = ev.key === undefined && !ev.compound;
      if (reset) {
        // Nowa wartość całej zmiennej unieważnia znane elementy.
        const prefix = name + '[';
        for (const k of [...currentKeys.keys()]) if (k.startsWith(prefix)) currentKeys.delete(k);
      }
      const list = history.get(name) ?? [];
      list.push({ off: ev.off, origin, reset, compound: ev.compound, path: ev.path });
      history.set(name, list);
    }
  }
  return { history, requests };
}

// Czy ścieżka path zaczyna się od ścieżki prefix, czyli leży w tej samej gałęzi albo głębiej.
function startsWith(path: BranchStep[], prefix: BranchStep[]): boolean {
  if (prefix.length > path.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (prefix[i].construct !== path[i].construct || prefix[i].branch !== path[i].branch) return false;
  }
  return true;
}

// Stan zmiennej w miejscu off i gałęzi path. Idziemy od najnowszego zapisu wstecz. Zapis, który wykonuje się przed
// każdym ujściem i zastępuje wartość, zamyka przeszukiwanie. Zapis w innej gałęzi tej samej konstrukcji pomijamy.
// Zapis w gałęzi, która może się nie wykonać, i zapis dopisujący łączą się z tym, co było wcześniej. Pełny zapis
// w gałęzi nadpisuje wszystko, co ta gałąź zapisała wcześniej, zanim się skończy, więc starsze zapisy z tej samej
// gałęzi (i z gałęzi w niej zagnieżdżonych) nie docierają do ujścia za gałęzią.
function resolveOrigin(list: HistoryEntry[] | undefined, off: number, path: BranchStep[], name: string): Origin {
  if (!list) return 'none';
  let acc: Origin = 'none';
  const overwritten: BranchStep[][] = [];
  for (let i = list.length - 1; i >= 0; i--) {
    const e = list[i];
    if (e.off > off) continue;
    const rel = relate(e.path, path, name);
    if (rel === 'exclusive') continue;
    if (overwritten.some((branch) => startsWith(e.path, branch))) continue;
    acc = joinOrigin(acc, e.origin);
    // Zwykłe skażenie nie zmieni się już od starszych zapisów.
    if (acc !== 'none' && !acc.endsWith('~')) return acc;
    if (!e.reset) continue;
    if (rel === 'dominates') return acc;
    overwritten.push(e.path);
  }
  return acc;
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

  // Korzeń analizowanego pliku.
  get root(): AnyNode {
    return this.program;
  }

  // Oznacza parametr funkcji jako źródło danych (na przykład $atts w callbacku shortcode).
  // Stan policzony wcześniej dla tego zakresu jest unieważniany i liczony od nowa.
  seed(scope: AnyNode, name: string, source: TaintSource, cleanKeys?: string[], site?: AnyNode): void {
    const list = this.seeds.get(scope) ?? [];
    list.push({ name, source, cleanKeys, site });
    this.seeds.set(scope, list);
    this.cache.delete(scope);
  }

  // Czy parametr ma już przypisane źródło danych.
  hasSeed(scope: AnyNode, name: string): boolean {
    return (this.seeds.get(scope) ?? []).some((s) => s.name === name);
  }

  // Zakresy wywołań, które przekazały parametrowi dane użytkownika.
  seedSites(scope: AnyNode, name: string): AnyNode[] {
    const out: AnyNode[] = [];
    for (const s of this.seeds.get(scope) ?? []) if (s.name === name && s.site) out.push(s.site);
    return out;
  }

  private scopeOf(stack: PhpNode[]): AnyNode {
    for (let i = stack.length - 1; i >= 0; i--) {
      if (SCOPE_KINDS.has(stack[i].kind)) return stack[i] as AnyNode;
    }
    return this.program;
  }

  private scoped(scope: AnyNode): Scoped {
    let scoped = this.cache.get(scope);
    if (!scoped) {
      scoped = buildScope(scope, this.spec, this.seeds.get(scope));
      this.cache.set(scope, scoped);
    }
    return scoped;
  }

  // Klucze zmiennej-tablicy, które w danym miejscu mają znane, czyste elementy.
  cleanKeysOf(name: string, stack: PhpNode[], at: unknown): string[] {
    const scoped = this.scoped(this.scopeOf(stack));
    const off = startOffset(at);
    const prefix = name + '[';
    const out: string[] = [];
    for (const k of scoped.history.keys()) {
      if (!k.startsWith(prefix) || !k.endsWith(']')) continue;
      const key = k.slice(prefix.length, -1);
      if (originKeyAt(scoped, name, key, off) === 'none') out.push(key);
    }
    return out;
  }

  // stack to przodkowie ujścia z obchodu AST. expr to wyrażenie do oceny.
  // at wskazuje węzeł, wg którego liczymy pozycję (domyślnie sam expr).
  analyze(expr: unknown, stack: PhpNode[], at?: unknown): TaintHit {
    const scope = this.scopeOf(stack);
    const scoped = this.scoped(scope);
    const off = startOffset(at ?? expr);
    const s = scoped;
    // Przodkowie od zakresu w dół, bo sprawdzenie poza funkcją niczego w niej nie potwierdza.
    const from = stack.lastIndexOf(scope as PhpNode);
    const ancestors = from >= 0 ? stack.slice(from) : stack;
    const guarded = guardedNames(ancestors, off, this.spec.prefixGuards);
    const sinkPath = branchPath(ancestors, off);
    const hit = evalTaint(
      expr,
      this.spec,
      withGuard(
        {
          origin: (name) => resolveOrigin(s.history.get(name), off, sinkPath, name),
          originKey: (name, key) => originKeyAt(s, name, key, off),
          // Zmienna żądania traci ten status po nadpisaniu przez przypisanie.
          isRequestVar: (name) => s.requests.has(name) && !s.history.has(name),
        },
        guarded,
      ),
    );
    // Wartość w całości po ucieczce cudzysłowów nie jest już skażona, o ile nie trafiła poza cudzysłów.
    return hit.escaped ? NONE : hit;
  }
}

// Nazwa skażonej zmiennej z dolarem, do komunikatów reguł.
export function viaText(hit: TaintHit): string {
  return `$${hit.via ?? ''}`;
}

// Opis źródła danych do komunikatów reguł, w języku skanu.
export function originText(hit: TaintHit, t: Translate): string {
  if (hit.source === 'request') return t('origin.request');
  if (hit.source === 'url') return t('origin.url');
  if (hit.source === 'param') return t('origin.param');
  if (hit.source === 'shortcode') return t('origin.shortcode');
  if (hit.source === 'caller') return t('origin.caller');
  return t('origin.user');
}
