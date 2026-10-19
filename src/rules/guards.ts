// Zmienne sprawdzone przed użyciem. Jeśli kod przed ujściem sprawdza zmienną
// listą dozwolonych wartości (in_array, array_key_exists, isset na tablicy
// z kluczem ze zmiennej), porównaniem z literałem, ctype_* albo zakotwiczonym
// wyrażeniem regularnym, to zmienna nie niesie już dowolnych danych. Skaner
// nie ocenia, czy lista jest poprawna. Uznaje samo sprawdzenie za walidację.
import { asNode, calledName, baseVariable, offsetName, SUPERGLOBALS, type AnyNode } from './ast-utils';

const MEMBERSHIP = new Set(['in_array', 'array_key_exists', 'key_exists']);
const TYPE_CHECKS = new Set(['ctype_digit', 'ctype_alnum', 'ctype_alpha', 'is_numeric', 'is_int']);
const EXITING_CALLS = new Set(['wp_die', 'wp_send_json', 'wp_send_json_error', 'wp_send_json_success']);
const EXIT_KINDS = new Set(['return', 'exit', 'throw', 'continue', 'break']);

function range(node: unknown): [number, number] | undefined {
  const loc = asNode(node)?.loc as { start?: { offset?: number }; end?: { offset?: number } } | undefined;
  const s = loc?.start?.offset;
  const e = loc?.end?.offset;
  return typeof s === 'number' && typeof e === 'number' ? [s, e] : undefined;
}

function contains(node: unknown, off: number): boolean {
  const r = range(node);
  return !!r && off >= r[0] && off < r[1];
}

// Klucz tablicy będący literałem tekstowym albo liczbowym.
function literalKeyOf(node: unknown): string | undefined {
  const n = asNode(node);
  if (!n || typeof n.value !== 'string') return undefined;
  return n.kind === 'string' || n.kind === 'number' ? n.value : undefined;
}

// Element tablicy o samych literalnych kluczach: $a['x'][0]['y'] to podstawa a i ścieżka x][0][y,
// więc nazwa[ścieżka] daje a[x][0][y]. Dla jednego klucza zapis jest taki sam jak dla pojedynczego elementu.
export function elementPath(node: unknown): { base: string; path: string } | undefined {
  const keys: string[] = [];
  let cur = asNode(node);
  while (cur && cur.kind === 'offsetlookup') {
    const key = literalKeyOf(cur.offset);
    if (key === undefined) return undefined;
    keys.unshift(key);
    cur = asNode(cur.what);
  }
  if (!cur || cur.kind !== 'variable' || typeof cur.name !== 'string' || keys.length === 0) return undefined;
  return { base: cur.name, path: keys.join('][') };
}

// Nazwy zmiennych w argumencie: sama zmienna, element tablicy o literalnych kluczach
// (zapisany jako nazwa[klucz] albo nazwa[a][b]) albo opakowanie typu sanitize_key( $v ).
function names(arg: unknown, out: Set<string>): void {
  const a = asNode(arg);
  if (!a) return;
  if (a.kind === 'variable' && typeof a.name === 'string') out.add(a.name);
  else if (a.kind === 'offsetlookup') {
    const el = elementPath(a);
    if (el) out.add(el.base + '[' + el.path + ']');
  } else if (a.kind === 'call' && Array.isArray(a.arguments) && a.arguments.length === 1) names(a.arguments[0], out);
}

function literal(node: unknown): boolean {
  const n = asNode(node);
  return !!n && (n.kind === 'string' || n.kind === 'number');
}

// Zakotwiczone na obu końcach wyrażenie (/^[a-z-]+$/) działa jak lista dozwolonych znaków.
// Wzorce z dowolnym ciągiem (.* albo .+) niczego nie ograniczają.
function anchored(src: string): boolean {
  const open = src[0];
  if (!open || /[\w\s\\]/.test(open)) return false;
  const close = open === '(' ? ')' : open === '{' ? '}' : open === '[' ? ']' : open;
  const end = src.lastIndexOf(close);
  if (end <= 1) return false;
  const body = src.slice(1, end);
  return body.startsWith('^') && /(?<!\\)\$$/.test(body) && !/(?<!\\)\.[*+]/.test(body);
}

// Nazwa wołanej funkcji albo metody ($obj->nazwa(), Klasa::nazwa()) w zapisie snake_case: isValidTable to is_valid_table.
function calleeLabel(call: AnyNode): string {
  const fn = calledName(call);
  if (fn) return fn;
  const what = asNode(call.what);
  if (what && (what.kind === 'propertylookup' || what.kind === 'staticlookup')) {
    return (offsetName(what.offset) ?? '').replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
  }
  return '';
}

// Walidator z nazwy: is_valid_table( $t ), $this->is_allowed_column( $c ), validate_orderby( $o ).
// Autor sprawdza nim wartość przed użyciem, więc uznajemy ją za zwalidowaną. Pomijamy walidatory,
// które przepuszczają cudzysłów albo średnik (adres e-mail, URL, data, token).
const VALIDATOR_NAME = /^(?:is_|has_)?(?:valid|allowed|allowlisted|whitelisted|safe|permitted|supported)|^validate_|_is_valid$|_is_allowed$/;
const WEAK_VALIDATOR =
  /email|(?:^|_)(?:url|uri|date|time|datetime|ip|ipv4|ipv6|token|nonce|json|xml|phone|password|captcha|licen[sc]e)s?(?:_|$)/;

function isValidatorName(name: string): boolean {
  return VALIDATOR_NAME.test(name) && !WEAK_VALIDATOR.test(name);
}

// Wzorzec, który pasuje do jednego znaku spoza dozwolonego zbioru: /[^a-z0-9_]/ albo /\W/.
// Test if ( preg_match( ten_wzorzec, $v ) ) { wyjście } zostawia w $v tylko dozwolone znaki.
function rejectsOtherChars(src: string): boolean {
  const open = src[0];
  if (!open || /[\w\s\\]/.test(open)) return false;
  const close = open === '(' ? ')' : open === '{' ? '}' : open === '[' ? ']' : open;
  const end = src.lastIndexOf(close);
  if (end <= 1) return false;
  return /^(?:\[\^(?:[^\]\\]|\\.)+\]|\\W|\\D)\+?$/.test(src.slice(1, end));
}

// Zmienne, które ten warunek potwierdza, gdy jest prawdziwy.
export function confirmedBy(test: unknown, out = new Set<string>()): Set<string> {
  const t = asNode(test);
  if (!t) return out;
  if (t.kind === 'bin') {
    if (t.type === '&&' || t.type === 'and') {
      confirmedBy(t.left, out);
      confirmedBy(t.right, out);
    } else if (t.type === '==' || t.type === '===') {
      if (literal(t.right)) names(t.left, out);
      else if (literal(t.left)) names(t.right, out);
    }
    return out;
  }
  if (t.kind === 'call') {
    const fn = calledName(t) ?? '';
    const args = Array.isArray(t.arguments) ? (t.arguments as unknown[]) : [];
    if (MEMBERSHIP.has(fn) || TYPE_CHECKS.has(fn)) names(args[0], out);
    else if (fn === 'preg_match') {
      const re = asNode(args[0]);
      const src = re?.kind === 'string' && typeof re.value === 'string' ? re.value : '';
      if (anchored(src)) names(args[1], out);
    } else if (isValidatorName(calleeLabel(t))) {
      for (const a of args) names(a, out);
    }
    return out;
  }
  if (t.kind === 'isset') {
    const vars = Array.isArray(t.variables) ? (t.variables as unknown[]) : [];
    for (const v of vars) {
      const lookup = asNode(v);
      if (!lookup || lookup.kind !== 'offsetlookup') continue;
      const base = baseVariable(lookup.what);
      // Klucz z superglobala nic nie potwierdza.
      if (base && base.kind === 'variable' && SUPERGLOBALS.has(base.name as string)) continue;
      names(lookup.offset, out);
    }
  }
  return out;
}

// Zmienne potwierdzone, gdy warunek jest fałszywy: !A albo A || B po negacjach.
export function confirmedByNegation(test: unknown, out = new Set<string>()): Set<string> {
  const t = asNode(test);
  if (!t) return out;
  if (t.kind === 'unary' && t.type === '!') return confirmedBy(t.what, out);
  if (t.kind === 'bin' && (t.type === '||' || t.type === 'or')) {
    confirmedByNegation(t.left, out);
    confirmedByNegation(t.right, out);
  } else if (t.kind === 'call' && calledName(t) === 'preg_match') {
    // Gdy wzorzec odrzucający obce znaki nie pasuje, wartość ma tylko dozwolone znaki.
    const args = Array.isArray(t.arguments) ? (t.arguments as unknown[]) : [];
    const re = asNode(args[0]);
    const src = re?.kind === 'string' && typeof re.value === 'string' ? re.value : '';
    if (rejectsOtherChars(src)) names(args[1], out);
  }
  return out;
}

function exits(body: unknown): boolean {
  const b = asNode(body);
  if (!b) return false;
  const last = b.kind === 'block' && Array.isArray(b.children) ? asNode(b.children[b.children.length - 1]) : b;
  if (!last) return false;
  if (EXIT_KINDS.has(last.kind as string)) return true;
  if (last.kind === 'expressionstatement') {
    const expr = asNode(last.expression);
    return !!expr && expr.kind === 'call' && EXITING_CALLS.has(calledName(expr) ?? '');
  }
  return false;
}

// Zmienne sprawdzone przed miejscem o przesunięciu off, na podstawie przodków ujścia.
export function guardedNames(ancestors: readonly AnyNode[], off: number): Set<string> {
  const out = new Set<string>();
  for (const a of ancestors) {
    const n = a as AnyNode;
    if (n.kind === 'if') {
      if (contains(n.body, off)) confirmedBy(n.test, out);
      else if (n.alternate && contains(n.alternate, off)) confirmedByNegation(n.test, out);
    } else if (n.kind === 'retif') {
      if (contains(n.trueExpr, off)) confirmedBy(n.test, out);
      else if (contains(n.falseExpr, off)) confirmedByNegation(n.test, out);
    } else if ((n.kind === 'block' || n.kind === 'program') && Array.isArray(n.children)) {
      for (const child of n.children as unknown[]) {
        const c = asNode(child);
        const r = range(c);
        if (!c || !r || r[0] >= off) break;
        // Wczesne wyjście: if ( ! in_array( $v, ... ) ) { return; } potwierdza $v dla dalszego kodu.
        if (c.kind === 'if' && !c.alternate && r[1] <= off && exits(c.body)) confirmedByNegation(c.test, out);
      }
    }
  }
  return out;
}

// Tekst węzła bez białych znaków, do porównania dwóch zapisów tego samego wyrażenia.
function sourceOf(node: unknown, code: string): string | undefined {
  const r = range(node);
  return r ? code.slice(r[0], r[1]).replace(/\s+/g, '') : undefined;
}

function checksSerializedString(test: unknown, want: string, code: string): boolean {
  const t = asNode(test);
  if (!t) return false;
  if (t.kind === 'bin' && (t.type === '&&' || t.type === 'and')) {
    return checksSerializedString(t.left, want, code) || checksSerializedString(t.right, want, code);
  }
  if (t.kind !== 'call' || calledName(t) !== 'is_serialized_string') return false;
  const args = Array.isArray(t.arguments) ? (t.arguments as unknown[]) : [];
  return sourceOf(args[0], code) === want;
}

// Wywołanie unserialize( $x ) wewnątrz if ( is_serialized_string( $x ) ). Taki tekst zawiera
// wyłącznie zserializowany napis, więc odczyt nie utworzy żadnego obiektu. Dotyczy tylko
// unserialize, dla XSS i SQL sprawdzenie niczego nie potwierdza.
export function guardedAsSerializedString(
  ancestors: readonly AnyNode[],
  off: number,
  arg: AnyNode,
  code: string,
): boolean {
  const want = sourceOf(arg, code);
  if (!want) return false;
  for (const a of ancestors) {
    const n = a as AnyNode;
    if (n.kind === 'if' && contains(n.body, off) && checksSerializedString(n.test, want, code)) return true;
    if (n.kind === 'retif' && contains(n.trueExpr, off) && checksSerializedString(n.test, want, code)) return true;
  }
  return false;
}
