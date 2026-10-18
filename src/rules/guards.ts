// Zmienne sprawdzone przed użyciem. Jeśli kod przed ujściem sprawdza zmienną
// listą dozwolonych wartości (in_array, array_key_exists, isset na tablicy
// z kluczem ze zmiennej), porównaniem z literałem, ctype_* albo zakotwiczonym
// wyrażeniem regularnym, to zmienna nie niesie już dowolnych danych. Skaner
// nie ocenia, czy lista jest poprawna. Uznaje samo sprawdzenie za walidację.
import { asNode, calledName, baseVariable, SUPERGLOBALS, type AnyNode } from './ast-utils';

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

// Nazwy zmiennych w argumencie: sama zmienna albo opakowanie typu sanitize_key( $v ).
function names(arg: unknown, out: Set<string>): void {
  const a = asNode(arg);
  if (!a) return;
  if (a.kind === 'variable' && typeof a.name === 'string') out.add(a.name);
  else if (a.kind === 'call' && Array.isArray(a.arguments) && a.arguments.length === 1) names(a.arguments[0], out);
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
