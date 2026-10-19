// Funkcje obsługujące shortcode. Ich atrybuty wpisuje autor wpisu (rola Contributor),
// więc traktujemy je jako dane użytkownika. Rozpoznajemy je dwoma sposobami:
// rejestracją add_shortcode z tego samego pliku oraz wywołaniem shortcode_atts
// na pierwszym parametrze funkcji. Drugi sposób działa też wtedy, gdy rejestracja
// leży w innym pliku, co jest częste w wtyczkach zbudowanych z klas. Wymóg
// pierwszego parametru odsiewa funkcje pomocnicze, które używają shortcode_atts
// tylko do scalenia wartości domyślnych.
import { walk } from '../parser';
import { asNode, calledName, callArgs, type AnyNode } from './ast-utils';
import { collectDefinitions, resolveCallbackNode } from './callbacks';
import { paramInfos } from './taint';
import type { PhpNode } from './types';

export interface ShortcodeHandler {
  scope: AnyNode; // funkcja, metoda albo domknięcie
  param: string; // parametr z atrybutami, bez dolara
}

const SCOPE_KINDS = new Set(['function', 'closure', 'method', 'arrowfunc']);

function paramNames(scope: AnyNode): string[] {
  return paramInfos(scope).map((p) => p.name);
}

export function findShortcodeHandlers(program: PhpNode, code: string): ShortcodeHandler[] {
  const found: ShortcodeHandler[] = [];
  const seen = new Set<string>();
  const scopeIds = new Map<AnyNode, number>();
  const add = (scope: AnyNode, param: string) => {
    let id = scopeIds.get(scope);
    if (id === undefined) {
      id = scopeIds.size;
      scopeIds.set(scope, id);
    }
    const key = `${id}:${param}`;
    if (seen.has(key)) return;
    seen.add(key);
    found.push({ scope, param });
  };

  const registered = code.includes('add_shortcode');
  const usesAtts = code.includes('shortcode_atts');
  if (!registered && !usesAtts) return found;

  const defs = registered ? collectDefinitions(program) : undefined;
  walk(program, (node, stack) => {
    const n = node as AnyNode;
    const name = calledName(n);
    if (registered && defs && name === 'add_shortcode') {
      const cb = asNode(callArgs(n)[1]);
      const target = cb ? resolveCallbackNode(cb, stack, defs) : undefined;
      const first = target ? paramNames(target)[0] : undefined;
      if (target && first) add(target, first);
      return;
    }
    if (usesAtts && name === 'shortcode_atts') {
      // shortcode_atts( $domyślne, $atts ): drugi argument to atrybuty z shortcode.
      const second = asNode(callArgs(n)[1]);
      const varName = second && second.kind === 'variable' ? second.name : undefined;
      if (typeof varName !== 'string') return;
      for (let i = stack.length - 1; i >= 0; i--) {
        const s = stack[i] as AnyNode;
        if (!SCOPE_KINDS.has(s.kind ?? '')) continue;
        if (paramNames(s)[0] === varName) add(s, varName);
        break;
      }
    }
  });
  return found;
}

// Funkcje zwracające tablicę. Ich wynik nie jest tekstem HTML.
const ARRAY_FUNCS = new Set([
  'shortcode_atts',
  'wp_parse_args',
  'array_merge',
  'array_replace',
  'array_map',
  'array_filter',
  'array_combine',
  'array_slice',
  'array_values',
  'array_keys',
  'array_diff',
  'array_intersect',
  'array_unique',
  'array_reverse',
  'explode',
  'compact',
  'str_split',
  'preg_split',
]);

function isArrayExpr(expr: unknown): boolean {
  const n = asNode(expr);
  if (!n) return false;
  if (n.kind === 'array') return true;
  if (n.kind === 'cast') return String(n.type ?? '').toLowerCase() === 'array';
  if (n.kind === 'call') return ARRAY_FUNCS.has(calledName(n) ?? '');
  return false;
}

// Czy wartość zwracana z funkcji jest tablicą, a nie tekstem. Shortcode oddaje tekst HTML,
// więc funkcja pomocnicza zwracająca sparsowane atrybuty nie jest ujściem XSS. Zmienną
// uznajemy za tablicę, gdy wszystkie jej przypisania w funkcji tworzą tablicę.
export function returnsArray(expr: unknown, scope: AnyNode): boolean {
  const e = asNode(expr);
  if (!e) return false;
  if (isArrayExpr(e)) return true;
  if (e.kind !== 'variable' || typeof e.name !== 'string') return false;
  let arrays = 0;
  let others = 0;
  walk(scope, (node, stack) => {
    const n = node as AnyNode;
    if (n.kind !== 'assign') return;
    if (stack.slice(1).some((a) => SCOPE_KINDS.has(a.kind ?? ''))) return;
    const left = asNode(n.left);
    if (!left || left.kind !== 'variable' || left.name !== e.name) return;
    if (n.operator === '=' && isArrayExpr(n.right)) arrays++;
    else others++;
  });
  return arrays > 0 && others === 0;
}
