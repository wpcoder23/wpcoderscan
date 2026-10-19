// Przepływ danych przez wywołania funkcji w obrębie jednego pliku.
// Parametr funkcji sam w sobie nie jest danymi użytkownika. Staje się nimi, gdy
// wywołanie z tego samego pliku przekazuje mu dane z superglobala, z żądania REST
// albo z atrybutów shortcode. Łączymy wywołania z definicjami: funkcje po nazwie,
// metody przez $this, self, static i nazwę klasy. Łańcuchy wywołań rozwiązujemy
// kilkoma przebiegami. Wywołania z innych plików są poza zasięgiem, a metody
// wołane na dowolnym obiekcie ($obj->metoda) pomijamy, bo nie znamy jego klasy.
import { walk } from '../parser';
import { arrayItems, asNode, entryKeyName, offsetName, type AnyNode } from './ast-utils';
import { collectDefinitions, enclosingClass, functionName, type Definitions } from './callbacks';
import { paramInfos, type TaintAnalyzer } from './taint';
import type { PhpNode } from './types';

interface CallSite {
  callee: AnyNode; // definicja funkcji albo metody z tego samego pliku
  stack: PhpNode[]; // przodkowie wywołania
  args: AnyNode[]; // argumenty pozycyjne, bez nazwanych i rozwiniętych
}

// Bez żadnego źródła danych w pliku analiza niczego nie znajdzie, więc pomijamy pracę.
const SOURCE_HINT =
  /\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|filter_input|php:\/\/input|WP_REST_Request|\$request\b|get_(?:param|params|json_params|body_params|query_params|url_params|body|file_params)\b|add_query_arg|remove_query_arg|shortcode_atts|add_shortcode/;

const MAX_PASSES = 6;
const NOT_POSITIONAL = new Set(['namedargument', 'variadic']);

// Wywołania rozpoznane w pliku oraz liczniki nazw. Liczniki mówią, czy każde wywołanie danej nazwy udało się
// połączyć z definicją i czy nazwa nie pojawia się też jako tekst (callback zapisany jako 'nazwa').
interface CallIndex {
  sites: CallSite[];
  calls: Map<string, number>; // wywołania wg nazwy funkcji albo metody, na dowolnym odbiorcy
  mentions: Map<string, number>; // teksty równe nazwie: 'nazwa', array( $this, 'nazwa' ), 'Klasa::nazwa'
}

const indexByProgram = new WeakMap<AnyNode, CallIndex>();
const localCalls = new WeakSet<AnyNode>();
const NAME_TEXT = /^\\?[A-Za-z_][\w\\]*(?:::[A-Za-z_]\w*)?$/;

const SCOPE_KINDS = new Set(['function', 'closure', 'method', 'arrowfunc']);

// Funkcja albo metoda otaczająca wywołanie. Poza funkcją zakresem jest cały program.
function scopeOf(stack: PhpNode[], program: PhpNode): AnyNode {
  for (let i = stack.length - 1; i >= 0; i--) {
    if (SCOPE_KINDS.has(stack[i].kind)) return stack[i] as AnyNode;
  }
  return program as AnyNode;
}

// Nazwa bez przestrzeni nazw, małymi literami. Definicje w pliku są zapisane bez niej.
function shortName(name: string): string {
  const i = name.lastIndexOf('\\');
  return (i >= 0 ? name.slice(i + 1) : name).toLowerCase();
}

function resolveCallee(call: AnyNode, stack: PhpNode[], defs: Definitions): AnyNode | undefined {
  const what = asNode(call.what);
  if (!what) return undefined;
  if (what.kind === 'name' && typeof what.name === 'string') return defs.functions.get(shortName(what.name));

  const offset = asNode(what.offset);
  if (!offset || offset.kind !== 'identifier') return undefined;
  const method = offsetName(offset);
  if (!method) return undefined;
  const target = asNode(what.what);
  if (!target) return undefined;

  let cls: string | undefined;
  if (what.kind === 'propertylookup') {
    if (target.kind === 'variable' && target.name === 'this') cls = enclosingClass(stack);
  } else if (what.kind === 'staticlookup') {
    if (target.kind === 'selfreference' || target.kind === 'staticreference') cls = enclosingClass(stack);
    else if (target.kind === 'name' && typeof target.name === 'string') cls = shortName(target.name);
  }
  return cls ? defs.methods.get(cls)?.get(method.toLowerCase()) : undefined;
}

// Nazwa wołanej funkcji albo metody małymi literami, bez względu na odbiorcę.
function calledLabel(call: AnyNode): string | undefined {
  const what = asNode(call.what);
  if (!what) return undefined;
  if (what.kind === 'name' && typeof what.name === 'string') return shortName(what.name);
  if (what.kind !== 'propertylookup' && what.kind !== 'staticlookup') return undefined;
  const offset = asNode(what.offset);
  if (!offset || offset.kind !== 'identifier') return undefined;
  return offsetName(offset)?.toLowerCase();
}

function bump(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}

// Tekst jako indeks tablicy ($request['nazwa']) wskazuje element, a nie funkcję.
function isIndexText(node: AnyNode, stack: PhpNode[]): boolean {
  const parent = stack[stack.length - 1] as AnyNode | undefined;
  return !!parent && parent.kind === 'offsetlookup' && parent.offset === node;
}

function indexOf(program: PhpNode): CallIndex {
  const cached = indexByProgram.get(program);
  if (cached) return cached;
  const defs = collectDefinitions(program);
  const resolvable = defs.functions.size > 0 || defs.methods.size > 0;
  const index: CallIndex = { sites: [], calls: new Map(), mentions: new Map() };
  walk(program, (node, stack) => {
    const n = node as AnyNode;
    if (n.kind === 'string' && typeof n.value === 'string' && NAME_TEXT.test(n.value)) {
      if (!isIndexText(n, stack)) {
        bump(index.mentions, shortName(n.value.includes('::') ? n.value.slice(n.value.lastIndexOf('::') + 2) : n.value));
      }
      return;
    }
    if (n.kind !== 'call') return;
    const label = calledLabel(n);
    if (label) bump(index.calls, label);
    if (!resolvable) return;
    const callee = resolveCallee(n, stack, defs);
    if (!callee) return;
    localCalls.add(n);
    const args: AnyNode[] = [];
    for (const a of Array.isArray(n.arguments) ? (n.arguments as unknown[]) : []) {
      const arg = asNode(a);
      if (!arg || NOT_POSITIONAL.has(arg.kind ?? '')) break;
      args.push(arg);
    }
    index.sites.push({ callee, stack, args });
  });
  indexByProgram.set(program, index);
  return index;
}

function callSitesOf(program: PhpNode): CallSite[] {
  return indexOf(program).sites;
}

// Zakresy (funkcje, metody, domknięcia), z których plik woła daną funkcję albo metodę. Wynik jest pełny tylko
// wtedy, gdy każde wywołanie tej nazwy w pliku zostało połączone z definicją i nazwa nie występuje jako tekst
// (callback hooka, array( $this, 'nazwa' )). Inaczej funkcja ma wejście, którego nie widzimy, i wynik to undefined.
// Wywołania z innych plików są poza zasięgiem, jak w całej analizie.
export function callerScopes(program: PhpNode, fn: AnyNode): AnyNode[] | undefined {
  const name = functionName(fn)?.toLowerCase();
  if (!name) return undefined;
  const index = indexOf(program);
  if ((index.mentions.get(name) ?? 0) > 0) return undefined;
  const scopes = index.sites.filter((site) => site.callee === fn).map((site) => scopeOf(site.stack, program));
  if (scopes.length === 0 || scopes.length !== (index.calls.get(name) ?? 0)) return undefined;
  return scopes;
}

// Czy wywołanie prowadzi do funkcji albo metody zdefiniowanej w tym samym pliku. Takie ujście
// obsługuje śledzenie wywołań, więc osobne zgłoszenie przy wywołaniu byłoby duplikatem.
export function isLocalCall(program: PhpNode, call: AnyNode): boolean {
  callSitesOf(program);
  return localCalls.has(call);
}

// Klucze argumentu-tablicy, które są czyste już w wywołaniu: wartości literalne w tablicy
// podanej wprost albo elementy zmiennej oczyszczone wcześniej. Wywołana funkcja dostaje
// je jako znane, więc na przykład ścieżka szablonu ze stałej nie jest uznana za skażoną.
function cleanKeys(taint: TaintAnalyzer, arg: AnyNode, stack: PhpNode[]): string[] {
  if (arg.kind === 'array') {
    const out: string[] = [];
    for (const entry of arrayItems(arg)) {
      const key = entryKeyName(entry);
      if (key === undefined) continue;
      const hit = taint.analyze(entry.value, stack);
      if (!hit.direct && !hit.viaVar) out.push(key);
    }
    return out;
  }
  if (arg.kind === 'variable' && typeof arg.name === 'string') return taint.cleanKeysOf(arg.name, stack, arg);
  return [];
}

// Zasiewa parametry funkcji z pliku tymi danymi, które trafiają do nich z wywołań
// w tym samym pliku. Analizator ocenia argumenty wg własnych reguł czyszczenia,
// więc wywołanie z absint( $_GET['id'] ) niczego nie zasiewa.
export function linkCallers(taint: TaintAnalyzer, program: PhpNode, code: string): void {
  if (!SOURCE_HINT.test(code)) return;
  const sites = callSitesOf(program);
  if (sites.length === 0) return;

  for (let pass = 0; pass < MAX_PASSES; pass++) {
    let changed = false;
    for (const site of sites) {
      const params = paramInfos(site.callee);
      const count = Math.min(site.args.length, params.length);
      for (let i = 0; i < count; i++) {
        const param = params[i];
        if (param.scalar || taint.hasSeed(site.callee, param.name)) continue;
        const hit = taint.analyze(site.args[i], site.stack);
        if ((!hit.direct && !hit.viaVar) || hit.source === 'param') continue;
        taint.seed(site.callee, param.name, hit.source ?? 'caller', cleanKeys(taint, site.args[i], site.stack), scopeOf(site.stack, program));
        changed = true;
      }
    }
    if (!changed) break;
  }
}
