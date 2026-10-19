// Przepływ danych przez wywołania funkcji w obrębie jednego pliku.
// Parametr funkcji sam w sobie nie jest danymi użytkownika. Staje się nimi, gdy
// wywołanie z tego samego pliku przekazuje mu dane z superglobala, z żądania REST
// albo z atrybutów shortcode. Łączymy wywołania z definicjami: funkcje po nazwie,
// metody przez $this, self, static i nazwę klasy. Łańcuchy wywołań rozwiązujemy
// kilkoma przebiegami. Wywołania z innych plików są poza zasięgiem, a metody
// wołane na dowolnym obiekcie ($obj->metoda) pomijamy, bo nie znamy jego klasy.
import { walk } from '../parser';
import { arrayItems, asNode, entryKeyName, offsetName, type AnyNode } from './ast-utils';
import { collectDefinitions, enclosingClass, type Definitions } from './callbacks';
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

const sitesByProgram = new WeakMap<AnyNode, CallSite[]>();
const localCalls = new WeakSet<AnyNode>();

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

function callSitesOf(program: PhpNode): CallSite[] {
  const cached = sitesByProgram.get(program);
  if (cached) return cached;
  const defs = collectDefinitions(program);
  const out: CallSite[] = [];
  if (defs.functions.size > 0 || defs.methods.size > 0) {
    walk(program, (node, stack) => {
      const n = node as AnyNode;
      if (n.kind !== 'call') return;
      const callee = resolveCallee(n, stack, defs);
      if (!callee) return;
      localCalls.add(n);
      const args: AnyNode[] = [];
      for (const a of Array.isArray(n.arguments) ? (n.arguments as unknown[]) : []) {
        const arg = asNode(a);
        if (!arg || NOT_POSITIONAL.has(arg.kind ?? '')) break;
        args.push(arg);
      }
      if (args.length > 0) out.push({ callee, stack, args });
    });
  }
  sitesByProgram.set(program, out);
  return out;
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
        taint.seed(site.callee, param.name, hit.source ?? 'caller', cleanKeys(taint, site.args[i], site.stack));
        changed = true;
      }
    }
    if (!changed) break;
  }
}
