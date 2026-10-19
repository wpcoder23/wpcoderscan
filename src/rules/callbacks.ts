// Rozwiązywanie callbacków rejestrowanych w WordPressie (add_action, add_shortcode)
// do definicji funkcji, metod i domknięć z tego samego pliku. Analiza jest
// jednoplikowa: callback zdefiniowany gdzie indziej zostaje nierozwiązany.
import { walk } from '../parser';
import { arrayItems, asNode, offsetName, type AnyNode } from './ast-utils';
import type { PhpNode } from './types';

export function functionName(n: AnyNode): string | undefined {
  const nm = n.name;
  if (typeof nm === 'string') return nm;
  const o = asNode(nm);
  if (o && typeof o.name === 'string') return o.name;
  return undefined;
}

export interface Definitions {
  functions: Map<string, AnyNode>; // nazwa małymi literami
  methods: Map<string, Map<string, AnyNode>>; // klasa małymi literami, potem metoda małymi literami
}

export function collectDefinitions(program: PhpNode): Definitions {
  const defs: Definitions = { functions: new Map(), methods: new Map() };
  walk(program, (node) => {
    const n = node as AnyNode;
    if (n.kind === 'function') {
      const nm = functionName(n);
      if (nm) defs.functions.set(nm.toLowerCase(), n);
    } else if (n.kind === 'class' || n.kind === 'trait') {
      const cname = functionName(n)?.toLowerCase();
      if (!cname) return;
      const methods = defs.methods.get(cname) ?? new Map<string, AnyNode>();
      const members = Array.isArray(n.body) ? (n.body as unknown[]) : [];
      for (const m of members) {
        const mn = asNode(m);
        const mname = mn && mn.kind === 'method' ? functionName(mn) : undefined;
        if (mn && mname) methods.set(mname.toLowerCase(), mn);
      }
      defs.methods.set(cname, methods);
    }
  });
  return defs;
}

// Nazwa klasy otaczającej węzeł (małymi literami), jeśli jest.
export function enclosingClass(stack: PhpNode[]): string | undefined {
  for (let i = stack.length - 1; i >= 0; i--) {
    const k = stack[i].kind;
    if (k === 'class' || k === 'trait') {
      const nm = functionName(stack[i] as AnyNode);
      return nm ? nm.toLowerCase() : undefined;
    }
  }
  return undefined;
}

export interface MethodRef {
  cls: string; // małymi literami
  method: string;
}

// Klasy indeksujemy po krótkiej nazwie, więc '\Ns\Klasa' i 'Ns\Klasa' sprowadzamy do 'klasa'.
export function shortClassName(name: string): string {
  return name.slice(name.lastIndexOf('\\') + 1).toLowerCase();
}

// Rozwiązuje callback zapisany jako tablica albo tekst 'Klasa::metoda'.
export function resolveMethodCallback(cb: AnyNode, stack: PhpNode[]): MethodRef | undefined {
  if (cb.kind === 'string' && typeof cb.value === 'string') {
    const m = /^\\?([A-Za-z_][\w\\]*)::([A-Za-z_]\w*)$/.exec(cb.value);
    return m ? { cls: shortClassName(m[1]), method: m[2] } : undefined;
  }
  if (cb.kind !== 'array') return undefined;
  const items = arrayItems(cb);
  if (items.length !== 2) return undefined;
  const target = asNode(items[0].value);
  const methodNode = asNode(items[1].value);
  if (!target || !methodNode || methodNode.kind !== 'string' || typeof methodNode.value !== 'string') {
    return undefined;
  }
  let cls: string | undefined;
  if (target.kind === 'variable' && target.name === 'this') cls = enclosingClass(stack);
  else if (target.kind === 'magic' && target.value === '__CLASS__') cls = enclosingClass(stack);
  else if (target.kind === 'string' && typeof target.value === 'string') cls = shortClassName(target.value);
  else if (target.kind === 'staticlookup' && offsetName(target.offset) === 'class') {
    const what = asNode(target.what);
    if (what && (what.kind === 'selfreference' || what.kind === 'staticreference')) cls = enclosingClass(stack);
    else if (what && what.kind === 'name' && typeof what.name === 'string') cls = shortClassName(what.name);
  }
  return cls ? { cls, method: methodNode.value } : undefined;
}

// Węzeł funkcji, metody albo domknięcia wskazany przez callback.
export function resolveCallbackNode(cb: AnyNode, stack: PhpNode[], defs: Definitions): AnyNode | undefined {
  if (cb.kind === 'closure' || cb.kind === 'arrowfunc') return cb;
  if (cb.kind === 'string' && typeof cb.value === 'string' && !cb.value.includes('::')) {
    return defs.functions.get(cb.value.replace(/^\\/, '').toLowerCase());
  }
  const ref = resolveMethodCallback(cb, stack);
  return ref ? defs.methods.get(ref.cls)?.get(ref.method.toLowerCase()) : undefined;
}
