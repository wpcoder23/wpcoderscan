// Integracja parsera PHP (glayzzle/php-parser) i obchód AST.
// Parser jest czysto w JS, więc działa w Node bez runtime PHP. To utrzymuje
// zerowe tarcie w npx i CI. Głębszą analizę taint planujemy dołożyć później.
import PhpParserModule from 'php-parser';
import type { PhpNode } from '../rules/types';

// php-parser 3.x eksportuje konstruktor Engine (module.exports = Engine),
// ale dostarczone typy nie udostępniają konstruktora. Rzutujemy jawnie,
// żeby trzymać typowanie bez łatania cudzych deklaracji.
interface PhpEngine {
  parseCode(buffer: string, filename: string): unknown;
}
type PhpEngineCtor = new (options: {
  parser?: Record<string, unknown>;
  ast?: Record<string, unknown>;
  lexer?: Record<string, unknown>;
}) => PhpEngine;

const Engine = PhpParserModule as unknown as PhpEngineCtor;

// Jedna instancja parsera. Pozycje w AST są potrzebne do zgłaszania linii.
// suppressErrors sprawia, że uszkodzony plik nie wywala całego skanu.
const engine = new Engine({
  parser: { extractDoc: false, suppressErrors: true },
  ast: { withPositions: true },
  lexer: { short_tags: true },
});

export function parsePhp(code: string, filename: string): PhpNode {
  return engine.parseCode(code, filename) as PhpNode;
}

// Rekurencyjny obchód AST. Odwiedza każdy węzeł mający pole kind.
// stack zawiera przodków będących węzłami (do reguł patrzących na kontekst).
export function walk(
  node: unknown,
  visit: (n: PhpNode, stack: PhpNode[]) => void,
  stack: PhpNode[] = [],
): void {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const el of node) walk(el, visit, stack);
    return;
  }
  const n = node as PhpNode;
  const isNode = typeof n.kind === 'string';
  if (isNode) visit(n, stack);
  const nextStack = isNode ? [...stack, n] : stack;
  for (const key of Object.keys(n)) {
    if (key === 'loc' || key === 'leadingComments' || key === 'trailingComments') continue;
    const val = (n as Record<string, unknown>)[key];
    if (val && typeof val === 'object') walk(val, visit, nextStack);
  }
}
