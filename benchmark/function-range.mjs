// Zakres linii najmniejszej funkcji, metody albo domknięcia, która obejmuje daną linię pliku PHP.
// Służy do metryki "func" w pomiarach recall. Plik jest tylko parsowany, nic z niego nie jest uruchamiane.
import { readFileSync } from 'node:fs';
import PhpParser from 'php-parser';

const FUNCTION_KINDS = new Set(['function', 'method', 'closure', 'arrowfunc']);

const engine = new PhpParser({
  parser: { extractDoc: false, suppressErrors: true },
  ast: { withPositions: true },
  lexer: { short_tags: true },
});

const cache = new Map();

function collect(node, out) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const child of node) collect(child, out);
    return;
  }
  if (FUNCTION_KINDS.has(node.kind) && node.loc) out.push([node.loc.start.line, node.loc.end.line]);
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'leadingComments' || key === 'trailingComments') continue;
    const value = node[key];
    if (value && typeof value === 'object') collect(value, out);
  }
}

function rangesOf(file) {
  let list = cache.get(file);
  if (list) return list;
  list = [];
  try {
    collect(engine.parseCode(readFileSync(file, 'utf8'), file), list);
  } catch {
    // Plik, którego nie da się sparsować, nie ma funkcji do wskazania.
  }
  cache.set(file, list);
  return list;
}

// Zwraca [pierwsza, ostatnia] linia najmniejszej funkcji obejmującej linię albo undefined, gdy linia leży poza funkcjami.
export function enclosingRange(file, line) {
  let best;
  for (const range of rangesOf(file)) {
    if (range[0] <= line && line <= range[1] && (!best || range[1] - range[0] < best[1] - best[0])) best = range;
  }
  return best;
}
