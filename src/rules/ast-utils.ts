// Wspólne pomocniki do pracy na AST z php-parser.
// Reguły operują na luźnym typie węzła, bo biblioteka nie daje pełnych typów.
import type { Position } from './types';

export type AnyNode = Record<string, unknown> & { kind?: string };

// Superglobale, czyli bezpośrednie źródła danych użytkownika.
export const SUPERGLOBALS = new Set(['_GET', '_POST', '_REQUEST', '_COOKIE', '_SERVER', '_FILES']);

export function asNode(v: unknown): AnyNode | undefined {
  return v && typeof v === 'object' ? (v as AnyNode) : undefined;
}

// Pozycja startowa węzła, jeśli parser ją zapisał.
export function nodeStart(node: AnyNode | undefined): Position | undefined {
  const loc = node?.loc as { start?: Position } | undefined;
  return loc?.start;
}

// Nazwa metody albo właściwości (offset w propertylookup, klucz w entry).
export function offsetName(offset: unknown): string | undefined {
  const o = asNode(offset);
  if (!o) return undefined;
  if (typeof o.name === 'string') return o.name;
  if (typeof o.value === 'string') return o.value;
  return undefined;
}

// Zejdź po łańcuchu offsetlookup do zmiennej bazowej, np. $_GET['a']['b'] -> $_GET.
export function baseVariable(node: unknown): AnyNode | undefined {
  let b = asNode(node);
  while (b && b.kind === 'offsetlookup') b = asNode(b.what);
  return b;
}

// Czy węzeł to zmienna superglobalna, bezpośrednio albo przez offsetlookup.
export function isSuperglobalAccess(node: unknown): boolean {
  const base = baseVariable(node);
  return !!base && base.kind === 'variable' && SUPERGLOBALS.has(base.name as string);
}

// Nazwa wołanej funkcji, gdy węzeł to proste wywołanie po nazwie.
// Zwracana małymi literami i bez wiodącego ukośnika (\esc_html -> esc_html),
// bo PHP nie rozróżnia wielkości liter w nazwach funkcji.
export function calledName(node: AnyNode): string | undefined {
  if (node.kind !== 'call') return undefined;
  const what = asNode(node.what);
  if (what && what.kind === 'name' && typeof what.name === 'string') {
    return what.name.replace(/^\\/, '').toLowerCase();
  }
  return undefined;
}

// Argumenty wywołania jako lista węzłów.
export function callArgs(node: AnyNode): AnyNode[] {
  const args = Array.isArray(node.arguments) ? (node.arguments as unknown[]) : [];
  return args.map(asNode).filter((a): a is AnyNode => !!a);
}

// Elementy tablicy literalnej jako lista węzłów entry.
export function arrayItems(node: unknown): AnyNode[] {
  const n = asNode(node);
  if (!n || n.kind !== 'array') return [];
  const items = Array.isArray(n.items) ? (n.items as unknown[]) : [];
  return items.map(asNode).filter((e): e is AnyNode => !!e);
}

// Nazwa klucza w entry, gdy klucz jest literałem tekstowym.
export function entryKeyName(entry: AnyNode): string | undefined {
  const k = asNode(entry.key);
  if (k && k.kind === 'string' && typeof k.value === 'string') return k.value;
  return undefined;
}

// Znajdź entry po nazwie klucza w tablicy literalnej.
export function findEntry(arr: AnyNode, keyName: string): AnyNode | undefined {
  return arrayItems(arr).find((e) => entryKeyName(e) === keyName);
}

// Pola węzła pominięte przy rekurencyjnym obchodzie (nie są węzłami AST).
const SKIP_KEYS = new Set(['loc', 'leadingComments', 'trailingComments']);

// Czy w poddrzewie występuje zmienna albo dostęp do superglobala.
// Nazwy funkcji (name) i literały są pomijane, żeby ograniczyć fałszywe alarmy.
export interface DynInfo {
  hasVar: boolean;
  hasSuperglobal: boolean;
}

export function analyzeDynamic(node: unknown, info: DynInfo): void {
  if (Array.isArray(node)) {
    for (const e of node as unknown[]) analyzeDynamic(e, info);
    return;
  }
  const n = asNode(node);
  if (!n) return;
  switch (n.kind) {
    case 'string':
    case 'number':
    case 'boolean':
    case 'nowdoc':
    case 'name':
      return;
    case 'variable':
      info.hasVar = true;
      return;
    case 'offsetlookup':
      if (isSuperglobalAccess(n)) info.hasSuperglobal = true;
      else info.hasVar = true;
      return;
    default:
      for (const k of Object.keys(n)) {
        if (SKIP_KEYS.has(k)) continue;
        analyzeDynamic(n[k], info);
      }
  }
}
