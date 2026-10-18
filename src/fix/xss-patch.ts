// Podpowiedź naprawy dla reguły XSS: opakowanie skażonego fragmentu funkcją ucieczki.
// Funkcję dobieramy z kontekstu HTML wokół miejsca wypisania. Poprawka jest
// "pełna" tylko wtedy, gdy kontekst znamy z kodu. Bez znanego kontekstu
// proponujemy esc_html i oznaczamy to jako zmianę do decyzji człowieka.
import { asNode, type AnyNode } from '../rules/ast-utils';
import { calledName } from '../rules/ast-utils';
import type { TaintAnalyzer } from '../rules/taint';
import type { FileContext, Patch, PhpNode, TextEdit } from '../rules/types';
import { detectParenStyle, wrapCall } from './style';
import { chooseEscaper, contextAt } from './xss-context';

const PLACEHOLDER = 'x';

// Funkcje, które tylko przekształcają tekst, więc ucieczkę kładziemy na całym wywołaniu.
const WRAPPABLE_CALLS = new Set([
  'wp_unslash',
  'stripslashes',
  'trim',
  'strtolower',
  'strtoupper',
  'ucfirst',
  'urldecode',
  'rawurldecode',
  'sanitize_text_field',
]);

interface Rendered {
  text: string; // znany tekst wyjścia, niewiadome części zastąpione znakiem zastępczym
  literal: boolean; // czy w tekście jest choć jeden prawdziwy literał
  opaque: boolean; // czy trafił się fragment, którego tekstu nie umiemy poznać
}

const EMPTY: Rendered = { text: '', literal: false, opaque: false };

function join(a: Rendered, b: Rendered): Rendered {
  return { text: a.text + b.text, literal: a.literal || b.literal, opaque: a.opaque || b.opaque };
}

// Tekst, jaki wypisze pojedynczy operand.
function renderOperand(node: AnyNode): Rendered {
  switch (node.kind) {
    case 'string':
      return { text: String(node.value ?? ''), literal: true, opaque: false };
    case 'number':
      return { text: String(node.value ?? ''), literal: true, opaque: false };
    case 'encapsed': {
      // Napis w cudzysłowie z interpolacją. Heredoc i inne odmiany traktujemy jako nieprzejrzyste.
      if (node.type !== 'string') return { text: '', literal: false, opaque: true };
      const parts = Array.isArray(node.value) ? (node.value as unknown[]) : [];
      let out: Rendered = EMPTY;
      for (const p of parts) {
        const expr = asNode(asNode(p)?.expression);
        if (expr && expr.kind === 'string') {
          out = join(out, { text: String(expr.value ?? ''), literal: true, opaque: false });
        } else {
          out = join(out, { text: PLACEHOLDER, literal: false, opaque: false });
        }
      }
      return out;
    }
    case 'nowdoc':
      return { text: '', literal: false, opaque: true };
    default:
      return { text: PLACEHOLDER, literal: false, opaque: false };
  }
}

// Rozbija łańcuch konkatenacji na operandy w kolejności wypisania.
export function flattenConcat(expr: AnyNode): AnyNode[] {
  if (expr.kind === 'bin' && expr.type === '.') {
    const left = asNode(expr.left);
    const right = asNode(expr.right);
    if (left && right) return [...flattenConcat(left), ...flattenConcat(right)];
  }
  return [expr];
}

function renderChain(ops: AnyNode[]): Rendered {
  return ops.reduce<Rendered>((acc, op) => join(acc, renderOperand(op)), EMPTY);
}

// Tekst wypisywany przez instrukcję z listy rodzeństwa, czyli to, co stoi przed naszym echo.
function renderStatement(node: AnyNode): Rendered {
  if (node.kind === 'inline') {
    return { text: String(node.value ?? ''), literal: true, opaque: false };
  }
  if (node.kind === 'echo') {
    const exprs = Array.isArray(node.expressions) ? (node.expressions as unknown[]) : [];
    return exprs.reduce<Rendered>((acc, e) => {
      const n = asNode(e);
      return n ? join(acc, renderChain(flattenConcat(n))) : acc;
    }, EMPTY);
  }
  if (node.kind === 'expressionstatement') {
    const ex = asNode(node.expression);
    if (ex && ex.kind === 'print') {
      const inner = asNode(ex.expression);
      return inner ? renderChain(flattenConcat(inner)) : EMPTY;
    }
  }
  return EMPTY;
}

function locateStatement(
  stmt: AnyNode,
  stack: PhpNode[],
): { list: AnyNode[]; index: number } | undefined {
  let cur = stmt;
  let depth = stack.length - 1;
  const top = asNode(stack[depth]);
  if (stmt.kind === 'print' && top?.kind === 'expressionstatement' && top.expression === stmt) {
    cur = top;
    depth -= 1;
  }
  const parent = asNode(stack[depth]);
  const list = parent && Array.isArray(parent.children) ? (parent.children as AnyNode[]) : undefined;
  if (!list) return undefined;
  const index = list.indexOf(cur);
  return index >= 0 ? { list, index } : undefined;
}

// Granice, za którymi tekst HTML sprzed deklaracji nie ma związku z jej ciałem.
const SCOPE_BOUNDARY = new Set(['function', 'method', 'closure', 'arrowfunc', 'class', 'trait', 'interface']);

// Cały tekst wypisany przed instrukcją, w kolejności pliku: rodzeństwo na każdym
// poziomie zagnieżdżenia aż do granicy funkcji. Dzięki temu znacznik otwarty
// przed blokiem if albo pętlą jest widoczny dla echo w środku bloku.
function precedingOutput(stmt: AnyNode, stack: PhpNode[]): Rendered {
  let cur: AnyNode = stmt;
  const levels: Rendered[] = [];
  for (let d = stack.length - 1; d >= 0; d--) {
    const anc = asNode(stack[d]);
    if (!anc) break;
    const list = Array.isArray(anc.children) ? (anc.children as AnyNode[]) : undefined;
    if (list) {
      const idx = list.indexOf(cur);
      if (idx >= 0) {
        let level = EMPTY;
        for (let i = 0; i < idx; i++) level = join(level, renderStatement(list[i]));
        levels.push(level);
      }
    }
    if (anc.kind && SCOPE_BOUNDARY.has(anc.kind)) break;
    cur = anc;
  }
  return levels.reverse().reduce<Rendered>((acc, l) => join(acc, l), EMPTY);
}

function span(node: AnyNode): { start: number; end: number } | undefined {
  const loc = node.loc as { start?: { offset?: number }; end?: { offset?: number } } | undefined;
  const start = loc?.start?.offset;
  const end = loc?.end?.offset;
  return typeof start === 'number' && typeof end === 'number' && end > start ? { start, end } : undefined;
}

// Czy operand da się bezpiecznie opakować w całości, bez zmiany znaczenia reszty wyrażenia.
function isSimpleOperand(node: AnyNode): boolean {
  switch (node.kind) {
    case 'variable':
    case 'offsetlookup':
    case 'propertylookup':
    case 'staticlookup':
      return true;
    case 'call': {
      const name = calledName(node);
      if (!name || !WRAPPABLE_CALLS.has(name)) return false;
      const args = Array.isArray(node.arguments) ? (node.arguments as unknown[]) : [];
      return args.length >= 1 && args.every((a) => {
        const n = asNode(a);
        return !!n && (isSimpleOperand(n) || isPlainLiteral(n));
      });
    }
    case 'bin':
      if (node.type !== '??') return false;
      return isBranch(asNode(node.left)) && isBranch(asNode(node.right));
    case 'retif':
      return isBranch(asNode(node.trueExpr) ?? asNode(node.test)) && isBranch(asNode(node.falseExpr));
    default:
      return false;
  }
}

// Literał bez znaczników, który po ucieczce wygląda tak samo.
function isPlainLiteral(node: AnyNode): boolean {
  if (node.kind === 'number' || node.kind === 'boolean' || node.kind === 'nullkeyword') return true;
  if (node.kind === 'string') return !/[<>&"']/.test(String(node.value ?? ''));
  return false;
}

function isBranch(node: AnyNode | undefined): boolean {
  return !!node && (isSimpleOperand(node) || isPlainLiteral(node));
}

export interface XssPatchInput {
  ctx: FileContext;
  taint: TaintAnalyzer;
  stmt: AnyNode; // echo albo print
  expr: AnyNode; // wyrażenie zgłoszone przez regułę
  exprIndex: number; // numer wyrażenia w echo a, b, c
  stack: PhpNode[]; // przodkowie instrukcji
}

export function buildXssPatch(input: XssPatchInput): Patch | undefined {
  const { ctx, taint, stmt, expr, exprIndex, stack } = input;
  const ops = flattenConcat(expr);

  const tainted: number[] = [];
  for (let i = 0; i < ops.length; i++) {
    const hit = taint.analyze(ops[i], stack);
    if (hit.direct || hit.viaVar) tainted.push(i);
  }
  if (tainted.length === 0) return undefined;
  if (tainted.some((i) => !isSimpleOperand(ops[i]) || !span(ops[i]))) return undefined;

  // Tekst sprzed instrukcji (rodzeństwo w tej samej liście) i sąsiednie wyrażenia echo.
  const where = locateStatement(stmt, stack);
  let before: Rendered = precedingOutput(stmt, stack);
  let afterChar = '';
  if (where) {
    const next = where.list[where.index + 1];
    if (next && next.kind === 'inline') afterChar = String(next.value ?? '').charAt(0);
  }

  const siblingsExprs =
    stmt.kind === 'echo' && Array.isArray(stmt.expressions) ? (stmt.expressions as unknown[]) : [expr];
  for (let i = 0; i < exprIndex; i++) {
    const n = asNode(siblingsExprs[i]);
    if (n) before = join(before, renderChain(flattenConcat(n)));
  }
  // Pierwszy znak tekstu po całym wyrażeniu: następne wyrażenie echo albo inline po instrukcji.
  const nextExpr = asNode(siblingsExprs[exprIndex + 1]);
  const tailChar = nextExpr ? renderChain(flattenConcat(nextExpr)).text.charAt(0) : afterChar;

  const paren = detectParenStyle(ctx.code);
  const edits: TextEdit[] = [];
  let manual = false;
  let used: string[] = [];

  for (const k of tainted) {
    const prefix = join(before, renderChain(ops.slice(0, k)));
    if (prefix.opaque) return undefined;

    // Pierwszy znak po tym operandzie: dalszy literał w łańcuchu albo koniec wyrażenia.
    let nextChar = '';
    let reachedEnd = true;
    for (let j = k + 1; j < ops.length; j++) {
      const r = renderOperand(ops[j]);
      if (r.opaque || !r.literal) {
        reachedEnd = false;
        break;
      }
      if (r.text.length > 0) {
        nextChar = r.text.charAt(0);
        reachedEnd = false;
        break;
      }
    }
    if (reachedEnd) nextChar = tailChar;

    const escaper = chooseEscaper(contextAt(prefix.text), nextChar);
    if (!escaper) return undefined;
    if (!prefix.literal) manual = true;

    const range = span(ops[k]);
    if (!range) return undefined;
    const { open, close } = wrapCall(escaper, paren);
    edits.push({ start: range.start, end: range.start, replacement: open });
    edits.push({ start: range.end, end: range.end, replacement: close });
    used.push(escaper);
  }

  used = [...new Set(used)];
  const names = used.map((u) => `${u}()`).join(' i ');
  return {
    safety: manual ? 'manual' : 'complete',
    label: manual
      ? `Opakuj dane w ${names}. Kontekst HTML nie wynika z kodu, więc sprawdź, czy to właściwa funkcja.`
      : `Opakuj dane w ${names}.`,
    edits,
  };
}
