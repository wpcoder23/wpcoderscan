// Reguła: unserialize na danych od użytkownika (PHP object injection).
// unserialize na $_GET/$_POST/$_REQUEST/$_COOKIE pozwala wstrzyknąć obiekt
// i wywołać łańcuch gadżetów. To wykrycie strukturalne, pewne. Zmienna zasilona
// takimi danymi daje heurystykę.
import { walk } from '../parser';
import { allowedClassesArg, detectArrayStyle, detectParenStyle } from '../fix/style';
import {
  analyzeDynamic,
  asNode,
  calledName,
  callArgs,
  findEntry,
  nodeStart,
  type AnyNode,
  type DynInfo,
} from './ast-utils';
import { linkCallers } from './callers';
import { guardedAsSerializedString } from './guards';
import { CODE_SPEC, originText, TaintAnalyzer, viaText } from './taint';
import type { Finding, FileContext, Patch, Rule } from './types';

// unserialize i wrapper WordPressa maybe_unserialize niosą to samo ryzyko.
const SINKS = new Set(['unserialize', 'maybe_unserialize']);

// Drugi argument to tablica literalna z allowed_classes => false, czyli obiekty są zablokowane.
function blocksObjects(arg: AnyNode | undefined): boolean {
  if (!arg || arg.kind !== 'array') return false;
  const entry = findEntry(arg, 'allowed_classes');
  const value = asNode(entry?.value);
  return !!value && value.kind === 'boolean' && value.value === false;
}

// allowed_classes ustawione na listę klas. Ryzyko jest mniejsze, ale zostaje, jeśli któraś z klas ma metody magiczne.
function restrictsClasses(arg: AnyNode | undefined): boolean {
  if (!arg || arg.kind !== 'array') return false;
  const entry = findEntry(arg, 'allowed_classes');
  const value = asNode(entry?.value);
  return !!value && value.kind === 'array';
}

// Dopisuje allowed_classes => false przed nawiasem zamykającym jednoargumentowego unserialize().
function buildPatch(ctx: FileContext, node: AnyNode): Patch | undefined {
  const end = (node.loc as { end?: { offset?: number } } | undefined)?.end?.offset;
  if (typeof end !== 'number' || ctx.code[end - 1] !== ')') return undefined;
  // Cofamy się przed białe znaki, żeby wstawić argument zaraz po poprzednim.
  let at = end - 1;
  while (at > 0 && /\s/.test(ctx.code[at - 1])) at--;
  const extra = allowedClassesArg(detectParenStyle(ctx.code), detectArrayStyle(ctx.code));
  return {
    safety: 'complete',
    label: ctx.t('unserialize.patch'),
    edits: [{ start: at, end: at, replacement: `, ${extra}` }],
  };
}

export const unserializeRule: Rule = {
  id: 'wp.unserialize.user_input',
  titleKey: 'rule.wp.unserialize.user_input.title',
  severity: 'high',
  confidence: 'firm',
  cwe: ['CWE-502'],
  asvs: ['5.5.3'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const taint = new TaintAnalyzer(ctx.ast, CODE_SPEC);
    linkCallers(taint, ctx.ast, ctx.code);
    walk(ctx.ast, (node, stack) => {
      const n = node as AnyNode;
      const name = calledName(n);
      if (!name || !SINKS.has(name)) return;

      const args = callArgs(n);
      if (args.length === 0) return;

      const info: DynInfo = { hasVar: false, hasSuperglobal: false };
      analyzeDynamic(args[0], info);
      // Pewne przy bezpośrednim superglobalu (albo filter_input, php://input), heurystyka przy zmiennej.
      const hit = taint.analyze(args[0], stack);
      const direct = info.hasSuperglobal || hit.direct;
      if (!direct && !hit.viaVar) return;
      if (name === 'unserialize' && blocksObjects(args[1])) return; // obiekty już zablokowane
      if (!direct && guardedAsSerializedString(stack as AnyNode[], nodeStart(n)?.offset ?? 0, args[0], ctx.code)) return;
      const patch = name === 'unserialize' && args.length === 1 ? buildPatch(ctx, n) : undefined;
      const limited = name === 'unserialize' && restrictsClasses(args[1]);
      const params = { name, var: viaText(hit), origin: originText(hit, ctx.t) };

      const loc = nodeStart(n);
      findings.push({
        ruleId: unserializeRule.id,
        severity: limited ? 'medium' : 'high',
        confidence: limited || !direct ? 'heuristic' : 'firm',
        message: direct
          ? ctx.t(limited ? 'unserialize.limited' : 'unserialize.full', { name })
          : ctx.t(limited ? 'unserialize.viaVar.limited' : 'unserialize.viaVar', params),
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: unserializeRule.cwe,
        asvs: unserializeRule.asvs,
        fix: ctx.t('unserialize.fix'),
        ...(patch ? { patch } : {}),
      });
    });
    return findings;
  },
};
