// Reguła: nazwa opcji WordPressa pochodząca od użytkownika (dowolna aktualizacja opcji).
// update_option( $_POST['name'], $_POST['value'] ) pozwala zmienić default_role albo users_can_register
// i przejąć witrynę. Stały przedrostek w nazwie (update_option( 'wtyczka_' . $klucz, ... )) ogranicza zakres do
// opcji wtyczki, także gdy przedrostek stoi w zmiennej, więc go nie zgłaszamy. Funkcja za bramką na uprawnienie
// administratora (własna, w funkcji, która ją woła, albo wymagana przy rejestracji strony menu czy trasy REST)
// nie jest zgłaszana. Wartość podana na stałe (update_option( $nazwa, true )) ogranicza skutek, więc wynik jest
// o stopień niższy. Stały koniec nazwy (update_option( $_POST['x'] . '_notice_ignore', ... )) ogranicza zakres do
// opcji z takim końcem, więc wynik jest słabą wskazówką.
import { walk } from '../parser';
import { calledName, callArgs, nodeStart, type AnyNode } from './ast-utils';
import { linkCallers } from './callers';
import { adminGated, downgradeGated, enclosingScope, flattenValue, gradeHit, leadingTaint, lowerGrade } from './sink-utils';
import { KEY_SPEC, TaintAnalyzer } from './taint';
import type { Finding, FileContext, PhpNode, Rule } from './types';

const OPTION_WRITERS = new Set(['update_option', 'add_option', 'update_site_option', 'add_site_option', 'update_network_option', 'add_network_option']);
const OPTION_DELETERS = new Set(['delete_option', 'delete_site_option', 'delete_network_option']);
const FIXED_VALUE_KINDS = new Set(['string', 'number', 'boolean']);

// Stały koniec nazwy ogranicza zakres do opcji z takim końcem: update_option( $_POST['addon'] . '_notice_ignore', ... ).
// Wyjątek to końcówki opcji ról ({prefiks}user_roles), bo prefiks tabeli atakujący zna.
const ROLE_SUFFIX = /(?:user_roles|capabilities)$/i;
const MIN_FIXED_SUFFIX = 5;

function hasFixedSuffix(stack: PhpNode[], name: AnyNode): boolean {
  const parts = flattenValue(stack, name);
  const last = parts[parts.length - 1];
  return parts.length > 1 && last?.lit !== undefined && last.lit.length >= MIN_FIXED_SUFFIX && !ROLE_SUFFIX.test(last.lit);
}

export const optionUpdateRule: Rule = {
  id: 'wp.option.arbitrary_update',
  titleKey: 'rule.wp.option.arbitrary_update.title',
  severity: 'critical',
  confidence: 'firm',
  cwe: ['CWE-915'],
  asvs: ['4.1.1'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const taint = new TaintAnalyzer(ctx.ast, KEY_SPEC);
    linkCallers(taint, ctx.ast, ctx.code);

    walk(ctx.ast, (node, stack: PhpNode[]) => {
      const n = node as AnyNode;
      if (n.kind !== 'call') return;
      const name = calledName(n);
      if (!name || !(OPTION_WRITERS.has(name) || OPTION_DELETERS.has(name))) return;
      const args = callArgs(n);
      if (!args[0]) return;

      const hit = leadingTaint(taint, args[0], stack, n, (text) => text.length > 0);
      const deletes = OPTION_DELETERS.has(name);
      const found = gradeHit(hit, deletes ? 'high' : 'critical', deletes ? 'medium' : 'high', ctx.t);
      if (!found) return;
      if (adminGated(enclosingScope(stack, ctx.ast), hit, taint)) return;
      const fixedValue = !deletes && args[1] !== undefined && FIXED_VALUE_KINDS.has(args[1].kind ?? '');
      const limited = hasFixedSuffix(stack, args[0]) ? downgradeGated(found) : found;
      const grade = fixedValue ? lowerGrade(limited) : limited;

      const loc = nodeStart(n);
      findings.push({
        ruleId: optionUpdateRule.id,
        severity: grade.severity,
        confidence: grade.confidence,
        message: ctx.t(deletes ? 'option.delete.message' : 'option.update.message', { name, from: grade.from }),
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: ['CWE-915'],
        asvs: ['4.1.1'],
        fix: ctx.t('option.fix'),
      });
    });

    return findings;
  },
};
