// Reguła: register_setting bez sanitize_callback.
// Opcja zapisana bez sanitize_callback przyjmuje wartość bez walidacji.
// To częsta droga do XSS w panelu i do zapisu nieoczekiwanych danych.
import { walk } from '../parser';
import { asNode, calledName, callArgs, findEntry, nodeStart, type AnyNode } from './ast-utils';
import type { Finding, FileContext, Rule } from './types';

export const registerSettingRule: Rule = {
  id: 'wp.option.no_sanitize_callback',
  titleKey: 'rule.wp.option.no_sanitize_callback.title',
  severity: 'medium',
  confidence: 'firm',
  cwe: ['CWE-20'],
  asvs: ['5.1.3'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    walk(ctx.ast, (node) => {
      const n = node as AnyNode;
      if (calledName(n) !== 'register_setting') return;

      const args = callArgs(n);
      // Mniej niż trzy argumenty: brak sanitize_callback.
      // Trzeci argument tablica bez klucza sanitize_callback: brak sanitizacji.
      // Trzeci argument jako callback (string, closure) to stara sygnatura, bezpieczna.
      let missing = false;
      if (args.length < 3) {
        missing = true;
      } else {
        const third = asNode(args[2]);
        if (third && third.kind === 'array' && !findEntry(third, 'sanitize_callback')) missing = true;
      }
      if (!missing) return;

      const loc = nodeStart(n);
      findings.push({
        ruleId: registerSettingRule.id,
        severity: 'medium',
        confidence: 'firm',
        message: ctx.t('registerSetting.message'),
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: registerSettingRule.cwe,
        asvs: registerSettingRule.asvs,
        fix: ctx.t('registerSetting.fix'),
      });
    });
    return findings;
  },
};
