// Reguła: unserialize na danych od użytkownika (PHP object injection).
// unserialize na $_GET/$_POST/$_REQUEST/$_COOKIE pozwala wstrzyknąć obiekt
// i wywołać łańcuch gadżetów. To wykrycie strukturalne, pewne.
import { walk } from '../parser';
import { analyzeDynamic, calledName, callArgs, nodeStart, type AnyNode, type DynInfo } from './ast-utils';
import type { Finding, FileContext, Rule } from './types';

// unserialize i wrapper WordPressa maybe_unserialize niosą to samo ryzyko.
const SINKS = new Set(['unserialize', 'maybe_unserialize']);

export const unserializeRule: Rule = {
  id: 'wp.unserialize.user_input',
  title: 'unserialize na danych od użytkownika',
  severity: 'high',
  confidence: 'firm',
  cwe: ['CWE-502'],
  asvs: ['5.5.3'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    walk(ctx.ast, (node) => {
      const n = node as AnyNode;
      const name = calledName(n);
      if (!name || !SINKS.has(name)) return;

      const args = callArgs(n);
      if (args.length === 0) return;

      const info: DynInfo = { hasVar: false, hasSuperglobal: false };
      analyzeDynamic(args[0], info);
      if (!info.hasSuperglobal) return; // pewne tylko przy bezpośrednim superglobalu

      const loc = nodeStart(n);
      findings.push({
        ruleId: unserializeRule.id,
        severity: 'high',
        confidence: 'firm',
        message: `${name}() na danych z superglobala. Grozi wstrzyknięciem obiektu PHP (object injection).`,
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: unserializeRule.cwe,
        asvs: unserializeRule.asvs,
        fix: 'Nie deserializuj danych od użytkownika. Użyj json_decode z danymi JSON, a jeśli musisz, wymuś allowed_classes => false.',
      });
    });
    return findings;
  },
};
