// Reguła: zdalne wykonanie kodu i niebezpieczne wykonanie poleceń.
// Wykrywa eval z danych dynamicznych, dynamiczne include/require,
// rodzinę system/exec/shell_exec na zmiennej oraz polecenia w backtickach.
import { walk } from '../parser';
import {
  analyzeDynamic,
  asNode,
  calledName,
  callArgs,
  nodeStart,
  type AnyNode,
  type DynInfo,
} from './ast-utils';
import type { Finding, FileContext, Rule, Severity } from './types';

// Funkcje uruchamiające polecenia systemowe.
const SHELL_SINKS = new Set([
  'system',
  'exec',
  'shell_exec',
  'passthru',
  'popen',
  'proc_open',
  'pcntl_exec',
]);

function dynOf(node: unknown): DynInfo {
  const info: DynInfo = { hasVar: false, hasSuperglobal: false };
  analyzeDynamic(node, info);
  return info;
}

function isDynamic(info: DynInfo): boolean {
  return info.hasVar || info.hasSuperglobal;
}

function sevFor(info: DynInfo): Severity {
  return info.hasSuperglobal ? 'critical' : 'high';
}

export const rceRule: Rule = {
  id: 'wp.rce.dynamic',
  title: 'Dynamiczne wykonanie kodu lub polecenia systemowego',
  severity: 'critical',
  confidence: 'firm',
  cwe: ['CWE-94'],
  asvs: ['5.2.4'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];

    const push = (
      node: AnyNode,
      severity: Severity,
      message: string,
      cwe: string[],
      asvs: string[],
      fix: string,
    ) => {
      const loc = nodeStart(node);
      findings.push({
        ruleId: rceRule.id,
        severity,
        confidence: 'firm',
        message,
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe,
        asvs,
        fix,
      });
    };

    walk(ctx.ast, (node) => {
      const n = node as AnyNode;

      // eval z czegokolwiek poza zwykłym literałem tekstowym.
      if (n.kind === 'eval') {
        const src = asNode(n.source);
        if (src && src.kind === 'string') return;
        push(
          n,
          'critical',
          'eval wykonuje kod zbudowany dynamicznie. To prosta droga do zdalnego wykonania kodu.',
          ['CWE-95'],
          ['5.2.4'],
          'Usuń eval. Zbuduj logikę wprost w PHP, bez wykonywania tekstu jako kodu.',
        );
        return;
      }

      // include/require ze ścieżką zależną od zmiennej albo superglobala.
      if (n.kind === 'include') {
        const info = dynOf(n.target);
        if (!isDynamic(info)) return;
        push(
          n,
          sevFor(info),
          'include lub require ze ścieżką z danych dynamicznych. Grozi dołączeniem obcego pliku i wykonaniem kodu.',
          ['CWE-98'],
          ['12.3.1'],
          'Nie buduj ścieżki z danych wejściowych. Użyj stałej listy dozwolonych plików (allowlista) albo ścieżek względem katalogu wtyczki.',
        );
        return;
      }

      // backticki, czyli wykonanie polecenia powłoki.
      if (n.kind === 'encapsed' && n.type === 'shell') {
        const info = dynOf(n.value);
        if (!isDynamic(info)) return;
        push(
          n,
          sevFor(info),
          'Polecenie w backtickach z danych dynamicznych. Grozi wstrzyknięciem polecenia systemowego.',
          ['CWE-78'],
          ['5.3.8'],
          'Unikaj powłoki. Jeśli musisz, przekaż argumenty przez escapeshellarg i nie sklejaj ich w tekst polecenia.',
        );
        return;
      }

      // system, exec, shell_exec i pokrewne z argumentem dynamicznym.
      const name = calledName(n);
      if (name && SHELL_SINKS.has(name)) {
        const info = dynOf(callArgs(n));
        if (!isDynamic(info)) return;
        push(
          n,
          sevFor(info),
          `${name}() uruchamia polecenie z danych dynamicznych. Grozi wstrzyknięciem polecenia systemowego.`,
          ['CWE-78'],
          ['5.3.8'],
          'Unikaj powłoki. Jeśli musisz, przekaż argumenty przez escapeshellarg i nie sklejaj ich w tekst polecenia.',
        );
      }
    });

    return findings;
  },
};
