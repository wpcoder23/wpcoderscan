// Reguła: zdalne wykonanie kodu i niebezpieczne wykonanie poleceń.
// Wykrywa eval z danych dynamicznych, include/require ze ścieżką z danych
// użytkownika, rodzinę system/exec/shell_exec oraz polecenia w backtickach.
// Dane śledzimy lekką analizą skażenia (taint.ts). Superglobal wprost to
// wykrycie pewne. Zmienna zasilona danymi z superglobala to heurystyka.
// Zwykłe dynamiczne include ze ścieżką złożoną ze stałych i zmiennych
// wtyczki nie jest zgłaszane, bo tak działa większość szablonów w WordPressie.
import { walk } from '../parser';
import { asNode, calledName, callArgs, nodeStart, type AnyNode } from './ast-utils';
import { CODE_SPEC, EXEC_SPEC, INCLUDE_SPEC, originText, TaintAnalyzer, type TaintHit } from './taint';
import type { Confidence, Finding, FileContext, PhpNode, Rule, Severity } from './types';

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

export const rceRule: Rule = {
  id: 'wp.rce.dynamic',
  title: 'Dynamiczne wykonanie kodu lub polecenia systemowego',
  severity: 'critical',
  confidence: 'firm',
  cwe: ['CWE-94'],
  asvs: ['5.2.4'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const evalTaint = new TaintAnalyzer(ctx.ast, CODE_SPEC);
    const includeTaint = new TaintAnalyzer(ctx.ast, INCLUDE_SPEC);
    const execTaint = new TaintAnalyzer(ctx.ast, EXEC_SPEC);

    const push = (
      node: AnyNode,
      severity: Severity,
      confidence: Confidence,
      message: string,
      cwe: string[],
      asvs: string[],
      fix: string,
    ) => {
      const loc = nodeStart(node);
      findings.push({
        ruleId: rceRule.id,
        severity,
        confidence,
        message,
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe,
        asvs,
        fix,
      });
    };

    // Pewność i waga zależą od tego, skąd pochodzą dane.
    const grade = (
      hit: TaintHit,
      critical: Severity,
    ): { sev: Severity; conf: Confidence; from: string } | null => {
      if (hit.direct) return { sev: critical, conf: 'firm', from: 'od użytkownika' };
      if (hit.viaVar) {
        return { sev: 'high', conf: 'heuristic', from: `ze zmiennej $${hit.via ?? ''} zasilonej danymi ${originText(hit)}` };
      }
      return null;
    };

    const analyzeArgs = (analyzer: TaintAnalyzer, n: AnyNode, stack: PhpNode[]): TaintHit => {
      let direct = false;
      let viaVar = false;
      let via: string | undefined;
      let source: TaintHit['source'];
      for (const a of callArgs(n)) {
        const h = analyzer.analyze(a, stack, n);
        direct = direct || h.direct;
        viaVar = viaVar || h.viaVar;
        if (via === undefined && h.via !== undefined) {
          via = h.via;
          source = h.source;
        }
      }
      return { direct, viaVar, via, source };
    };

    walk(ctx.ast, (node, stack) => {
      const n = node as AnyNode;

      // eval z czegokolwiek poza zwykłym literałem tekstowym.
      if (n.kind === 'eval') {
        const src = asNode(n.source);
        if (!src || src.kind === 'string') return;
        const hit = evalTaint.analyze(src, stack);
        const g = grade(hit, 'critical');
        push(
          n,
          g ? g.sev : 'medium',
          g ? g.conf : 'heuristic',
          'eval wykonuje kod zbudowany dynamicznie. To prosta droga do zdalnego wykonania kodu.',
          ['CWE-95'],
          ['5.2.4'],
          'Usuń eval. Zbuduj logikę wprost w PHP, bez wykonywania tekstu jako kodu.',
        );
        return;
      }

      // include/require ze ścieżką pochodzącą od użytkownika.
      if (n.kind === 'include') {
        const hit = includeTaint.analyze(n.target, stack);
        const g = grade(hit, 'critical');
        if (!g) return;
        push(
          n,
          g.sev,
          g.conf,
          `include lub require ze ścieżką ${g.from}. Grozi dołączeniem obcego pliku i wykonaniem kodu.`,
          ['CWE-98'],
          ['12.3.1'],
          'Nie buduj ścieżki z danych wejściowych. Użyj stałej listy dozwolonych plików (allowlista) albo ścieżek względem katalogu wtyczki.',
        );
        return;
      }

      // backticki, czyli wykonanie polecenia powłoki.
      if (n.kind === 'encapsed' && n.type === 'shell') {
        const g = grade(execTaint.analyze(n, stack), 'critical');
        if (!g) return;
        push(
          n,
          g.sev,
          g.conf,
          `Polecenie w backtickach ${g.from}. Grozi wstrzyknięciem polecenia systemowego.`,
          ['CWE-78'],
          ['5.3.8'],
          'Unikaj powłoki. Jeśli musisz, przekaż argumenty przez escapeshellarg i nie sklejaj ich w tekst polecenia.',
        );
        return;
      }

      // system, exec, shell_exec i pokrewne z argumentem od użytkownika.
      const name = calledName(n);
      if (name && SHELL_SINKS.has(name)) {
        const g = grade(analyzeArgs(execTaint, n, stack), 'critical');
        if (!g) return;
        push(
          n,
          g.sev,
          g.conf,
          `${name}() uruchamia polecenie ${g.from}. Grozi wstrzyknięciem polecenia systemowego.`,
          ['CWE-78'],
          ['5.3.8'],
          'Unikaj powłoki. Jeśli musisz, przekaż argumenty przez escapeshellarg i nie sklejaj ich w tekst polecenia.',
        );
      }
    });

    return findings;
  },
};
