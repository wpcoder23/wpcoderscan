// Reguła: zdalne wykonanie kodu i niebezpieczne wykonanie poleceń.
// Wykrywa eval z danych dynamicznych, include/require ze ścieżką z danych
// użytkownika, funkcje ładujące szablon po nazwie (get_template_part, load_template),
// rodzinę system/exec/shell_exec oraz polecenia w backtickach.
// Dane śledzimy lekką analizą skażenia (taint.ts). Superglobal wprost to
// wykrycie pewne. Zmienna zasilona danymi z superglobala to heurystyka.
// Zwykłe dynamiczne include ze ścieżką złożoną ze stałych i zmiennych
// wtyczki nie jest zgłaszane, bo tak działa większość szablonów w WordPressie.
import { walk } from '../parser';
import { asNode, calledName, callArgs, nodeStart, offsetName, type AnyNode } from './ast-utils';
import { isLocalCall, linkCallers } from './callers';
import { findShortcodeHandlers } from './shortcodes';
import { CODE_SPEC, EXEC_SPEC, INCLUDE_SPEC, originText, TaintAnalyzer, viaText, type TaintHit } from './taint';
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

// Nazwy ładujące szablon po nazwie. Porównujemy bez podkreśleń i wielkości liter, żeby objąć
// get_template_part, getTemplatePart i własne przedrostki (lae_get_template_part).
const TEMPLATE_LOADER =
  /(?:gettemplate(?:part|file|html)?|loadtemplate(?:part|file)?|locatetemplate|rendertemplate(?:part)?|includetemplate)$/;

// Funkcje rdzenia WordPressa i WooCommerce. Dane wprost z superglobala to przy nich wykrycie pewne.
// Własne funkcje o podobnej nazwie mogą walidować nazwę, więc dają tylko heurystykę.
const CORE_LOADERS = new Set([
  'get_template_part',
  'locate_template',
  'load_template',
  'wc_get_template',
  'wc_get_template_part',
  'wc_get_template_html',
]);

interface TemplateLoader {
  label: string;
  core: boolean;
  argCount: number; // ile pierwszych argumentów składa nazwę szablonu
}

// Funkcja albo metoda (na dowolnym obiekcie) ładująca szablon po nazwie.
function templateLoader(n: AnyNode): TemplateLoader | undefined {
  if (n.kind !== 'call') return undefined;
  const fn = calledName(n);
  let label = fn;
  if (!label) {
    const what = asNode(n.what);
    if (!what || (what.kind !== 'propertylookup' && what.kind !== 'staticlookup')) return undefined;
    label = offsetName(what.offset);
  }
  if (!label) return undefined;
  const flat = label.replace(/_/g, '').toLowerCase();
  if (!TEMPLATE_LOADER.test(flat)) return undefined;
  return { label, core: !!fn && CORE_LOADERS.has(fn), argCount: flat.endsWith('templatepart') ? 2 : 1 };
}

export const rceRule: Rule = {
  id: 'wp.rce.dynamic',
  titleKey: 'rule.wp.rce.dynamic.title',
  severity: 'critical',
  confidence: 'firm',
  cwe: ['CWE-94'],
  asvs: ['5.2.4'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const evalTaint = new TaintAnalyzer(ctx.ast, CODE_SPEC);
    const includeTaint = new TaintAnalyzer(ctx.ast, INCLUDE_SPEC);
    const execTaint = new TaintAnalyzer(ctx.ast, EXEC_SPEC);
    // Atrybuty shortcode pochodzą od autora wpisu, więc są danymi użytkownika.
    for (const h of findShortcodeHandlers(ctx.ast, ctx.code)) {
      for (const analyzer of [evalTaint, includeTaint, execTaint]) analyzer.seed(h.scope, h.param, 'shortcode');
    }
    for (const analyzer of [evalTaint, includeTaint, execTaint]) linkCallers(analyzer, ctx.ast, ctx.code);

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
      if (hit.direct) return { sev: critical, conf: 'firm', from: ctx.t('rce.from.direct') };
      if (hit.viaVar) {
        return {
          sev: 'high',
          conf: 'heuristic',
          from: ctx.t('rce.from.viaVar', { var: viaText(hit), origin: originText(hit, ctx.t) }),
        };
      }
      return null;
    };

    // skipArrays: literał tablicy w wywołaniu ładującym szablon to dane dla szablonu, nie jego nazwa.
    const analyzeArgs = (analyzer: TaintAnalyzer, n: AnyNode, stack: PhpNode[], limit = Infinity, skipArrays = false): TaintHit => {
      let direct = false;
      let viaVar = false;
      let via: string | undefined;
      let source: TaintHit['source'];
      for (const a of callArgs(n).slice(0, limit)) {
        if (skipArrays && asNode(a)?.kind === 'array') continue;
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
          ctx.t('rce.eval.message'),
          ['CWE-95'],
          ['5.2.4'],
          ctx.t('rce.eval.fix'),
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
          ctx.t('rce.include.message', { from: g.from }),
          ['CWE-98'],
          ['12.3.1'],
          ctx.t('rce.include.fix'),
        );
        return;
      }

      // Funkcje ładujące szablon po nazwie. Wywołania funkcji z tego pliku obsługuje śledzenie wywołań.
      const loader = templateLoader(n);
      if (loader && !isLocalCall(ctx.ast, n)) {
        const g = grade(analyzeArgs(includeTaint, n, stack, loader.argCount, true), 'critical');
        if (!g) return;
        push(
          n,
          loader.core ? g.sev : 'high',
          loader.core ? g.conf : 'heuristic',
          ctx.t('rce.template.message', { name: loader.label, from: g.from }),
          ['CWE-98'],
          ['12.3.1'],
          ctx.t('rce.template.fix'),
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
          ctx.t('rce.backtick.message', { from: g.from }),
          ['CWE-78'],
          ['5.3.8'],
          ctx.t('rce.shell.fix'),
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
          ctx.t('rce.shell.message', { name, from: g.from }),
          ['CWE-78'],
          ['5.3.8'],
          ctx.t('rce.shell.fix'),
        );
      }
    });

    return findings;
  },
};
