// Pętla silnika. Zbiera pliki, parsuje, uruchamia reguły, liczy wynik.
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { collectPhpFiles, type CollectOptions } from '../collector';
import { createTranslator, DEFAULT_LANG, type Lang } from '../i18n';
import { compileGlob, isExcluded } from '../glob';
import { allRules, extendedRules } from '../rules';
import type { Finding, Rule } from '../rules/types';
import { analyzeSource, type ScanError } from './analyze';
import { applyBaseline, type Baseline } from './baseline';
import { assignFingerprints } from './fingerprint';
import { resolvePatches } from '../fix/verify';
import { scoreFindings, type Score } from './score';
import { applyIgnores, matchesPattern, parseIgnores, type SuppressedFinding } from './suppress';

export interface ScanOptions extends CollectOptions {
  rules?: Rule[];
  extended?: boolean; // dołącz reguły rozszerzone (większa czułość, więcej fałszywych alarmów)
  cwd?: string; // do liczenia ścieżek względnych
  files?: string[]; // jawna lista plików do skanu, pomija kolektor (tryb diff)
  lang?: Lang; // język komunikatów wyniku, domyślnie angielski
  exclude?: string[]; // wzorce ścieżek plików do pominięcia (składnia w src/glob.ts)
  excludeBase?: string; // katalog, od którego liczymy ścieżki wzorców, domyślnie cwd
  disabledRules?: string[]; // identyfikatory reguł (także wzorce z gwiazdką), które nie mają działać
  ignoreComments?: boolean; // honoruj komentarze wpcoderscan-ignore, domyślnie tak
  baseline?: Baseline; // znaleziska zapisane w baseline nie są zgłaszane
}

export type { ScanError };

// Ostrzeżenie o błędnym komentarzu wyciszającym. Nie jest błędem skanera i nie zmienia kodu wyjścia.
export interface ScanWarning {
  file: string;
  line: number;
  message: string;
}

export interface ScanResult {
  lang: Lang; // język komunikatów w tym wyniku
  target: string;
  filesScanned: number;
  findings: Finding[];
  score: Score;
  errors: ScanError[];
  warnings: ScanWarning[];
  suppressed: SuppressedFinding[]; // wyciszone komentarzem wpcoderscan-ignore
  baselined: number; // znaleziska pominięte, bo są w baseline
  staleBaseline: number; // wpisy baseline bez dopasowania w tym skanie
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export async function scan(target: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const cwd = opts.cwd ?? process.cwd();
  const lang = opts.lang ?? DEFAULT_LANG;
  const t = createTranslator(lang);
  const disabled = opts.disabledRules ?? [];
  const rules = (opts.rules ?? (opts.extended ? [...allRules, ...extendedRules] : allRules)).filter(
    (r) => !disabled.some((pattern) => matchesPattern(pattern, r.id)),
  );
  // Komentarz wyciszający może dotyczyć reguły rozszerzonej, więc literówki sprawdzamy na pełnej liście.
  const knownRuleIds = [...allRules, ...extendedRules].map((r) => r.id);
  // W trybie diff dostajemy gotową listę plików. Inaczej zbiera ją kolektor.
  let files = opts.files ?? (await collectPhpFiles(target, opts));
  if (opts.exclude && opts.exclude.length > 0) {
    const patterns = opts.exclude.map(compileGlob);
    const base = opts.excludeBase ?? cwd;
    files = files.filter((abs) => !isExcluded(path.relative(base, abs).split(path.sep).join('/'), patterns));
  }
  let findings: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  const warnings: ScanWarning[] = [];
  const errors: ScanError[] = [];
  const scannedFiles = new Set<string>();

  for (const abs of files) {
    // Ścieżki zawsze z ukośnikiem w przód, żeby wynik był taki sam na każdym
    // systemie i zgodny z formatem SARIF.
    const rel = (path.relative(cwd, abs) || path.basename(abs)).split(path.sep).join('/');

    let code: string;
    try {
      code = await fs.readFile(abs, 'utf8');
    } catch (e) {
      errors.push({ file: rel, message: t('error.read', { detail: (e as Error).message }) });
      continue;
    }

    scannedFiles.add(rel);
    const analysis = analyzeSource(rel, abs, code, rules, lang);
    errors.push(...analysis.errors);
    // Podpowiedzi napraw przechodzą bramki: parse, ponowny skan, brak konfliktów.
    resolvePatches({ rel, abs, code, before: analysis.findings, rules, lang });

    let fileFindings = analysis.findings;
    if (opts.ignoreComments !== false) {
      const ignores = parseIgnores(code, knownRuleIds);
      for (const p of ignores.problems) {
        const message = p.kind === 'noRule' ? t('warn.ignoreNoRule') : t('warn.ignoreUnknownRule', { rule: p.rule ?? '' });
        warnings.push({ file: rel, line: p.line, message });
      }
      const split = applyIgnores(fileFindings, ignores.directives);
      fileFindings = split.kept;
      suppressed.push(...split.suppressed);
    }
    findings.push(...fileFindings);
  }

  // Odciski liczymy razem z wyciszonymi, żeby komentarz nie przesuwał numerów wystąpień w baseline.
  assignFingerprints([...findings, ...suppressed]);

  let baselined = 0;
  let staleBaseline = 0;
  if (opts.baseline) {
    const applied = applyBaseline(findings, opts.baseline, {
      rules: new Set(rules.map((r) => r.id)),
      files: scannedFiles,
    });
    findings = applied.kept;
    baselined = applied.baselined.length;
    staleBaseline = applied.stale;
  }

  // Najcięższe najpierw, potem po pliku i linii.
  findings.sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );

  const score = scoreFindings(findings);
  return { lang, target, filesScanned: files.length, findings, score, errors, warnings, suppressed, baselined, staleBaseline };
}
