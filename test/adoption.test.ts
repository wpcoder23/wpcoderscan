// Wdrożenie w istniejącym kodzie: komentarze wyciszające, wykluczenia, wyłączone reguły,
// baseline i plik ustawień. Najpierw silnik, potem CLI od początku do końca.
import { describe, it, expect, afterAll } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { buildSarif, createBaseline, renderTerminal, scan } from '../src/index';
import type { ScanResult } from '../src/index';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

// eval na danych z żądania: reguła pewna, poziom krytyczny.
const EVAL = "eval( $_POST['code'] );";
// echo superglobala: heurystyka, poziom wysoki.
const ECHO = "echo $_GET['a'];";

const dirs: string[] = [];
function tempDir(): string {
  const d = mkdtempSync(join(tmpdir(), 'wpcs-adopt-'));
  dirs.push(d);
  return d;
}
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function php(...lines: string[]): string {
  return ['<?php', ...lines, ''].join('\n');
}
function put(dir: string, rel: string, content: string): void {
  const file = join(dir, rel);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, content, 'utf8');
}
const ruleIds = (r: ScanResult) => r.findings.map((f) => f.ruleId).sort();

describe('silnik: komentarze wyciszające', () => {
  it('komentarz wycisza znalezisko, zostawia ślad w wyniku i nie daje ostrzeżeń', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php('// wpcoderscan-ignore wp.rce.dynamic -- stały tekst z pliku zespołu', EVAL));
    const r = await scan(dir, { cwd: dir });
    expect(r.findings).toHaveLength(0);
    expect(r.suppressed).toHaveLength(1);
    expect(r.suppressed[0].ruleId).toBe('wp.rce.dynamic');
    expect(r.suppressed[0].suppressedBy).toEqual({ line: 2, scope: 'line', reason: 'stały tekst z pliku zespołu' });
    expect(r.warnings).toEqual([]);
    expect(r.score.value).toBe(100);
  });

  it('ignoreComments: false pokazuje znalezisko mimo komentarza', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php('// wpcoderscan-ignore wp.rce.dynamic', EVAL));
    const r = await scan(dir, { cwd: dir, ignoreComments: false });
    expect(ruleIds(r)).toEqual(['wp.rce.dynamic']);
    expect(r.suppressed).toEqual([]);
    expect(r.warnings).toEqual([]);
  });

  it('komentarz wyciszający dotyczy wskazanej reguły i linii, nie sąsiednich', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php('// wpcoderscan-ignore wp.rce.dynamic', EVAL, ECHO, EVAL));
    const r = await scan(dir, { cwd: dir });
    expect(r.suppressed.map((f) => f.line)).toEqual([3]);
    expect(r.findings.map((f) => `${f.ruleId}:${f.line}`).sort()).toEqual(['wp.rce.dynamic:5', 'wp.xss.echo_superglobal:4']);
  });

  it('wersja -file wycisza regułę w całym pliku, ale nie w innych plikach', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php('// wpcoderscan-ignore-file wp.xss.echo_superglobal', ECHO, EVAL, ECHO));
    put(dir, 'b.php', php(ECHO));
    const r = await scan(dir, { cwd: dir });
    expect(r.suppressed.map((f) => f.line).sort((a, b) => a - b)).toEqual([3, 5]);
    expect(r.findings.map((f) => `${f.file}:${f.ruleId}`).sort()).toEqual(['a.php:wp.rce.dynamic', 'b.php:wp.xss.echo_superglobal']);
  });

  it('błędne komentarze dają ostrzeżenia z numerem linii w języku skanu i niczego nie wyciszają', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php('// wpcoderscan-ignore', '// wpcoderscan-ignore wp.nope.rule', EVAL));
    const en = await scan(dir, { cwd: dir });
    expect(en.warnings.map((w) => [w.file, w.line])).toEqual([
      ['a.php', 2],
      ['a.php', 3],
    ]);
    expect(en.warnings[0].message).toMatch(/needs a rule id/);
    expect(en.warnings[1].message).toContain('"wp.nope.rule"');
    expect(ruleIds(en)).toEqual(['wp.rce.dynamic']);

    const pl = await scan(dir, { cwd: dir, lang: 'pl' });
    expect(pl.warnings[0].message).toMatch(/wymaga identyfikatora reguły/);
  });

  it('komentarz dla wyłączonej reguły nie jest literówką', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php('// wpcoderscan-ignore wp.rce.dynamic', EVAL));
    const r = await scan(dir, { cwd: dir, disabledRules: ['wp.rce.dynamic'] });
    expect(r.warnings).toEqual([]);
    expect(r.findings).toHaveLength(0);
  });
});

describe('silnik: wyłączone reguły i wykluczenia', () => {
  it('disabledRules przyjmuje identyfikatory i wzorce z gwiazdką', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php(EVAL, ECHO));
    expect(ruleIds(await scan(dir, { cwd: dir }))).toEqual(['wp.rce.dynamic', 'wp.xss.echo_superglobal']);
    expect(ruleIds(await scan(dir, { cwd: dir, disabledRules: ['wp.rce.dynamic'] }))).toEqual(['wp.xss.echo_superglobal']);
    expect(ruleIds(await scan(dir, { cwd: dir, disabledRules: ['wp.xss.*'] }))).toEqual(['wp.rce.dynamic']);
    expect(ruleIds(await scan(dir, { cwd: dir, disabledRules: ['*'] }))).toEqual([]);
  });

  it('exclude pomija pliki i katalogi, a liczy ścieżki od excludeBase', async () => {
    const dir = tempDir();
    put(dir, 'plugin/main.php', php(EVAL));
    put(dir, 'plugin/legacy/lib.php', php(EVAL));
    put(dir, 'plugin/includes/old.min.php', php(EVAL));
    const target = join(dir, 'plugin');
    const base = { cwd: dir, excludeBase: dir };

    expect((await scan(target, base)).filesScanned).toBe(3);
    expect((await scan(target, { ...base, exclude: ['legacy/'] })).filesScanned).toBe(2);
    expect((await scan(target, { ...base, exclude: ['*.min.php'] })).filesScanned).toBe(2);
    expect((await scan(target, { ...base, exclude: ['plugin/legacy'] })).filesScanned).toBe(2);
    // Wzorzec zakotwiczony szuka legacy tylko w katalogu głównym, a tu leży on w plugin/.
    expect((await scan(target, { ...base, exclude: ['/legacy'] })).filesScanned).toBe(3);

    const r = await scan(target, { ...base, exclude: ['legacy/', '*.min.php'] });
    expect(r.filesScanned).toBe(1);
    expect(r.findings.map((f) => f.file)).toEqual(['plugin/main.php']);
  });
});

describe('silnik: odciski i baseline', () => {
  it('każde znalezisko ma odcisk i odciski są unikalne także dla identycznych linii', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php(EVAL, EVAL, EVAL, ECHO));
    const r = await scan(dir, { cwd: dir });
    expect(r.findings).toHaveLength(4);
    const ids = r.findings.map((f) => f.fingerprint);
    expect(ids.every((id) => /^[0-9a-f]{16}(:\d+)?$/.test(id ?? ''))).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('znane znaleziska znikają z wyniku, także po przesunięciu linii, a nowe zostają', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php(EVAL, ECHO));
    const first = await scan(dir, { cwd: dir });
    const baseline = createBaseline(first.findings);
    expect(baseline.entries).toHaveLength(2);

    const same = await scan(dir, { cwd: dir, baseline });
    expect(same.findings).toHaveLength(0);
    expect(same.baselined).toBe(2);
    expect(same.staleBaseline).toBe(0);

    // Puste linie na górze przesuwają stare znaleziska, a nowa linia dodaje jedno.
    put(dir, 'a.php', php('', '', '// komentarz', EVAL, ECHO, "eval( $_POST['inny'] );"));
    const changed = await scan(dir, { cwd: dir, baseline });
    expect(changed.baselined).toBe(2);
    expect(changed.findings.map((f) => [f.ruleId, f.snippet])).toEqual([['wp.rce.dynamic', "eval( $_POST['inny'] );"]]);
  });

  it('identyczne linie dopasowuje po numerze wystąpienia: trzecia kopia jest nowa', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php(EVAL, EVAL));
    const baseline = createBaseline((await scan(dir, { cwd: dir })).findings);
    put(dir, 'a.php', php(EVAL, EVAL, EVAL));
    const r = await scan(dir, { cwd: dir, baseline });
    expect(r.baselined).toBe(2);
    expect(r.findings).toHaveLength(1);
  });

  it('naprawione znalezisko zostawia nieaktualny wpis, ale tylko dla aktywnych reguł i czytanych plików', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php(EVAL, ECHO));
    put(dir, 'b.php', php(EVAL));
    const baseline = createBaseline((await scan(dir, { cwd: dir })).findings);
    expect(baseline.entries).toHaveLength(3);

    put(dir, 'a.php', php(ECHO));
    const fixed = await scan(dir, { cwd: dir, baseline });
    expect(fixed.staleBaseline).toBe(1);

    // Reguła wyłączona w tym skanie: jej wpisy nie są "nieaktualne".
    const ruleOff = await scan(dir, { cwd: dir, baseline, disabledRules: ['wp.rce.dynamic'] });
    expect(ruleOff.staleBaseline).toBe(0);

    // Skan wybranych plików (tryb diff): wpisy dla plików nieczytanych są pomijane.
    const onlyB = await scan('diff:test', { cwd: dir, baseline, files: [join(dir, 'b.php')] });
    expect(onlyB.staleBaseline).toBe(0);
    expect(onlyB.baselined).toBe(1);
  });

  it('komentarz wyciszający nie przesuwa numerów wystąpień w baseline', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php('// wpcoderscan-ignore wp.rce.dynamic', EVAL, EVAL));
    const withComment = await scan(dir, { cwd: dir });
    expect(withComment.suppressed).toHaveLength(1);
    expect(withComment.findings).toHaveLength(1);
    const baseline = createBaseline(withComment.findings);

    // Po usunięciu komentarza wyciszona kopia staje się nowym znaleziskiem, druga zostaje znana.
    put(dir, 'a.php', php(EVAL, EVAL));
    const r = await scan(dir, { cwd: dir, baseline });
    expect(r.baselined).toBe(1);
    expect(r.findings).toHaveLength(1);
  });
});

describe('raporty: wyciszone, baseline i ostrzeżenia', () => {
  it('terminal pokazuje liczby wyciszonych i znanych znalezisk, ostrzeżenia i nieaktualne wpisy', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php('// wpcoderscan-ignore wp.rce.dynamic', EVAL, ECHO, '// wpcoderscan-ignore'));
    const baseline = createBaseline((await scan(dir, { cwd: dir })).findings);
    put(dir, 'b.php', php('// wpcoderscan-ignore wp.rce.dynamic', EVAL, '// wpcoderscan-ignore'));
    const withNew = await scan(dir, { cwd: dir, baseline: { ...baseline, entries: [...baseline.entries, { id: 'zzz', rule: 'wp.rce.dynamic', file: 'a.php', line: 1 }] } });
    const text = renderTerminal(withNew, { cwd: dir });
    expect(text).toContain('suppressed by comments: 2');
    expect(text).toContain('in baseline: 1');
    expect(text).toContain('warnings: 2');
    expect(text).toContain('a.php:5: wpcoderscan-ignore needs a rule id');
    expect(text).toContain('baseline entries without a match: 1');

    const pl = await scan(dir, { cwd: dir, lang: 'pl', baseline });
    expect(renderTerminal(pl, { cwd: dir })).toContain('wyciszone komentarzem: 2');
  });

  it('SARIF pomija wyciszone i znane znaleziska, a ich liczby daje we właściwościach przebiegu', async () => {
    const dir = tempDir();
    put(dir, 'a.php', php('// wpcoderscan-ignore wp.rce.dynamic', EVAL, ECHO));
    const baseline = createBaseline((await scan(dir, { cwd: dir })).findings);
    put(dir, 'b.php', php('// wpcoderscan-ignore wp.rce.dynamic', EVAL, EVAL));
    const r = await scan(dir, { cwd: dir, baseline });
    const run = buildSarif(r).runs[0];
    expect(run.results.map((x) => x.ruleId)).toEqual(['wp.rce.dynamic']);
    expect(run.properties).toEqual({ suppressedByComments: 2, baselined: 1 });
    expect(run.results[0].partialFingerprints.wpcsFingerprint).toMatch(/^[0-9a-f]{16}(:\d+)?$/);

    const clean = buildSarif(await scan(dir, { cwd: dir, ignoreComments: false })).runs[0];
    expect(clean.properties).toBeUndefined();
  });
});

describe('CLI od początku do końca: ustawienia i baseline', () => {
  // Uruchamia źródło przez tsx w podanym katalogu, bez budowania paczki.
  const loader = pathToFileURL(join(root, 'node_modules', 'tsx', 'dist', 'loader.mjs')).href;
  const cli = (cwd: string, args: string[], env: Record<string, string> = {}) =>
    spawnSync(process.execPath, ['--import', loader, join(root, 'src', 'cli.ts'), ...args], {
      cwd,
      encoding: 'utf8',
      env: { ...process.env, WPCODERSCAN_LANG: '', NO_COLOR: '1', ...env },
    });
  const json = (out: string) => JSON.parse(out) as ScanResult;
  const T = { timeout: 120_000 };

  it('plik ustawień z bieżącego katalogu wyklucza pliki, a --no-config go pomija', T, () => {
    const dir = tempDir();
    put(dir, 'src/a.php', php(EVAL));
    put(dir, 'legacy/b.php', php(EVAL));
    put(dir, '.wpcoderscan.json', JSON.stringify({ exclude: ['legacy/'] }));

    const withConfig = cli(dir, ['.', '--json']);
    expect(withConfig.status).toBe(1);
    expect(withConfig.stderr).toContain('using config .wpcoderscan.json');
    expect(json(withConfig.stdout).filesScanned).toBe(1);

    const without = cli(dir, ['.', '--json', '--no-config']);
    expect(without.status).toBe(1);
    expect(without.stderr).not.toContain('using config');
    expect(json(without.stdout).filesScanned).toBe(2);
  });

  it('kolejność ustawień: flaga, zmienna środowiskowa, plik ustawień', T, () => {
    const dir = tempDir();
    put(dir, 'a.php', php(EVAL));

    put(dir, '.wpcoderscan.json', JSON.stringify({ failOn: 'none' }));
    expect(cli(dir, ['.']).status).toBe(0);
    expect(cli(dir, ['.', '--fail-on', 'high']).status).toBe(1);
    expect(cli(dir, ['.', '--fail-on=high']).status).toBe(1);

    put(dir, '.wpcoderscan.json', JSON.stringify({ lang: 'pl' }));
    expect(json(cli(dir, ['.', '--json']).stdout).lang).toBe('pl');
    expect(json(cli(dir, ['.', '--json', '--lang', 'en']).stdout).lang).toBe('en');
    expect(json(cli(dir, ['.', '--json'], { WPCODERSCAN_LANG: 'en' }).stdout).lang).toBe('en');

    // Heurystyka nie łamie builda, dopóki ustawienia nie włączą strict.
    put(dir, 'a.php', php(ECHO));
    put(dir, '.wpcoderscan.json', JSON.stringify({}));
    expect(cli(dir, ['.']).status).toBe(0);
    put(dir, '.wpcoderscan.json', JSON.stringify({ strict: true }));
    expect(cli(dir, ['.']).status).toBe(1);
  });

  it('wyłączona reguła znika z wyniku, a literówka w nazwie reguły daje ostrzeżenie', T, () => {
    const dir = tempDir();
    put(dir, 'a.php', php(EVAL));
    put(dir, '.wpcoderscan.json', JSON.stringify({ rules: { 'wp.rce.dynamic': 'off', 'wp.nope.*': 'off' } }));
    const r = cli(dir, ['.', '--json']);
    expect(r.status).toBe(0);
    expect(json(r.stdout).findings).toHaveLength(0);
    expect(r.stderr).toContain('warning:');
    expect(r.stderr).toContain('"wp.nope.*"');
  });

  it('zepsute ustawienia kończą się kodem 2, a plik z katalogu skanowanego nie jest czytany', T, () => {
    const dir = tempDir();
    put(dir, 'a.php', php(EVAL));
    put(dir, '.wpcoderscan.json', JSON.stringify({ foo: 1 }));
    const bad = cli(dir, ['.']);
    expect(bad.status).toBe(2);
    expect(bad.stderr).toContain('unknown option "foo"');
    expect(cli(dir, ['.', '--config', 'brak.json']).status).toBe(2);
    expect(cli(dir, ['.', '--no-config']).status).toBe(1);

    // Cudza wtyczka z własnym plikiem ustawień nie wyłącza reguł skanerowi, który ją sprawdza.
    const outer = tempDir();
    put(outer, 'plugin/a.php', php(EVAL));
    put(outer, 'plugin/.wpcoderscan.json', JSON.stringify({ failOn: 'none', rules: { '*': 'off' } }));
    const scanned = cli(outer, ['plugin', '--json']);
    expect(scanned.status).toBe(1);
    expect(scanned.stderr).not.toContain('using config');
    expect(json(scanned.stdout).findings).toHaveLength(1);
  });

  it('--write-baseline zapisuje plik, a --baseline zgłasza już tylko nowe znaleziska', T, () => {
    const dir = tempDir();
    put(dir, 'a.php', php(EVAL, ECHO));

    const written = cli(dir, ['.', '--write-baseline', 'base.json']);
    expect(written.status).toBe(0);
    expect(written.stdout).toBe('');
    expect(written.stderr).toContain('Baseline saved to base.json: 2 findings');
    expect(existsSync(join(dir, 'base.json'))).toBe(true);
    expect(JSON.parse(readFileSync(join(dir, 'base.json'), 'utf8')).entries).toHaveLength(2);

    const known = cli(dir, ['.', '--baseline', 'base.json', '--json']);
    expect(known.status).toBe(0);
    expect(json(known.stdout).findings).toHaveLength(0);
    expect(json(known.stdout).baselined).toBe(2);
    expect(cli(dir, ['.', '--baseline=base.json']).stdout).toContain('in baseline: 2');

    put(dir, 'a.php', php('', EVAL, ECHO, "eval( $_POST['nowy'] );"));
    const fresh = cli(dir, ['.', '--baseline', 'base.json', '--json']);
    expect(fresh.status).toBe(1);
    expect(json(fresh.stdout).findings.map((f) => f.snippet)).toEqual(["eval( $_POST['nowy'] );"]);
  });

  it('ścieżka baseline z pliku ustawień liczy się od katalogu tego pliku', T, () => {
    const dir = tempDir();
    put(dir, 'a.php', php(EVAL));
    expect(cli(dir, ['.', '--write-baseline', 'ci/base.json']).status).not.toBe(0);
    mkdirSync(join(dir, 'ci'));
    expect(cli(dir, ['.', '--write-baseline', 'ci/base.json']).status).toBe(0);
    put(dir, '.wpcoderscan.json', JSON.stringify({ baseline: 'ci/base.json' }));
    const r = cli(dir, ['.', '--json']);
    expect(r.status).toBe(0);
    expect(json(r.stdout).baselined).toBe(1);
  });

  it('błędy użycia baseline kończą się kodem 2 z czytelnym komunikatem', T, () => {
    const dir = tempDir();
    put(dir, 'a.php', php(EVAL));
    const missing = cli(dir, ['.', '--baseline', 'brak.json']);
    expect(missing.status).toBe(2);
    expect(missing.stderr).toContain('baseline file not found');

    put(dir, 'zly.json', 'to nie json');
    const invalid = cli(dir, ['.', '--baseline', 'zly.json']);
    expect(invalid.status).toBe(2);
    expect(invalid.stderr).toContain('baseline file is not valid');

    const noValue = cli(dir, ['.', '--baseline']);
    expect(noValue.status).toBe(2);
    expect(noValue.stderr).toContain('option --baseline needs a value');
    expect(cli(dir, ['.', '--write-baseline', '--json']).stderr).toContain('option --write-baseline needs a value');

    const diff = cli(dir, ['.', '--write-baseline', 'x.json', '--diff', 'HEAD']);
    expect(diff.status).toBe(2);
    expect(diff.stderr).toContain('cannot be combined with --diff');
    expect(existsSync(join(dir, 'x.json'))).toBe(false);
  });

  it('komentarze wyciszające działają domyślnie, a --no-ignore-comments i ustawienia je wyłączają', T, () => {
    const dir = tempDir();
    put(dir, 'a.php', php('// wpcoderscan-ignore wp.rce.dynamic -- sprawdzone', EVAL));

    const def = cli(dir, ['.']);
    expect(def.status).toBe(0);
    expect(def.stdout).toContain('suppressed by comments: 1');

    expect(cli(dir, ['.', '--no-ignore-comments']).status).toBe(1);
    put(dir, '.wpcoderscan.json', JSON.stringify({ ignoreComments: false }));
    expect(cli(dir, ['.']).status).toBe(1);
  });

  it('pomoc opisuje nowe opcje po angielsku i po polsku', T, () => {
    const dir = tempDir();
    const en = cli(dir, ['--help']).stdout;
    for (const flag of ['--baseline <file>', '--write-baseline <file>', '--config <file>', '--no-config', '--no-ignore-comments']) {
      expect(en).toContain(flag);
    }
    const pl = cli(dir, ['--help', '--lang', 'pl']).stdout;
    for (const flag of ['--baseline <plik>', '--write-baseline <plik>', '--config <plik>', '--no-config', '--no-ignore-comments']) {
      expect(pl).toContain(flag);
    }
  });
});
