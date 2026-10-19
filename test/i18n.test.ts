// Katalogi tłumaczeń, wybór języka i język wyniku skanu, raportów oraz CLI.
import { describe, it, expect } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan, buildSarif, renderTerminal, allRules, extendedRules } from '../src/index';
import { catalogOf, createTranslator, format, LANGS, parseLang, placeholders } from '../src/i18n';
import { parseArgs, parseFailOn, resolveLanguage, UsageError } from '../src/cli-options';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const vulnDir = join(here, 'fixtures', 'vulnerable');
const safeDir = join(here, 'fixtures', 'safe');
// Myślnik en (U+2013) i em (U+2014) składamy z kodów, żeby nie wpisywać ich do pliku.
const DASHES = new RegExp('[' + String.fromCharCode(0x2013, 0x2014) + ']');

describe('katalogi tłumaczeń', () => {
  const en = catalogOf('en');
  const pl = catalogOf('pl');
  const keys = Object.keys(en);

  it('mają te same klucze', () => {
    expect(Object.keys(pl).sort()).toEqual([...keys].sort());
  });

  it('mają niepuste wartości i te same zmienne w klamrach', () => {
    for (const key of keys) {
      const k = key as keyof typeof en;
      expect(en[k].trim().length, `en ${key}`).toBeGreaterThan(0);
      expect(pl[k].trim().length, `pl ${key}`).toBeGreaterThan(0);
      expect(placeholders(pl[k]), `zmienne ${key}`).toEqual(placeholders(en[k]));
    }
  });

  it('nie zawierają myślnika em ani en', () => {
    for (const lang of LANGS) {
      for (const [key, value] of Object.entries(catalogOf(lang))) {
        expect(DASHES.test(value), `${lang} ${key}`).toBe(false);
      }
    }
  });

  it('polski katalog zawiera polskie znaki tam, gdzie powinien', () => {
    expect(pl['report.score']).toBe('Wynik: {value}/100');
    expect(pl['rule.wp.auth.unprotected_action.title']).toContain('uprawnień');
  });

  it('każda reguła ma tytuł pod kluczem rule.<id>.title', () => {
    for (const rule of [...allRules, ...extendedRules]) {
      expect(rule.titleKey).toBe(`rule.${rule.id}.title`);
      expect(en[rule.titleKey].length).toBeGreaterThan(0);
    }
  });
});

describe('format i tłumacz', () => {
  it('podstawia zmienne i zostawia brakujące na widoku', () => {
    expect(format('a {x} b {y}', { x: 1 })).toBe('a 1 b {y}');
    expect(createTranslator('en')('report.counts', { files: 3, findings: 2 })).toBe('files: 3, findings: 2');
    expect(createTranslator('pl')('report.counts', { files: 3, findings: 2 })).toBe('plików: 3, znalezisk: 2');
  });

  it('nie wstawia wartości drugi raz, gdy sama zawiera klamry', () => {
    expect(format('x {a} y {b}', { a: '{b}', b: 'B' })).toBe('x {b} y B');
  });
});

describe('rozpoznawanie języka', () => {
  it('rozumie kody i nazwy ustawień regionalnych', () => {
    expect(parseLang('pl')).toBe('pl');
    expect(parseLang('PL')).toBe('pl');
    expect(parseLang('pl_PL')).toBe('pl');
    expect(parseLang('en-US')).toBe('en');
    expect(parseLang('en_GB.UTF-8')).toBe('en');
    expect(parseLang(' pl ')).toBe('pl');
  });

  it('odrzuca nieznane i puste wartości', () => {
    expect(parseLang('de')).toBeNull();
    expect(parseLang('')).toBeNull();
    expect(parseLang(undefined)).toBeNull();
    expect(parseLang(null)).toBeNull();
  });
});

describe('argumenty CLI i wybór języka', () => {
  it('czyta --lang w dwóch zapisach', () => {
    expect(parseArgs(['x', '--lang', 'pl']).lang).toBe('pl');
    expect(parseArgs(['x', '--lang=pl']).lang).toBe('pl');
    expect(parseArgs(['x']).lang).toBeNull();
  });

  it('flaga ma pierwszeństwo przed zmienną, zmienna przed domyślnym angielskim', () => {
    expect(resolveLanguage('pl', 'en').lang).toBe('pl');
    expect(resolveLanguage(null, 'pl').lang).toBe('pl');
    expect(resolveLanguage(null, undefined).lang).toBe('en');
    expect(resolveLanguage(null, '').lang).toBe('en');
  });

  it('zła flaga to błąd, zła zmienna to ostrzeżenie z angielskim w zapasie', () => {
    expect(() => resolveLanguage('xx', undefined)).toThrow(UsageError);
    const fromEnv = resolveLanguage(null, 'xx');
    expect(fromEnv.lang).toBe('en');
    expect(fromEnv.warning).toContain('WPCODERSCAN_LANG');
  });

  it('--fail-on przyjmuje znane poziomy, a nieznany odrzuca', () => {
    const t = createTranslator('en');
    expect(parseFailOn('high', t)).toBe('high');
    expect(parseFailOn('none', t)).toBe('none');
    expect(() => parseFailOn('hihg', t)).toThrow(/unknown --fail-on level "hihg"/);
    expect(() => parseFailOn('hihg', createTranslator('pl'))).toThrow(/nieznany poziom --fail-on/);
  });
});

describe('język wyniku skanu', () => {
  it('domyślnie angielski', async () => {
    const r = await scan(vulnDir, { cwd: vulnDir });
    expect(r.lang).toBe('en');
    const sqli = r.findings.find((f) => f.ruleId === 'wp.sqli.unprepared' && f.confidence === 'firm');
    expect(sqli?.message).toContain('inserts user input into the query without prepare');
    expect(sqli?.fix).toContain('Use $wpdb->prepare()');
  });

  it('polski na życzenie, z tymi samymi znaleziskami', async () => {
    const en = await scan(vulnDir, { cwd: vulnDir });
    const pl = await scan(vulnDir, { cwd: vulnDir, lang: 'pl' });
    expect(pl.lang).toBe('pl');
    expect(pl.findings.map((f) => `${f.ruleId}:${f.file}:${f.line}`)).toEqual(
      en.findings.map((f) => `${f.ruleId}:${f.file}:${f.line}`),
    );
    const sqli = pl.findings.find((f) => f.ruleId === 'wp.sqli.unprepared' && f.confidence === 'firm');
    expect(sqli?.message).toContain('wkleja dane od użytkownika do zapytania bez prepare');
    expect(pl.findings.some((f) => f.patch?.label.startsWith('Opakuj dane'))).toBe(true);
    expect(en.findings.some((f) => f.patch?.label.startsWith('Wrap the data'))).toBe(true);
  });

  it('żaden komunikat po angielsku nie ma polskich znaków i odwrotnie nie brakuje kluczy', async () => {
    const en = await scan(vulnDir, { cwd: vulnDir, extended: true });
    for (const f of en.findings) {
      expect(/[ąćęłńóśźż]/i.test(f.message), f.message).toBe(false);
      expect(/[ąćęłńóśźż]/i.test(f.fix ?? ''), f.fix).toBe(false);
      expect(f.message.includes('{'), f.message).toBe(false);
    }
    const pl = await scan(vulnDir, { cwd: vulnDir, extended: true, lang: 'pl' });
    for (const f of pl.findings) expect(f.message.includes('{'), f.message).toBe(false);
  });
});

describe('raporty w wybranym języku', () => {
  it('terminal po angielsku i po polsku', async () => {
    const en = renderTerminal(await scan(vulnDir, { cwd: vulnDir }), { cwd: vulnDir });
    expect(en).toContain('Score:');
    expect(en).toContain('files:');
    expect(en).toContain('CRITICAL');
    const pl = renderTerminal(await scan(vulnDir, { cwd: vulnDir, lang: 'pl' }), { cwd: vulnDir });
    expect(pl).toContain('Wynik:');
    expect(pl).toContain('plików:');
    expect(pl).toContain('KRYTYCZNE');
  });

  it('SARIF ma opisy reguł w języku wyniku', async () => {
    const en = buildSarif(await scan(vulnDir, { cwd: vulnDir })).runs[0].tool.driver.rules;
    const pl = buildSarif(await scan(vulnDir, { cwd: vulnDir, lang: 'pl' })).runs[0].tool.driver.rules;
    expect(en.find((r) => r.id === 'wp.rce.dynamic')?.shortDescription.text).toBe(
      'Dynamic code or system command execution',
    );
    expect(pl.find((r) => r.id === 'wp.rce.dynamic')?.shortDescription.text).toBe(
      'Dynamiczne wykonanie kodu lub polecenia systemowego',
    );
  });

  it('SARIF opisuje regułę rozszerzoną tylko wtedy, gdy wynik ją zawiera', async () => {
    const plain = buildSarif(await scan(vulnDir, { cwd: vulnDir })).runs[0];
    expect(plain.tool.driver.rules.map((r) => r.id)).not.toContain('wp.sqli.param_unprepared');

    const extended = buildSarif(await scan(vulnDir, { cwd: vulnDir, extended: true })).runs[0];
    const ids = extended.tool.driver.rules.map((r) => r.id);
    if (extended.results.some((r) => r.ruleId === 'wp.sqli.param_unprepared')) {
      expect(ids).toContain('wp.sqli.param_unprepared');
    }
    for (const res of extended.results) {
      expect(res.ruleIndex).toBeDefined();
      expect(extended.tool.driver.rules[res.ruleIndex as number].id).toBe(res.ruleId);
    }
  });
});

describe('CLI od początku do końca', () => {
  // Uruchamia źródło przez tsx, bez budowania paczki.
  const cli = (args: string[], env: Record<string, string> = {}) =>
    spawnSync(process.execPath, ['--import', 'tsx', join(root, 'src', 'cli.ts'), ...args], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, WPCODERSCAN_LANG: '', NO_COLOR: '1', ...env },
    });

  it('pomoc: angielska domyślnie, polska przez flagę i przez zmienną', () => {
    const def = cli(['--help']);
    expect(def.status).toBe(0);
    expect(def.stdout).toContain('Usage:');
    expect(def.stdout).toContain('--lang <en|pl>');

    const viaFlag = cli(['--help', '--lang', 'pl']);
    expect(viaFlag.stdout).toContain('Użycie:');

    const viaEnv = cli(['--help'], { WPCODERSCAN_LANG: 'pl_PL' });
    expect(viaEnv.stdout).toContain('Użycie:');

    const flagWins = cli(['--help', '--lang', 'en'], { WPCODERSCAN_LANG: 'pl' });
    expect(flagWins.stdout).toContain('Usage:');
  });

  it('zły język i zły poziom kończą się kodem 2 z komunikatem', () => {
    const badLang = cli(['--help', '--lang', 'xx']);
    expect(badLang.status).toBe(2);
    expect(badLang.stderr).toContain('unknown language "xx"');

    const badLevel = cli([safeDir, '--fail-on', 'hihg']);
    expect(badLevel.status).toBe(2);
    expect(badLevel.stderr).toContain('unknown --fail-on level "hihg"');

    const badEnv = cli(['--help'], { WPCODERSCAN_LANG: 'xx' });
    expect(badEnv.status).toBe(0);
    expect(badEnv.stderr).toContain('WPCODERSCAN_LANG');
    expect(badEnv.stdout).toContain('Usage:');
  });

  it('skan: JSON w wybranym języku, kod wyjścia bez zmian', () => {
    const en = cli([vulnDir, '--json']);
    expect(en.status).toBe(1);
    const enJson = JSON.parse(en.stdout) as { lang: string; findings: Array<{ message: string }> };
    expect(enJson.lang).toBe('en');
    expect(enJson.findings.length).toBeGreaterThan(0);

    const pl = cli([vulnDir, '--json', '--lang', 'pl']);
    expect(pl.status).toBe(1);
    const plJson = JSON.parse(pl.stdout) as { lang: string };
    expect(plJson.lang).toBe('pl');
  });

  it('wersja nie zależy od języka', () => {
    const v = execFileSync(process.execPath, ['--import', 'tsx', join(root, 'src', 'cli.ts'), '--version'], {
      cwd: root,
      encoding: 'utf8',
    });
    expect(v.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
