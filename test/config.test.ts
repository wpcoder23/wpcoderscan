// Plik ustawień .wpcoderscan.json: wczytywanie i walidacja.
import { describe, it, expect, afterAll } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { CONFIG_FILE, discoverConfig, loadConfig } from '../src/config';
import { UsageError } from '../src/cli-options';
import { createTranslator } from '../src/i18n';

const dirs: string[] = [];
function tempDir(): string {
  const d = mkdtempSync(join(tmpdir(), 'wpcs-config-'));
  dirs.push(d);
  return d;
}
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const en = createTranslator('en');
const pl = createTranslator('pl');

// Zapisuje plik ustawień w nowym katalogu i zwraca jego ścieżkę.
function configFile(content: unknown, raw = false): string {
  const file = join(tempDir(), CONFIG_FILE);
  writeFileSync(file, raw ? (content as string) : JSON.stringify(content), 'utf8');
  return file;
}

describe('loadConfig', () => {
  it('wczytuje poprawne ustawienia i podaje katalog pliku', () => {
    const file = configFile({
      $schema: 'https://example.invalid/schema.json',
      failOn: 'medium',
      strict: true,
      extended: false,
      lang: 'pl',
      exclude: ['vendor/', 'tests'],
      rules: { 'wp.auth.unprotected_action': 'off', 'wp.xss.*': 'off' },
      baseline: '.wpcoderscan-baseline.json',
      ignoreComments: false,
    });
    const loaded = loadConfig(file, en);
    expect(loaded.file).toBe(file);
    expect(loaded.dir).toBe(dirname(file));
    expect(loaded.config).toEqual({
      failOn: 'medium',
      strict: true,
      extended: false,
      lang: 'pl',
      exclude: ['vendor/', 'tests'],
      rules: { 'wp.auth.unprotected_action': 'off', 'wp.xss.*': 'off' },
      baseline: '.wpcoderscan-baseline.json',
      ignoreComments: false,
    });
  });

  it('pusty obiekt jest poprawny', () => {
    expect(loadConfig(configFile({}), en).config).toEqual({});
  });

  it('akceptuje plik zapisany z BOM', () => {
    const file = configFile('﻿{"failOn":"none"}', true);
    expect(loadConfig(file, en).config).toEqual({ failOn: 'none' });
  });

  it('brak pliku to błąd użycia', () => {
    expect(() => loadConfig(join(tempDir(), 'brak.json'), en)).toThrow(UsageError);
    expect(() => loadConfig(join(tempDir(), 'brak.json'), en)).toThrow(/config file not found/);
  });

  it('zepsuty JSON i obiekt nadrzędny inny niż obiekt to błąd', () => {
    expect(() => loadConfig(configFile('{nie json', true), en)).toThrow(/cannot use config file/);
    expect(() => loadConfig(configFile('[]', true), en)).toThrow(/top level must be a JSON object/);
    expect(() => loadConfig(configFile('null', true), en)).toThrow(UsageError);
  });

  it('nieznana opcja to błąd, bo literówka nie może po cichu wyłączyć ustawienia', () => {
    expect(() => loadConfig(configFile({ failon: 'high' }), en)).toThrow(/unknown option "failon"/);
  });

  it('zły typ opcji to błąd z nazwą opcji', () => {
    expect(() => loadConfig(configFile({ strict: 'tak' }), en)).toThrow(/option "strict".*boolean/);
    expect(() => loadConfig(configFile({ extended: 1 }), en)).toThrow(/option "extended"/);
    expect(() => loadConfig(configFile({ ignoreComments: 'nie' }), en)).toThrow(/option "ignoreComments"/);
    expect(() => loadConfig(configFile({ baseline: 5 }), en)).toThrow(/option "baseline".*string/);
    expect(() => loadConfig(configFile({ exclude: 'vendor' }), en)).toThrow(/option "exclude".*string\[\]/);
    expect(() => loadConfig(configFile({ exclude: ['ok', 3] }), en)).toThrow(/option "exclude"/);
    expect(() => loadConfig(configFile({ exclude: [' '] }), en)).toThrow(/option "exclude"/);
    expect(() => loadConfig(configFile({ rules: [] }), en)).toThrow(/option "rules".*object/);
  });

  it('reguły można tylko wyłączyć', () => {
    expect(() => loadConfig(configFile({ rules: { 'wp.rce.dynamic': 'on' } }), en)).toThrow(
      /rule "wp.rce.dynamic" in "rules" can only be set to "off"/,
    );
  });

  it('zły poziom failOn i zły język to błąd, none jest poprawne', () => {
    expect(() => loadConfig(configFile({ failOn: 'hihg' }), en)).toThrow(/unknown --fail-on level "hihg"/);
    expect(loadConfig(configFile({ failOn: 'none' }), en).config.failOn).toBe('none');
    expect(() => loadConfig(configFile({ lang: 'xx' }), en)).toThrow(/unknown language "xx".*en, pl/);
  });

  it('komunikaty są w języku tłumacza', () => {
    expect(() => loadConfig(configFile({ foo: 1 }), pl)).toThrow(/nieznana opcja "foo"/);
    expect(() => loadConfig(join(tempDir(), 'brak.json'), pl)).toThrow(/nie znaleziono pliku ustawień/);
  });
});

describe('discoverConfig', () => {
  it('znajduje plik w podanym katalogu', () => {
    const dir = tempDir();
    writeFileSync(join(dir, CONFIG_FILE), '{}', 'utf8');
    expect(discoverConfig(dir)).toBe(join(dir, CONFIG_FILE));
  });

  it('nie szuka w katalogach nadrzędnych ani w podkatalogach', () => {
    const parent = tempDir();
    writeFileSync(join(parent, CONFIG_FILE), '{}', 'utf8');
    const child = join(parent, 'plugin');
    mkdirSync(child);
    expect(discoverConfig(child)).toBeNull();

    const other = tempDir();
    mkdirSync(join(other, 'plugin'));
    writeFileSync(join(other, 'plugin', CONFIG_FILE), '{}', 'utf8');
    expect(discoverConfig(other)).toBeNull();
  });
});
