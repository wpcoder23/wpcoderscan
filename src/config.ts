// Plik konfiguracji .wpcoderscan.json. Ustawienia z linii poleceń mają pierwszeństwo.
// Plik szukamy tylko w bieżącym katalogu, nie w skanowanym kodzie, żeby cudza wtyczka
// nie mogła wyłączyć reguł skanerowi, który ją sprawdza. Flaga --config wskazuje inny plik.
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { SEVERITY_ORDER, UsageError } from './cli-options';
import { LANGS, parseLang, type Translate } from './i18n';

export const CONFIG_FILE = '.wpcoderscan.json';

export interface Config {
  failOn?: string;
  strict?: boolean;
  extended?: boolean;
  lang?: string;
  exclude?: string[]; // wzorce ścieżek względem katalogu z plikiem konfiguracji
  rules?: Record<string, 'off'>; // wyłączone reguły
  baseline?: string; // ścieżka względem katalogu z plikiem konfiguracji
  ignoreComments?: boolean; // czy honorować komentarze wpcoderscan-ignore, domyślnie tak
}

export interface LoadedConfig {
  file: string; // ścieżka bezwzględna
  dir: string; // katalog pliku, od którego liczymy ścieżki względne
  config: Config;
}

const KEYS = ['failOn', 'strict', 'extended', 'lang', 'exclude', 'rules', 'baseline', 'ignoreComments'];

export function discoverConfig(cwd: string): string | null {
  const file = path.join(cwd, CONFIG_FILE);
  return existsSync(file) ? file : null;
}

export function loadConfig(file: string, t: Translate): LoadedConfig {
  const abs = path.resolve(file);
  if (!existsSync(abs)) throw new UsageError(t('config.notFound', { file }));
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(abs, 'utf8').replace(/^\uFEFF/, ''));
  } catch (e) {
    throw new UsageError(t('config.invalid', { file, detail: (e as Error).message }));
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new UsageError(t('config.invalid', { file, detail: t('config.expectedObject') }));
  }
  const obj = raw as Record<string, unknown>;
  const wrongType = (key: string, expected: string) => new UsageError(t('config.badType', { file, key, expected }));

  for (const key of Object.keys(obj)) {
    if (key === '$schema') continue;
    if (!KEYS.includes(key)) throw new UsageError(t('config.unknownKey', { file, key }));
  }

  const config: Config = {};
  for (const key of ['strict', 'extended', 'ignoreComments'] as const) {
    if (obj[key] === undefined) continue;
    if (typeof obj[key] !== 'boolean') throw wrongType(key, 'boolean');
    config[key] = obj[key] as boolean;
  }
  for (const key of ['failOn', 'lang', 'baseline'] as const) {
    if (obj[key] === undefined) continue;
    if (typeof obj[key] !== 'string') throw wrongType(key, 'string');
    config[key] = obj[key] as string;
  }
  if (config.lang !== undefined && !parseLang(config.lang)) {
    throw new UsageError(t('config.badLang', { file, value: config.lang, supported: LANGS.join(', ') }));
  }
  if (config.failOn !== undefined && config.failOn !== 'none' && !(SEVERITY_ORDER as string[]).includes(config.failOn)) {
    throw new UsageError(t('cli.badFailOn', { value: config.failOn }));
  }
  if (obj.exclude !== undefined) {
    if (!Array.isArray(obj.exclude) || obj.exclude.some((x) => typeof x !== 'string' || !x.trim())) throw wrongType('exclude', 'string[]');
    config.exclude = obj.exclude as string[];
  }
  if (obj.rules !== undefined) {
    if (!obj.rules || typeof obj.rules !== 'object' || Array.isArray(obj.rules)) throw wrongType('rules', 'object');
    const rules: Record<string, 'off'> = {};
    for (const [rule, value] of Object.entries(obj.rules as Record<string, unknown>)) {
      if (value !== 'off') throw new UsageError(t('config.badRuleValue', { file, rule }));
      rules[rule] = 'off';
    }
    config.rules = rules;
  }
  return { file: abs, dir: path.dirname(abs), config };
}
