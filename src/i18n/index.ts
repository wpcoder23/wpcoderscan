// Tłumaczenia komunikatów. Język wyjścia wybiera wywołujący (CLI: --lang albo
// zmienna WPCODERSCAN_LANG). Biblioteka nie czyta środowiska, domyślnie mówi po angielsku.
import { en, type MessageKey } from './en';
import { pl } from './pl';

export type { MessageKey };
export type Lang = 'en' | 'pl';
export type Params = Record<string, string | number>;
export type Translate = (key: MessageKey, params?: Params) => string;

export const LANGS: readonly Lang[] = ['en', 'pl'];
export const DEFAULT_LANG: Lang = 'en';

const CATALOGS: Record<Lang, Record<MessageKey, string>> = { en, pl };

// Podstawia {nazwa} wartościami z params. Brakujący parametr zostaje w tekście
// jak jest, żeby błąd był widoczny w wyniku i w teście.
export function format(template: string, params?: Params): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (whole, name: string) => {
    const value = params[name];
    return value === undefined ? whole : String(value);
  });
}

export function createTranslator(lang: Lang): Translate {
  const catalog = CATALOGS[lang] ?? CATALOGS[DEFAULT_LANG];
  return (key, params) => format(catalog[key], params);
}

// Rozpoznaje język z tekstu, także z nazwy ustawień regionalnych: "pl", "pl_PL", "en-US", "en_GB.UTF-8".
export function parseLang(value: string | null | undefined): Lang | null {
  if (!value) return null;
  const base = value.trim().toLowerCase().split(/[-_.@]/)[0];
  return LANGS.find((l) => l === base) ?? null;
}

// Zmienne klamrowe użyte w szablonie, do kontroli zgodności katalogów w testach.
export function placeholders(template: string): string[] {
  return [...new Set([...template.matchAll(/\{(\w+)\}/g)].map((m) => m[1]))].sort();
}

export function catalogOf(lang: Lang): Readonly<Record<MessageKey, string>> {
  return CATALOGS[lang];
}
