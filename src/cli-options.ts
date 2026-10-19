// Argumenty CLI i wybór języka. Osobno od cli.ts, bo cli.ts uruchamia się przy imporcie.
import { LANGS, parseLang, type Lang, type Translate } from './i18n';
import type { Severity } from './rules/types';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export interface Args {
  target: string;
  json: boolean;
  sarif: boolean;
  failOn: string;
  strict: boolean;
  diff: string | null;
  suggest: boolean;
  extended: boolean;
  patch: string | null;
  lang: string | null;
  help: boolean;
  version: boolean;
}

// Błąd użycia (zły argument). CLI kończy się z kodem 2.
export class UsageError extends Error {}

export function parseArgs(argv: string[]): Args {
  const args: Args = {
    target: '',
    json: false,
    sarif: false,
    failOn: 'high',
    strict: false,
    diff: null,
    suggest: false,
    extended: false,
    patch: null,
    lang: null,
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a === '--sarif') args.sarif = true;
    else if (a === '--strict') args.strict = true;
    else if (a === '--suggest') args.suggest = true;
    else if (a === '--extended') args.extended = true;
    else if (a === '--patch') args.patch = argv[++i] ?? null;
    else if (a === '--lang') args.lang = argv[++i] ?? '';
    else if (a.startsWith('--lang=')) args.lang = a.slice('--lang='.length);
    else if (a === '--help' || a === '-h') args.help = true;
    else if (a === '--version' || a === '-v') args.version = true;
    else if (a === '--fail-on') args.failOn = argv[++i] ?? 'high';
    else if (a === '--diff') args.diff = argv[++i] ?? 'HEAD';
    else if (!a.startsWith('-') && !args.target) args.target = a;
  }
  return args;
}

export interface ResolvedLanguage {
  lang: Lang;
  warning: string | null;
}

// Kolejność: flaga --lang, potem zmienna WPCODERSCAN_LANG, potem angielski.
// Zła wartość flagi to błąd. Zła wartość zmiennej tylko ostrzega, bo zmienna
// bywa ustawiona globalnie i nie powinna psuć CI. Oba komunikaty są po angielsku,
// bo język nie jest jeszcze wybrany.
export function resolveLanguage(explicit: string | null, env: string | undefined): ResolvedLanguage {
  const supported = LANGS.join(', ');
  if (explicit !== null) {
    const lang = parseLang(explicit);
    if (!lang) throw new UsageError(`unknown language "${explicit}", supported languages: ${supported}`);
    return { lang, warning: null };
  }
  if (env && env.trim()) {
    const lang = parseLang(env);
    if (lang) return { lang, warning: null };
    return {
      lang: 'en',
      warning: `warning: ignoring WPCODERSCAN_LANG="${env}", supported languages: ${supported}. Using English.`,
    };
  }
  return { lang: 'en', warning: null };
}

// Poziom dla --fail-on. Nieznana wartość to błąd, bo po cichu wyłączałaby bramkę CI.
export function parseFailOn(value: string, t: Translate): Severity | 'none' {
  if (value === 'none') return 'none';
  if ((SEVERITY_ORDER as string[]).includes(value)) return value as Severity;
  throw new UsageError(t('cli.badFailOn', { value }));
}
