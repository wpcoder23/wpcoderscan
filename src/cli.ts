#!/usr/bin/env node
// Wejście CLI dla WPCoderScan.
import { scan, type ScanOptions, type ScanResult } from './index';
import { renderTerminal } from './report/terminal';
import { renderSarif } from './report/sarif';
import { buildPatchFile } from './fix/suggest';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { gitChangedPhpFiles } from './collector/git';
import { parseArgs, parseFailOn, resolveLanguage, SEVERITY_ORDER, UsageError } from './cli-options';
import { discoverConfig, loadConfig, type Config, type LoadedConfig } from './config';
import { createBaseline, parseBaseline, serializeBaseline, type Baseline } from './engine/baseline';
import { matchesPattern } from './engine/suppress';
import { allRules, extendedRules } from './rules';
import { createTranslator, DEFAULT_LANG, parseLang } from './i18n';
import { VERSION } from './version';

// Tłumacz dla błędów zgłaszanych na końcu. Po wyborze języka zostaje podmieniony.
let t = createTranslator(DEFAULT_LANG);

// Ścieżka do komunikatu. Plik z bieżącego katalogu pokazujemy względnie.
function displayPath(cwd: string, file: string): string {
  const rel = path.relative(cwd, file);
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel.split(path.sep).join('/') : file;
}

function warn(message: string): void {
  process.stderr.write(`${t('cli.warning', { message })}\n`);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.version) {
    process.stdout.write(`${VERSION}\n`);
    process.exit(0);
  }

  const envLang = process.env.WPCODERSCAN_LANG;
  const resolved = resolveLanguage(args.lang, envLang);
  if (resolved.warning) process.stderr.write(`${resolved.warning}\n`);
  let lang = resolved.lang;
  t = createTranslator(lang);

  if (args.help || (!args.target && args.diff === null)) {
    process.stdout.write(t('cli.help'));
    process.exit(args.help ? 0 : 1);
  }
  if (args.missingValue) throw new UsageError(t('cli.missingValue', { option: args.missingValue }));
  if (args.writeBaseline !== null && args.diff !== null) throw new UsageError(t('cli.baselineDiff'));

  // Plik ustawień czytamy tylko z bieżącego katalogu albo ze wskazanej ścieżki, nigdy ze skanowanego kodu.
  const cwd = process.cwd();
  let loaded: LoadedConfig | null = null;
  if (!args.noConfig) {
    const file = args.config ?? discoverConfig(cwd);
    if (file) loaded = loadConfig(file, t);
  }
  const config: Config = loaded?.config ?? {};
  const configName = loaded ? displayPath(cwd, loaded.file) : '';

  // Kolejność ustawień: flaga, zmienna środowiskowa, plik ustawień, wartość domyślna.
  if (config.lang !== undefined && args.lang === null && !envLang?.trim()) {
    lang = parseLang(config.lang) ?? lang;
    t = createTranslator(lang);
  }
  if (loaded) process.stderr.write(`${t('config.using', { file: configName })}\n`);
  const failOn = parseFailOn(args.failOn ?? config.failOn ?? 'high', t);
  const strict = args.strict || config.strict === true;
  const extended = args.extended || config.extended === true;

  const disabledRules = Object.keys(config.rules ?? {});
  const knownRuleIds = [...allRules, ...extendedRules].map((r) => r.id);
  for (const pattern of disabledRules) {
    if (!knownRuleIds.some((id) => matchesPattern(pattern, id))) {
      warn(t('config.unknownRule', { file: configName, rule: pattern }));
    }
  }

  // Zapis baseline zawsze liczy od zera, więc wtedy istniejącego baseline nie wczytujemy.
  let baseline: Baseline | undefined;
  if (args.writeBaseline === null) {
    const baselineFile =
      args.baseline !== null
        ? path.resolve(cwd, args.baseline)
        : loaded && config.baseline
          ? path.resolve(loaded.dir, config.baseline)
          : null;
    if (baselineFile) {
      if (!existsSync(baselineFile)) throw new UsageError(t('baseline.notFound', { file: displayPath(cwd, baselineFile) }));
      baseline = parseBaseline(readFileSync(baselineFile, 'utf8').replace(/^﻿/, ''), t);
    }
  }

  const options: ScanOptions = {
    cwd,
    extended,
    lang,
    exclude: config.exclude,
    excludeBase: loaded?.dir,
    disabledRules,
    ignoreComments: !args.noIgnoreComments && config.ignoreComments !== false,
    baseline,
  };
  let result: ScanResult;
  if (args.diff !== null) {
    // Tryb diff: skanujemy tylko pliki PHP zmienione wobec ref gita.
    const files = gitChangedPhpFiles(args.diff, cwd, t);
    result = await scan(`diff:${args.diff}`, { ...options, files });
  } else {
    result = await scan(args.target, options);
  }

  if (args.writeBaseline !== null) {
    writeFileSync(path.resolve(cwd, args.writeBaseline), serializeBaseline(createBaseline(result.findings)), 'utf8');
    process.stderr.write(`${t('baseline.saved', { file: args.writeBaseline, count: result.findings.length })}\n`);
    process.exit(0);
  }

  if (args.sarif) {
    process.stdout.write(renderSarif(result));
  } else if (args.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(renderTerminal(result, { suggest: args.suggest, cwd }));
  }

  if (args.patch !== null) {
    const built = buildPatchFile(result, cwd);
    if (built.patches === 0) {
      process.stderr.write(`${t('cli.patch.none')}\n`);
    } else {
      writeFileSync(args.patch, built.diff, 'utf8');
      process.stderr.write(
        `${t('cli.patch.saved', { file: args.patch, patches: built.patches, files: built.files })}\n` +
          `${t('cli.patch.apply', { file: args.patch })}\n`,
      );
    }
    if (built.manual > 0) {
      process.stderr.write(`${t('cli.patch.manual', { count: built.manual })}\n`);
    }
  }

  if (failOn !== 'none') {
    const threshold = SEVERITY_ORDER.indexOf(failOn);
    const fail = result.findings.some(
      (f) =>
        SEVERITY_ORDER.indexOf(f.severity) <= threshold &&
        (strict || f.confidence === 'firm'),
    );
    process.exit(fail ? 1 : 0);
  }
  process.exit(0);
}

main().catch((e: unknown) => {
  process.stderr.write(`${t('cli.error', { message: (e as Error).message })}\n`);
  process.exit(2);
});
