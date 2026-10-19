#!/usr/bin/env node
// Wejście CLI dla WPCoderScan.
import { scan, type ScanResult } from './index';
import { renderTerminal } from './report/terminal';
import { renderSarif } from './report/sarif';
import { buildPatchFile } from './fix/suggest';
import { writeFileSync } from 'node:fs';
import { gitChangedPhpFiles } from './collector/git';
import { parseArgs, parseFailOn, resolveLanguage, SEVERITY_ORDER } from './cli-options';
import { createTranslator, DEFAULT_LANG } from './i18n';
import { VERSION } from './version';

// Tłumacz dla błędów zgłaszanych na końcu. Po wyborze języka zostaje podmieniony.
let t = createTranslator(DEFAULT_LANG);

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.version) {
    process.stdout.write(`${VERSION}\n`);
    process.exit(0);
  }

  const resolved = resolveLanguage(args.lang, process.env.WPCODERSCAN_LANG);
  if (resolved.warning) process.stderr.write(`${resolved.warning}\n`);
  const lang = resolved.lang;
  t = createTranslator(lang);

  if (args.help || (!args.target && args.diff === null)) {
    process.stdout.write(t('cli.help'));
    process.exit(args.help ? 0 : 1);
  }
  const failOn = parseFailOn(args.failOn, t);

  const cwd = process.cwd();
  let result: ScanResult;
  if (args.diff !== null) {
    // Tryb diff: skanujemy tylko pliki PHP zmienione wobec ref gita.
    const files = gitChangedPhpFiles(args.diff, cwd, t);
    result = await scan(`diff:${args.diff}`, { cwd, files, extended: args.extended, lang });
  } else {
    result = await scan(args.target, { cwd, extended: args.extended, lang });
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
        (args.strict || f.confidence === 'firm'),
    );
    process.exit(fail ? 1 : 0);
  }
  process.exit(0);
}

main().catch((e: unknown) => {
  process.stderr.write(`${t('cli.error', { message: (e as Error).message })}\n`);
  process.exit(2);
});
