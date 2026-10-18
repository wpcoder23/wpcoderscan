#!/usr/bin/env node
// Wejście CLI dla WPCoderScaner.
import { scan, type ScanResult } from './index';
import { renderTerminal } from './report/terminal';
import { renderSarif } from './report/sarif';
import { gitChangedPhpFiles } from './collector/git';
import type { Severity } from './rules/types';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

interface Args {
  target: string;
  json: boolean;
  sarif: boolean;
  failOn: Severity | 'none';
  strict: boolean;
  diff: string | null;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    target: '',
    json: false,
    sarif: false,
    failOn: 'high',
    strict: false,
    diff: null,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a === '--sarif') args.sarif = true;
    else if (a === '--strict') args.strict = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else if (a === '--fail-on') args.failOn = (argv[++i] as Severity) ?? 'high';
    else if (a === '--diff') args.diff = argv[++i] ?? 'HEAD';
    else if (!a.startsWith('-') && !args.target) args.target = a;
  }
  return args;
}

const HELP = `WPCoderScaner - skaner bezpieczeństwa kodu WordPress i PHP

Użycie:
  wpcs <ścieżka> [opcje]
  wpcoderscaner <ścieżka> [opcje]

Opcje:
  --json              wypisz wynik jako JSON
  --sarif             wypisz wynik jako SARIF 2.1.0 (do zakładki Security GitHuba)
  --fail-on <poziom>  kod wyjścia 1, gdy jest znalezisko tego poziomu lub cięższe
                      (critical, high, medium, low, none; domyślnie high)
  --strict            licz też znaleziska heurystyczne do kodu wyjścia
                      (domyślnie build łamią tylko znaleziska pewne)
  --diff <ref>        skanuj tylko pliki PHP zmienione wobec ref gita
                      (domyślnie HEAD; szybki skan dla pull requestów)
  -h, --help          ta pomoc
`;

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || (!args.target && args.diff === null)) {
    process.stdout.write(HELP);
    process.exit(args.help ? 0 : 1);
  }

  const cwd = process.cwd();
  let result: ScanResult;
  if (args.diff !== null) {
    // Tryb diff: skanujemy tylko pliki PHP zmienione wobec ref gita.
    const files = gitChangedPhpFiles(args.diff, cwd);
    result = await scan(`diff:${args.diff}`, { cwd, files });
  } else {
    result = await scan(args.target, { cwd });
  }

  if (args.sarif) {
    process.stdout.write(renderSarif(result));
  } else if (args.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(renderTerminal(result));
  }

  if (args.failOn !== 'none') {
    const threshold = SEVERITY_ORDER.indexOf(args.failOn);
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
  process.stderr.write(`błąd: ${(e as Error).message}\n`);
  process.exit(2);
});
