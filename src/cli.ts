#!/usr/bin/env node
// Wejście CLI dla WPCoderScaner.
import { scan } from './index';
import { renderTerminal } from './report/terminal';
import type { Severity } from './rules/types';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

interface Args {
  target: string;
  json: boolean;
  failOn: Severity | 'none';
  strict: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { target: '', json: false, failOn: 'high', strict: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a === '--strict') args.strict = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else if (a === '--fail-on') args.failOn = (argv[++i] as Severity) ?? 'high';
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
  --fail-on <poziom>  kod wyjścia 1, gdy jest znalezisko tego poziomu lub cięższe
                      (critical, high, medium, low, none; domyślnie high)
  --strict            licz też znaleziska heurystyczne do kodu wyjścia
                      (domyślnie build łamią tylko znaleziska pewne)
  -h, --help          ta pomoc
`;

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.target) {
    process.stdout.write(HELP);
    process.exit(args.help ? 0 : 1);
  }

  const result = await scan(args.target, { cwd: process.cwd() });

  if (args.json) {
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
