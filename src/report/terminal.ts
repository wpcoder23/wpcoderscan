// Raport w terminalu. Bez zależności, kolory przez kody ANSI.
import type { ScanResult } from '../engine';
import { previewPatch, readSource } from '../fix/suggest';
import type { Severity } from '../rules/types';

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  green: '\x1b[32m',
  gray: '\x1b[90m',
};

const useColor = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
function c(code: string, s: string): string {
  return useColor ? code + s + C.reset : s;
}

const LABEL: Record<Severity, string> = {
  critical: 'KRYTYCZNE',
  high: 'WYSOKIE',
  medium: 'ŚREDNIE',
  low: 'NISKIE',
  info: 'INFO',
};

function sevColor(s: Severity): string {
  if (s === 'critical' || s === 'high') return C.red;
  if (s === 'medium') return C.yellow;
  return C.blue;
}

export interface TerminalOptions {
  suggest?: boolean; // pokaż podgląd podpowiedzi napraw przy znaleziskach
  cwd?: string; // do odczytu plików przy podglądzie
}

export function renderTerminal(r: ScanResult, opts: TerminalOptions = {}): string {
  const out: string[] = [];
  const cwd = opts.cwd ?? process.cwd();
  const sources = new Map<string, string | null>();
  const source = (file: string): string | null => {
    if (!sources.has(file)) sources.set(file, readSource(cwd, file));
    return sources.get(file) ?? null;
  };
  out.push('');
  out.push(c(C.bold, `WPCoderScan  skan: ${r.target}`));
  out.push(c(C.gray, `plików: ${r.filesScanned}, znalezisk: ${r.findings.length}`));
  out.push('');

  for (const f of r.findings) {
    const tag = c(sevColor(f.severity) + C.bold, LABEL[f.severity].padEnd(9));
    const conf = f.confidence === 'heuristic' ? c(C.gray, '  heurystyka') : '';
    out.push(`${tag} ${c(C.bold, f.ruleId)}${conf}`);
    out.push(`  ${f.file}:${f.line}:${f.column}`);
    out.push(`  ${f.message}`);
    if (f.snippet) out.push(c(C.gray, `    ${f.snippet}`));
    if (f.fix) out.push(c(C.green, `    naprawa: ${f.fix}`));
    if (opts.suggest && f.patch) {
      const note = f.patch.safety === 'manual' ? ' (do decyzji)' : '';
      out.push(c(C.green, `    podpowiedź${note}: ${f.patch.label}`));
      const code = source(f.file);
      for (const line of code ? previewPatch(code, f.patch) : []) {
        out.push(c(line.startsWith('-') ? C.red : C.green, `      ${line}`));
      }
    }
    out.push('');
  }

  const s = r.score;
  out.push(c(C.bold, `Wynik: ${s.value}/100`));
  out.push(
    `${c(C.red, `krytyczne ${s.counts.critical}`)}   ${c(C.red, `wysokie ${s.counts.high}`)}   ` +
      `${c(C.yellow, `średnie ${s.counts.medium}`)}   ${c(C.blue, `niskie ${s.counts.low}`)}`,
  );

  if (r.errors.length) {
    out.push('');
    out.push(c(C.gray, `błędy skanera: ${r.errors.length}`));
    for (const e of r.errors) out.push(c(C.gray, `  ${e.file}: ${e.message}`));
  }

  const withPatch = r.findings.filter((f) => f.patch).length;
  if (withPatch > 0 && !opts.suggest) {
    out.push('');
    out.push(c(C.gray, `podpowiedzi napraw: ${withPatch} (pokaż je opcją --suggest)`));
  }

  out.push('');
  return out.join('\n');
}
