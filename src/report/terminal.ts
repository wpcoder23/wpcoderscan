// Raport w terminalu. Bez zależności, kolory przez kody ANSI.
import type { ScanResult } from '../engine';
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

export function renderTerminal(r: ScanResult): string {
  const out: string[] = [];
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

  out.push('');
  return out.join('\n');
}
