// Skanuje wtyczki napisane przez model AI na podstawie krótkich próśb klienta (benchmark/ai-code/prompts.json).
// Skanujemy zamrożoną wersją skanera, a prawda o podatnościach leży w osobnym pliku ground-truth.json, spisanym
// przed pierwszym skanem. Skrypt niczego nie uruchamia z kodu wtyczek, tylko go parsuje.
// Użycie: node benchmark/ai-code/scan.mjs --lib dist/index.js --set sonnet-neutral --label v081 [--extended]
import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { args, loadScanner } from '../common.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const opt = args({
  lib: { type: 'string', default: 'dist/index.js' },
  set: { type: 'string', default: 'sonnet-neutral' },
  label: { type: 'string', default: 'v081' },
  extended: { type: 'boolean', default: false },
});
const scan = await loadScanner(opt.lib);
const root = join(here, 'plugins', opt.set);
if (!existsSync(root)) {
  console.error(`Brak katalogu ${root}`);
  process.exit(2);
}

const rows = [];
for (const slug of readdirSync(root).sort()) {
  const dir = join(root, slug);
  if (!statSync(dir).isDirectory()) continue;
  const r = await scan(dir, { cwd: dir, extended: opt.extended });
  rows.push({
    slug,
    files: r.filesScanned,
    errors: r.errors?.length ?? 0,
    findings: r.findings.map((f) => ({
      rule: f.ruleId,
      sev: f.severity,
      conf: f.confidence,
      file: f.file,
      line: f.line,
      msg: f.message.slice(0, 240),
    })),
  });
}

const out = join(here, 'results', `${opt.set}-${opt.label}${opt.extended ? '-extended' : ''}.json`);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(rows, null, 1));
const total = rows.reduce((a, r) => a + r.findings.length, 0);
console.log(`Wtyczki: ${rows.length}, pliki: ${rows.reduce((a, r) => a + r.files, 0)}, znaleziska: ${total}, błędy: ${rows.reduce((a, r) => a + r.errors, 0)}`);
console.log(`Zapisano ${resolve(out)}`);
