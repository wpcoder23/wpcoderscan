// Pomiar szumu: skanuje najpopularniejsze darmowe wtyczki z wordpress.org (kod publiczny, tylko czytanie
// i parsowanie) i liczy znaleziska na wtyczkę. To nie jest współczynnik fałszywych alarmów, bo nie wiemy,
// które z wykryć są prawdziwe. To miara tego, jak bardzo skaner hałasuje na kodzie, który powszechnie działa.
// Użycie: node benchmark/noise.mjs --lib dist/index.js --out results/current-noise.json [--list data/popular.json] [--live]
// Domyślnie czyta zamrożoną listę z data/popular.json. Lista popularnych wtyczek się zmienia, więc do porównań
// między wersjami skanera używaj tej samej listy z pliku. Z --live pobiera aktualną listę z API wordpress.org.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { args, CACHE, download, extract, here, loadScanner, RESULTS } from './common.mjs';

const opt = args({
  lib: { type: 'string', default: 'dist/index.js' },
  out: { type: 'string', default: join(RESULTS, 'current-noise.json') },
  list: { type: 'string', default: join(here, 'data', 'popular.json') },
  extended: { type: 'boolean', default: false },
  count: { type: 'string', default: '200' },
  live: { type: 'boolean', default: false },
});
const scan = await loadScanner(opt.lib);

// Lista: z pliku (powtarzalna) albo z API wordpress.org (aktualna).
let plugins = [];
if (!opt.live && existsSync(opt.list)) {
  plugins = JSON.parse(readFileSync(opt.list, 'utf8'));
} else {
  for (let page = 1; plugins.length < Number(opt.count); page++) {
    const res = await fetch(
      'https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[browse]=popular&request[per_page]=100&request[page]=' + page,
      { signal: AbortSignal.timeout(60000) },
    );
    if (res.status !== 200) break;
    const data = await res.json();
    if (!data.plugins?.length) break;
    for (const p of data.plugins) plugins.push({ slug: p.slug, version: p.version, installs: p.active_installs });
  }
}
plugins = plugins.slice(0, Number(opt.count));
console.log(`Plugins: ${plugins.length}`);

const rows = [];
let files = 0;
let errors = 0;
for (const p of plugins) {
  const zip = join(CACHE, 'noise-zips', `${p.slug}.${p.version}.zip`);
  const dir = join(CACHE, 'noise-src', `${p.slug}-${p.version}`);
  if (!existsSync(dir)) {
    const ok = await download(`https://downloads.wordpress.org/plugin/${p.slug}.${p.version}.zip`, zip);
    if (!ok || !extract(zip, dir)) {
      rows.push({ slug: p.slug, version: p.version, error: 'download or unpack failed', findings: [] });
      continue;
    }
  }
  try {
    const r = await scan(dir, { cwd: dir, extended: opt.extended });
    files += r.filesScanned;
    errors += r.errors?.length ?? 0;
    rows.push({
      slug: p.slug,
      version: p.version,
      files: r.filesScanned,
      errors: r.errors?.length ?? 0,
      findings: r.findings.map((f) => ({ rule: f.ruleId, conf: f.confidence, sev: f.severity, file: f.file, line: f.line, msg: f.message.slice(0, 160) })),
    });
  } catch (e) {
    rows.push({ slug: p.slug, version: p.version, error: String(e.message).slice(0, 100), findings: [] });
  }
}
const out = resolve(opt.out);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(rows));

const scanned = rows.filter((r) => !r.error);
const counts = scanned.map((r) => r.findings.length).sort((a, b) => a - b);
const pct = (p) => counts[Math.min(counts.length - 1, Math.floor((p / 100) * counts.length))];
const byRule = {};
const pluginsByRule = {};
for (const r of scanned) {
  const seen = new Set();
  for (const f of r.findings) {
    const k = `${f.rule} (${f.conf})`;
    byRule[k] = (byRule[k] ?? 0) + 1;
    if (!seen.has(k)) {
      seen.add(k);
      pluginsByRule[k] = (pluginsByRule[k] ?? 0) + 1;
    }
  }
}
console.log(`Scanned plugins: ${scanned.length} of ${rows.length}, PHP files: ${files}, scanner errors: ${errors}`);
console.log(`Without findings: ${counts.filter((c) => c === 0).length}, total findings: ${counts.reduce((a, b) => a + b, 0)}, median per plugin: ${pct(50)}, p90: ${pct(90)}`);
for (const k of Object.keys(byRule).sort()) console.log(`${k}: ${byRule[k]} findings in ${pluginsByRule[k]} plugins`);
console.log(`Saved ${out}`);
