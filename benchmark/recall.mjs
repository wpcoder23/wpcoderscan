// Pomiar recall na zbiorze CVE: pobiera podatne wersje wtyczek z wordpress.org, skanuje je (tylko czytanie
// i parsowanie) i sprawdza, czy skaner zgłasza błąd tej samej klasy w pliku i blisko linii z odnośnika CVE.
// Liczy trzy trafienia: near (okno wokół linii CVE), func (okno albo cała funkcja, w której leży linia CVE)
// i file (gdziekolwiek w pliku). Zawsze near <= func <= file.
// Użycie: node benchmark/recall.mjs --lib dist/index.js --out results/current-recall.json [--extended] [--max 1000] [--data cves.json]
// --data wskazuje plik w katalogu data/. Inny zbiór, na przykład ślepy, mierzy się tym samym skryptem.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { args, CACHE, download, extract, here, loadScanner, RESULTS, RULES_FOR } from './common.mjs';
import { enclosingRange } from './function-range.mjs';

const opt = args({
  lib: { type: 'string', default: 'dist/index.js' },
  out: { type: 'string', default: join(RESULTS, 'current-recall.json') },
  data: { type: 'string', default: 'cves.json' },
  extended: { type: 'boolean', default: false },
  max: { type: 'string', default: '1000' },
  window: { type: 'string', default: '25' },
});
const scan = await loadScanner(opt.lib);
const WINDOW = Number(opt.window);
const cves = JSON.parse(readFileSync(join(here, 'data', basename(opt.data)), 'utf8'));

// Jedna pozycja na parę (wtyczka, wersja). Stored XSS jest w NVD najliczniejszy i najtrudniejszy dla skanera
// statycznego, więc bierzemy z niego pierwsze 80 wpisów, żeby nie przykrył innych klas. CSRF i klasy
// spoza listy pomijamy.
const jobs = new Map();
let storedLeft = 80;
for (const c of cves) {
  const cls = c.cls;
  if (cls === 'other' || cls === 'csrf') continue;
  if (cls === 'xss_stored' && storedLeft-- <= 0) continue;
  for (const h of c.hits) {
    const key = `${h.slug}@${h.version}`;
    if (!jobs.has(key)) jobs.set(key, { slug: h.slug, version: h.version, cves: [] });
    jobs.get(key).cves.push({ id: c.id, cls, file: h.file, line: h.line });
  }
}
const list = [...jobs.values()].slice(0, Number(opt.max));
console.log(`Plugin versions: ${list.length}`);

const rows = [];
for (const job of list) {
  const zip = join(CACHE, 'recall-zips', `${job.slug}.${job.version}.zip`);
  const dir = join(CACHE, 'recall-src', `${job.slug}-${job.version}`);
  if (!existsSync(dir)) {
    const ok = await download(`https://downloads.wordpress.org/plugin/${job.slug}.${job.version}.zip`, zip);
    if (!ok) {
      rows.push({ ...job, status: 'download failed' });
      continue;
    }
    if (!extract(zip, dir)) {
      rows.push({ ...job, status: 'unpack failed' });
      continue;
    }
  }
  let result;
  try {
    result = await scan(dir, { cwd: dir, extended: opt.extended });
  } catch (e) {
    rows.push({ ...job, status: 'scan failed: ' + String(e.message).slice(0, 80) });
    continue;
  }
  const perCve = job.cves.map((c) => {
    const wanted = `${job.slug}/${c.file}`.toLowerCase();
    const inFile = result.findings.filter((f) => f.file.toLowerCase() === wanted);
    const rules = RULES_FOR[c.cls] ?? [];
    const near = inFile.some((f) => Math.abs(f.line - c.line) <= WINDOW && rules.includes(f.ruleId));
    const range = enclosingRange(join(dir, job.slug, c.file), c.line);
    const func = near || (range !== undefined && inFile.some((f) => f.line >= range[0] && f.line <= range[1] && rules.includes(f.ruleId)));
    return {
      id: c.id,
      cls: c.cls,
      file: c.file,
      line: c.line,
      fileFound: existsSync(join(dir, job.slug, c.file)),
      nearClass: near,
      funcClass: func,
      fileClass: inFile.some((f) => rules.includes(f.ruleId)),
    };
  });
  rows.push({ slug: job.slug, version: job.version, status: 'ok', files: result.filesScanned, total: result.findings.length, cves: perCve });
}
const out = resolve(opt.out);
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(rows));

// Podsumowanie po unikalnych parach (CVE, wtyczka, wersja).
const uniq = new Map();
for (const r of rows) {
  if (r.status !== 'ok') continue;
  for (const c of r.cves) {
    const key = `${c.id}|${r.slug}|${r.version}`;
    const prev = uniq.get(key);
    if (!prev) uniq.set(key, { cls: c.cls, near: c.nearClass, func: c.funcClass, file: c.fileClass });
    else {
      prev.near ||= c.nearClass;
      prev.func ||= c.funcClass;
      prev.file ||= c.fileClass;
    }
  }
}
const byCls = {};
for (const v of uniq.values()) {
  const b = (byCls[v.cls] ??= { pairs: 0, near: 0, func: 0, file: 0 });
  b.pairs++;
  if (v.near) b.near++;
  if (v.func) b.func++;
  if (v.file) b.file++;
}
const failed = rows.filter((r) => r.status !== 'ok').length;
console.log(`Unique (CVE, plugin, version) pairs: ${uniq.size}. Versions that could not be scanned: ${failed}.`);
console.table(byCls);
const near = [...uniq.values()].filter((v) => v.near).length;
const func = [...uniq.values()].filter((v) => v.func).length;
const file = [...uniq.values()].filter((v) => v.file).length;
console.log(`near: ${near} of ${uniq.size} (${((100 * near) / uniq.size).toFixed(1)}%), file: ${file} of ${uniq.size} (${((100 * file) / uniq.size).toFixed(1)}%)`);
console.log(`func: ${func} of ${uniq.size} (${((100 * func) / uniq.size).toFixed(1)}%)`);
console.log(`Saved ${out}`);
