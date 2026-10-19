// Pomiar recall reguł ujść na drugim zbiorze CVE (data/cves-extra.json): wysyłanie plików, odczyt i usuwanie
// plików, SSRF, eskalacja uprawnień, obejście logowania, aktualizacja opcji i RCE. Skanuje każdą podatną wersję
// raz, w trybie rozszerzonym, i liczy trafienia dwa razy: tylko regułami, które istniały przed nowymi
// (kolumna before), i wszystkimi (kolumna after). Zestaw reguł dla każdej klasy jest ustalony niżej, przed
// pomiarem, i nie zmienia się po obejrzeniu wyników.
// Użycie: node benchmark/recall-extra.mjs --lib dist/index.js --out results/current-recall-extra.json [--window 25] [--data cves-extra.json]
// --data wskazuje plik w katalogu data/. Inny zbiór, na przykład ślepy, mierzy się tym samym skryptem.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { args, CACHE, download, extract, here, loadScanner, RESULTS } from './common.mjs';
import { enclosingRange } from './function-range.mjs';

const opt = args({
  lib: { type: 'string', default: 'dist/index.js' },
  out: { type: 'string', default: join(RESULTS, 'current-recall-extra.json') },
  data: { type: 'string', default: 'cves-extra.json' },
  window: { type: 'string', default: '25' },
});
const scan = await loadScanner(opt.lib);
const WINDOW = Number(opt.window);
const cves = JSON.parse(readFileSync(join(here, 'data', basename(opt.data)), 'utf8'));

const AUTHZ = ['wp.auth.unprotected_action', 'wp.rest.no_permission_callback'];

// Które reguły liczą się jako trafienie w danej klasie. existing to reguły sprzed nowej rodziny, added to nowe.
// Klasy other i redirect pomijamy, bo żadna reguła nie ma ich pokrywać.
const RULES = {
  upload: { existing: [], added: ['wp.upload.unrestricted', 'wp.file.path_traversal'] },
  file_read: { existing: [], added: ['wp.file.path_traversal'] },
  file_delete: { existing: [], added: ['wp.file.path_traversal'] },
  ssrf: { existing: [], added: ['wp.http.ssrf'] },
  rce: { existing: ['wp.rce.dynamic'], added: [] },
  privesc: { existing: AUTHZ, added: ['wp.privilege.escalation', 'wp.option.arbitrary_update'] },
  authbypass: { existing: AUTHZ, added: ['wp.privilege.escalation'] },
  option_update: { existing: [], added: ['wp.option.arbitrary_update'] },
};

// Jedna pozycja na parę (wtyczka, wersja).
const jobs = new Map();
for (const c of cves) {
  if (!RULES[c.cls]) continue;
  for (const h of c.hits) {
    const key = `${h.slug}@${h.version}`;
    if (!jobs.has(key)) jobs.set(key, { slug: h.slug, version: h.version, cves: [] });
    jobs.get(key).cves.push({ id: c.id, cls: c.cls, file: h.file, line: h.line });
  }
}
const list = [...jobs.values()];
console.log(`Plugin versions: ${list.length}`);

const rows = [];
for (const job of list) {
  const zip = join(CACHE, 'extra-zips', `${job.slug}.${job.version}.zip`);
  const dir = join(CACHE, 'extra-src', `${job.slug}-${job.version}`);
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
    result = await scan(dir, { cwd: dir, extended: true });
  } catch (e) {
    rows.push({ ...job, status: 'scan failed: ' + String(e.message).slice(0, 80) });
    continue;
  }
  const perCve = job.cves.map((c) => {
    const wanted = `${job.slug}/${c.file}`.toLowerCase();
    const inFile = result.findings.filter((f) => f.file.toLowerCase() === wanted);
    const range = enclosingRange(join(dir, job.slug, c.file), c.line);
    const hit = (rules) => {
      const near = inFile.some((f) => Math.abs(f.line - c.line) <= WINDOW && rules.includes(f.ruleId));
      const func = near || (range !== undefined && inFile.some((f) => f.line >= range[0] && f.line <= range[1] && rules.includes(f.ruleId)));
      return { near, func, file: inFile.some((f) => rules.includes(f.ruleId)) };
    };
    const before = hit(RULES[c.cls].existing);
    const after = hit([...RULES[c.cls].existing, ...RULES[c.cls].added]);
    return {
      id: c.id,
      cls: c.cls,
      file: c.file,
      line: c.line,
      fileFound: existsSync(join(dir, job.slug, c.file)),
      nearBefore: before.near,
      funcBefore: before.func,
      fileBefore: before.file,
      nearAfter: after.near,
      funcAfter: after.func,
      fileAfter: after.file,
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
    if (!prev) uniq.set(key, { ...c });
    else
      for (const k of ['nearBefore', 'funcBefore', 'fileBefore', 'nearAfter', 'funcAfter', 'fileAfter']) prev[k] ||= c[k];
  }
}
const byCls = {};
const total = { pairs: 0, nearBefore: 0, nearAfter: 0, funcBefore: 0, funcAfter: 0, fileBefore: 0, fileAfter: 0 };
for (const v of uniq.values()) {
  const b = (byCls[v.cls] ??= { pairs: 0, nearBefore: 0, nearAfter: 0, funcBefore: 0, funcAfter: 0, fileBefore: 0, fileAfter: 0 });
  for (const t of [b, total]) {
    t.pairs++;
    for (const k of ['nearBefore', 'nearAfter', 'funcBefore', 'funcAfter', 'fileBefore', 'fileAfter']) if (v[k]) t[k]++;
  }
}
const failed = rows.filter((r) => r.status !== 'ok').length;
console.log(`Unique (CVE, plugin, version) pairs: ${uniq.size}. Versions that could not be scanned: ${failed}.`);
console.table(byCls);
const pct = (n) => `${n} of ${total.pairs} (${((100 * n) / total.pairs).toFixed(1)}%)`;
console.log(`near: before ${pct(total.nearBefore)}, after ${pct(total.nearAfter)}`);
console.log(`func: before ${pct(total.funcBefore)}, after ${pct(total.funcAfter)}`);
console.log(`file: before ${pct(total.fileBefore)}, after ${pct(total.fileAfter)}`);
console.log(`Saved ${out}`);
