// Porównanie dwóch pomiarów (recall na zbiorze CVE i szum na popularnych wtyczkach).
// Użycie: node benchmark/compare.mjs --base base --cand current [--new]
// Etykieta to przedrostek plików w benchmark/results, na przykład base-recall.json, base-recall-extended.json
// i base-noise.json. Pliki powstają po node benchmark/run.mjs --label <etykieta>.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { args, RESULTS } from './common.mjs';

const opt = args({ base: { type: 'string' }, cand: { type: 'string' }, new: { type: 'boolean', default: false } });
if (!opt.base || !opt.cand) {
  console.error('Usage: node benchmark/compare.mjs --base <label> --cand <label> [--new]');
  process.exit(2);
}
const file = (label, kind) => join(RESULTS, `${label}-${kind}.json`);
const read = (path) => JSON.parse(readFileSync(path, 'utf8'));

function recall(path) {
  const uniq = new Map();
  for (const row of read(path)) {
    if (row.status !== 'ok') continue;
    for (const c of row.cves) {
      const key = `${c.id}|${row.slug}|${row.version}`;
      const prev = uniq.get(key);
      if (!prev) uniq.set(key, { cls: c.cls, near: c.nearClass, file: c.fileClass });
      else {
        prev.near ||= c.nearClass;
        prev.file ||= c.fileClass;
      }
    }
  }
  const byCls = {};
  for (const [k, v] of uniq) {
    const b = (byCls[v.cls] ??= { n: 0, near: 0, file: 0, keys: new Set() });
    b.n++;
    if (v.near) {
      b.near++;
      b.keys.add(k);
    }
    if (v.file) b.file++;
  }
  return byCls;
}

for (const kind of ['recall', 'recall-extended']) {
  if (!existsSync(file(opt.base, kind)) || !existsSync(file(opt.cand, kind))) continue;
  const a = recall(file(opt.base, kind));
  const b = recall(file(opt.cand, kind));
  console.log(`\n== ${kind}: ${opt.base} -> ${opt.cand}`);
  let na = 0;
  let nb = 0;
  let fa = 0;
  let fb = 0;
  let n = 0;
  for (const cls of Object.keys(a).sort()) {
    const x = a[cls];
    const y = b[cls] ?? { near: 0, file: 0, keys: new Set() };
    const lost = [...x.keys].filter((k) => !y.keys.has(k));
    const diff = y.near - x.near;
    console.log(
      `${cls.padEnd(12)} n=${String(x.n).padStart(3)}  near ${String(x.near).padStart(3)} -> ${String(y.near).padStart(3)} (${diff >= 0 ? '+' : ''}${diff})  file ${String(x.file).padStart(3)} -> ${String(y.file).padStart(3)}${lost.length ? '  LOST: ' + lost.join(', ') : ''}`,
    );
    na += x.near;
    nb += y.near;
    fa += x.file;
    fb += y.file;
    n += x.n;
  }
  console.log(`TOTAL near ${na} -> ${nb} of ${n} (${((100 * na) / n).toFixed(1)}% -> ${((100 * nb) / n).toFixed(1)}%), file ${fa} -> ${fb}`);
}

function noise(path) {
  const rows = read(path);
  const counts = rows.filter((r) => !r.error).map((r) => r.findings.length).sort((p, q) => p - q);
  const byRule = {};
  const plug = {};
  for (const r of rows) {
    const seen = new Set();
    for (const f of r.findings) {
      const k = `${f.rule} (${f.conf})`;
      byRule[k] = (byRule[k] ?? 0) + 1;
      if (!seen.has(k)) {
        seen.add(k);
        plug[k] = (plug[k] ?? 0) + 1;
      }
    }
  }
  return {
    rows,
    byRule,
    plug,
    none: counts.filter((c) => c === 0).length,
    total: counts.reduce((p, q) => p + q, 0),
    median: counts[Math.floor(counts.length / 2)],
    p90: counts[Math.floor(counts.length * 0.9)],
  };
}

if (existsSync(file(opt.base, 'noise')) && existsSync(file(opt.cand, 'noise'))) {
  const a = noise(file(opt.base, 'noise'));
  const b = noise(file(opt.cand, 'noise'));
  console.log(`\n== noise on popular plugins: ${opt.base} -> ${opt.cand}`);
  console.log(`without findings ${a.none} -> ${b.none}, total ${a.total} -> ${b.total}, median ${a.median} -> ${b.median}, p90 ${a.p90} -> ${b.p90}`);
  for (const k of [...new Set([...Object.keys(a.byRule), ...Object.keys(b.byRule)])].sort()) {
    console.log(`${k.padEnd(44)} ${String(a.byRule[k] ?? 0).padStart(4)} -> ${String(b.byRule[k] ?? 0).padStart(4)}   plugins ${a.plug[k] ?? 0} -> ${b.plug[k] ?? 0}`);
  }
  if (opt.new) {
    // Ten sam wynik znaleziska rozpoznajemy po wtyczce, regule, pliku i linii. Reguła autoryzacji nie ma
    // stabilnej linii (zgłasza przy definicji obsługi), więc dla niej bierzemy treść komunikatu.
    const sig = (slug, f) => (f.rule === 'wp.auth.unprotected_action' ? `${slug}|${f.rule}|${f.file}|${f.msg}` : `${slug}|${f.rule}|${f.file}|${f.line}`);
    const baseSet = new Set();
    for (const r of a.rows) for (const f of r.findings) baseSet.add(sig(r.slug, f));
    const candSet = new Set();
    for (const r of b.rows) for (const f of r.findings) candSet.add(sig(r.slug, f));
    let added = 0;
    console.log('\n-- New findings (not in the base run):');
    for (const r of b.rows) {
      for (const f of r.findings) {
        if (baseSet.has(sig(r.slug, f))) continue;
        added++;
        console.log(`${r.slug} ${f.rule} ${f.sev}/${f.conf} ${f.file}:${f.line} | ${f.msg}`);
      }
    }
    let gone = 0;
    for (const r of a.rows) for (const f of r.findings) if (!candSet.has(sig(r.slug, f))) gone++;
    console.log(`(${added} new, ${gone} gone)`);
  }
}
