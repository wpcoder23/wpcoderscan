// Porównuje wynik skanu wtyczek napisanych przez model AI z prawdą spisaną przed skanem (ground-truth/<zestaw>/<slug>.json).
// Trafienie to znalezisko reguły właściwej dla klasy słabości, w tym samym pliku, w odległości do 25 linii.
// Znaleziska, które nie są trafieniem, dzielę na zamierzone (byDesign), bezpieczne sklejenia (safeInterpolations)
// i niewyjaśnione. Niewyjaśnione trzeba ocenić ręcznie, czytając kod. Ocenę po skanie zapisuję w polu judged
// pliku prawdy (plik, linia, reguła, werdykt, uzasadnienie). Taki wpis tłumaczy znalezisko, nigdy nie dodaje słabości.
// Użycie: node benchmark/ai-code/compare.mjs --set sonnet-neutral --label v081 [--extended] [--list] [--truth ground-truth-final]
// --truth wskazuje katalog prawdy. Domyślnie to prawda spisana przeze mnie przed skanem, a ground-truth-final
// to prawda po scaleniu z niezależnym przeglądem (pole foundBy przy każdej słabości).
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { args } from '../common.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const opt = args({
  set: { type: 'string', default: 'sonnet-neutral' },
  label: { type: 'string', default: 'v081' },
  extended: { type: 'boolean', default: false },
  list: { type: 'boolean', default: false },
  truth: { type: 'string', default: 'ground-truth' },
});

const NEAR = 25;
const DESIGN_NEAR = 3;

const RULES = {
  sqli: ['wp.sqli.unprepared', 'wp.sqli.param_unprepared'],
  xss: ['wp.xss.echo_superglobal'],
  xss_stored: ['wp.xss.echo_superglobal'],
  authz: ['wp.auth.unprotected_action', 'wp.rest.no_permission_callback'],
  csrf: ['wp.auth.unprotected_action'],
  upload: ['wp.upload.unrestricted'],
  path: ['wp.file.path_traversal'],
  ssrf: ['wp.http.ssrf'],
  privesc: ['wp.privilege.escalation', 'wp.option.arbitrary_update', 'wp.option.no_sanitize_callback'],
  unserialize: ['wp.unserialize.user_input'],
  rce: ['wp.rce.dynamic'],
  include: ['wp.rce.dynamic'],
  secret: ['wp.secret.hardcoded'],
};

const name = `${opt.set}-${opt.label}${opt.extended ? '-extended' : ''}`;
const resultFile = join(here, 'results', `${name}.json`);
if (!existsSync(resultFile)) {
  console.error(`Brak ${resultFile}`);
  process.exit(2);
}
const rows = JSON.parse(readFileSync(resultFile, 'utf8'));
const gtDir = join(here, opt.truth, opt.set);

const norm = (p) => String(p).replace(/\\/g, '/');
const sameFile = (a, b) => {
  const x = norm(a);
  const y = norm(b);
  return x === y || x.endsWith('/' + y) || y.endsWith('/' + x);
};

const totals = { plugins: 0, weaknesses: 0, noRule: 0, detected: 0, missed: 0, findings: 0, matched: 0, byDesign: 0, safe: 0, judged: 0, unexplained: 0 };
const detail = [];

for (const row of rows) {
  const gtFile = join(gtDir, `${row.slug}.json`);
  if (!existsSync(gtFile)) {
    console.log(`${row.slug}: brak prawdy, pomijam`);
    continue;
  }
  const gt = JSON.parse(readFileSync(gtFile, 'utf8'));
  totals.plugins++;

  const used = new Set();
  const weaknesses = gt.weaknesses.map((w) => {
    totals.weaknesses++;
    const rules = RULES[w.class];
    if (!rules) {
      totals.noRule++;
      return { ...w, status: 'no-rule' };
    }
    const hit = row.findings.find(
      (f) => rules.includes(f.rule) && sameFile(f.file, w.file) && Math.abs(f.line - w.line) <= NEAR,
    );
    if (hit) {
      totals.detected++;
      for (const f of row.findings) {
        if (rules.includes(f.rule) && sameFile(f.file, w.file) && Math.abs(f.line - w.line) <= NEAR) used.add(f);
      }
      return { ...w, status: 'detected', by: `${hit.rule}@${hit.line}` };
    }
    totals.missed++;
    return { ...w, status: 'missed' };
  });

  const extras = [];
  for (const f of row.findings) {
    totals.findings++;
    if (used.has(f)) {
      totals.matched++;
      continue;
    }
    const design = gt.byDesign.find((d) => sameFile(f.file, d.file) && Math.abs(f.line - d.line) <= DESIGN_NEAR);
    if (design) {
      totals.byDesign++;
      extras.push({ ...f, tag: 'by-design', why: design.why });
      continue;
    }
    const safe = gt.safeInterpolations.find((d) => sameFile(f.file, d.file) && Math.abs(f.line - d.line) <= 2);
    if (safe) {
      totals.safe++;
      extras.push({ ...f, tag: 'safe-interpolation', why: safe.why });
      continue;
    }
    const judged = (gt.judged || []).find((d) => d.rule === f.rule && sameFile(f.file, d.file) && d.line === f.line);
    if (judged) {
      totals.judged++;
      extras.push({ ...f, tag: `judged-${judged.verdict}`, why: judged.why });
      continue;
    }
    totals.unexplained++;
    extras.push({ ...f, tag: 'unexplained' });
  }
  detail.push({ slug: row.slug, weaknesses, extras });
}

console.log(`Zestaw ${name}`);
console.log(
  `Wtyczki: ${totals.plugins}, słabości: ${totals.weaknesses} (bez reguły: ${totals.noRule}), wykryte: ${totals.detected}, pominięte: ${totals.missed}`,
);
const countable = totals.detected + totals.missed;
if (countable) console.log(`Wykrywalność dla klas z regułą: ${totals.detected} z ${countable} (${((100 * totals.detected) / countable).toFixed(1)}%)`);
console.log(
  `Znaleziska: ${totals.findings}, trafienia: ${totals.matched}, zamierzone: ${totals.byDesign}, bezpieczne sklejenia: ${totals.safe}, ocenione po skanie: ${totals.judged}, niewyjaśnione: ${totals.unexplained}`,
);

for (const d of detail) {
  const missed = d.weaknesses.filter((w) => w.status === 'missed');
  const open = d.extras.filter((e) => e.tag === 'unexplained');
  if (!opt.list && !missed.length && !open.length) continue;
  console.log(`\n== ${d.slug}`);
  for (const w of d.weaknesses) console.log(`  [${w.status}] ${w.class} ${w.file}:${w.line} ${w.desc ?? ''}`);
  for (const e of d.extras) {
    if (!opt.list && e.tag !== 'unexplained') continue;
    console.log(`  (${e.tag}) ${e.rule} ${e.file}:${e.line} [${e.sev}/${e.conf}] ${e.msg}`);
  }
}

const suffix = opt.truth === 'ground-truth' ? '' : `-${opt.truth}`;
writeFileSync(join(here, 'results', `${name}${suffix}-compare.json`), JSON.stringify({ totals, detail }, null, 1));
