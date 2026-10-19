// Odświeża migawkę data/cves.json: wpisy CVE wtyczek WordPress z NVD, które mają odnośnik do
// plugins.trac.wordpress.org z plikiem i linią w podatnej wersji. Dane z sieci są niezaufane, tylko je czytamy.
// Użycie: node benchmark/fetch-cves.mjs [--from 2023] [--to 2025]
// NVD ogranicza liczbę zapytań, więc pobranie trwa około godziny. Gotowa migawka leży w repozytorium.
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { args, here, sleep, vulnClass } from './common.mjs';

const opt = args({ from: { type: 'string', default: '2023' }, to: { type: 'string', default: '2025' } });
const KEYWORDS = [
  'wordpress plugin SQL Injection',
  'wordpress plugin Reflected Cross-Site Scripting',
  'wordpress plugin PHP Object Injection',
  'wordpress plugin Local File Inclusion',
  'wordpress plugin Missing Authorization',
  'wordpress plugin Stored Cross-Site Scripting',
];
const WINDOWS = [];
for (let y = Number(opt.from); y <= Number(opt.to); y++) {
  for (let m = 0; m < 12; m += 3) {
    const s = new Date(Date.UTC(y, m, 1));
    const e = new Date(Date.UTC(y, m + 3, 0, 23, 59, 59));
    WINDOWS.push([s.toISOString().slice(0, 19) + '.000', e.toISOString().slice(0, 19) + '.000']);
  }
}

// Myślnik typograficzny z opisów NVD zamieniamy na zwykły łącznik.
const DASH = new RegExp('[' + String.fromCharCode(0x2013, 0x2014) + ']', 'g');
const out = new Map();
for (const kw of KEYWORDS) {
  for (const [s, e] of WINDOWS) {
    const url =
      'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&keywordSearch=' +
      encodeURIComponent(kw) +
      '&pubStartDate=' + s + '&pubEndDate=' + e;
    let data = null;
    for (let attempt = 0; attempt < 4 && !data; attempt++) {
      try {
        const res = await fetch(url, { signal: AbortSignal.timeout(60000) });
        if (res.status === 200) data = await res.json();
        else await sleep(8000 * (attempt + 1));
      } catch {
        await sleep(8000 * (attempt + 1));
      }
      await sleep(6500);
    }
    if (!data) continue;
    for (const v of data.vulnerabilities ?? []) {
      const cve = v.cve;
      const hits = (cve.references ?? [])
        .map((r) => r.url.match(/plugins\.trac\.wordpress\.org\/browser\/([a-z0-9_-]+)\/tags\/([^/]+)\/([^#?]+)(?:\?[^#]*)?#L(\d+)/i))
        .filter(Boolean)
        .map((m) => ({ slug: m[1], version: m[2], file: m[3], line: Number(m[4]) }));
      if (hits.length === 0) continue;
      const desc = (cve.descriptions ?? []).find((d) => d.lang === 'en')?.value ?? '';
      out.set(cve.id, { id: cve.id, published: String(cve.published).slice(0, 10), cls: vulnClass(desc), desc: desc.slice(0, 280).replace(DASH, '-'), hits });
    }
    console.log(`${kw} ${s.slice(0, 10)}: ${out.size} entries`);
  }
}
mkdirSync(join(here, 'data'), { recursive: true });
writeFileSync(join(here, 'data', 'cves.json'), JSON.stringify([...out.values()]).replace(/\},\{"id"/g, '},\n{"id"') + '\n');
console.log(`Saved ${out.size} entries to benchmark/data/cves.json`);
