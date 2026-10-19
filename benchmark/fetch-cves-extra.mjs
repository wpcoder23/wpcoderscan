// Odświeża migawkę data/cves-extra.json: wpisy CVE wtyczek WordPress w klasach spoza głównego zbioru (wysyłanie
// plików, eskalacja uprawnień, obejście logowania, usuwanie i odczyt plików, SSRF, aktualizacja opcji, RCE,
// przekierowanie). Bierzemy tylko wpisy z odnośnikiem do plugins.trac.wordpress.org z plikiem i linią w podatnej
// wersji. Dane z sieci są niezaufane, tylko je czytamy.
// Użycie: node benchmark/fetch-cves-extra.mjs [--from 2023] [--to 2025]
// NVD ogranicza liczbę zapytań, więc pobranie trwa około godziny. Gotowa migawka leży w repozytorium.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { args, here, sleep } from './common.mjs';

const opt = args({ from: { type: 'string', default: '2023' }, to: { type: 'string', default: '2025' } });
const KEYWORDS = [
  'wordpress plugin Arbitrary File Upload',
  'wordpress plugin Privilege Escalation',
  'wordpress plugin Authentication Bypass',
  'wordpress plugin Arbitrary File Deletion',
  'wordpress plugin Arbitrary File Read',
  'wordpress plugin Path Traversal',
  'wordpress plugin Server-Side Request Forgery',
  'wordpress plugin Arbitrary Options Update',
  'wordpress plugin Remote Code Execution',
  'wordpress plugin Open Redirect',
];
const WINDOWS = [];
for (let y = Number(opt.from); y <= Number(opt.to); y++) {
  for (let m = 0; m < 12; m += 3) {
    const s = new Date(Date.UTC(y, m, 1));
    const e = new Date(Date.UTC(y, m + 3, 0, 23, 59, 59));
    WINDOWS.push([s.toISOString().slice(0, 19) + '.000', e.toISOString().slice(0, 19) + '.000']);
  }
}

// Klasa z opisu CVE. Od niej zależy, które reguły liczą się jako trafienie (patrz recall-extra.mjs).
function klass(desc) {
  const d = desc.toLowerCase();
  if (d.includes('file upload')) return 'upload';
  if (d.includes('privilege escalation')) return 'privesc';
  if (d.includes('authentication bypass')) return 'authbypass';
  if (d.includes('file deletion') || d.includes('file delete')) return 'file_delete';
  if (d.includes('file read') || d.includes('file download') || d.includes('path traversal') || d.includes('directory traversal')) return 'file_read';
  if (d.includes('server-side request forgery') || d.includes('ssrf')) return 'ssrf';
  if (d.includes('options update') || d.includes('option update') || d.includes('arbitrary option')) return 'option_update';
  if (d.includes('remote code execution') || d.includes('code injection') || d.includes('command injection')) return 'rce';
  if (d.includes('open redirect')) return 'redirect';
  return 'other';
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
    if (!data) {
      console.log(`${kw} ${s.slice(0, 10)}: no response`);
      continue;
    }
    for (const v of data.vulnerabilities ?? []) {
      const cve = v.cve;
      const hits = (cve.references ?? [])
        .map((r) => r.url.match(/plugins\.trac\.wordpress\.org\/browser\/([a-z0-9_-]+)\/tags\/([^/]+)\/([^#?]+)(?:\?[^#]*)?#L(\d+)/i))
        .filter(Boolean)
        .map((m) => ({ slug: m[1], version: m[2], file: m[3], line: Number(m[4]) }));
      if (hits.length === 0) continue;
      const desc = (cve.descriptions ?? []).find((d) => d.lang === 'en')?.value ?? '';
      out.set(cve.id, { id: cve.id, published: String(cve.published).slice(0, 10), cls: klass(desc), desc: desc.slice(0, 280).replace(DASH, '-'), hits });
    }
    console.log(`${kw} ${s.slice(0, 10)}: ${out.size} entries`);
  }
}
mkdirSync(join(here, 'data'), { recursive: true });
writeFileSync(join(here, 'data', 'cves-extra.json'), JSON.stringify([...out.values()]).replace(/\},\{"id"/g, '},\n{"id"') + '\n');
console.log(`Saved ${out.size} entries to benchmark/data/cves-extra.json`);
