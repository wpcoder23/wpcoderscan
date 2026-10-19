// Zbiera proste metryki ruchu i użycia WPCoderScan i dopisuje jeden wiersz do .measure/metrics.jsonl.
// Źródła: publiczne API npm, API GitHub przez `gh` (konto z dostępem do repozytorium, bez tokenów w kodzie).
// Użycie: node scripts/metrics.mjs [--print]
// Brakujące źródło zapisuje jako null. Skrypt niczego nie wysyła, tylko czyta.
import { spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const OWNER = 'wpcoder23';
const REPO = 'wpcoderscan';
const PACKAGE = 'wpcoderscan';

function gh(path, extra = []) {
  const r = spawnSync('gh', ['api', ...extra, path], { encoding: 'utf8' });
  if (r.status !== 0) return null;
  try {
    return JSON.parse(r.stdout);
  } catch {
    return null;
  }
}

async function npm(path) {
  try {
    const res = await fetch(`https://api.npmjs.org/${path}`, { signal: AbortSignal.timeout(20000) });
    return res.status === 200 ? await res.json() : null;
  } catch {
    return null;
  }
}

const repo = gh(`repos/${OWNER}/${REPO}`);
const views = gh(`repos/${OWNER}/${REPO}/traffic/views`);
const clones = gh(`repos/${OWNER}/${REPO}/traffic/clones`);
const referrers = gh(`repos/${OWNER}/${REPO}/traffic/popular/referrers`);
// Instalacje akcji: pliki spoza naszego konta, które wołają akcję w workflow.
const uses = gh('search/code', ['-X', 'GET', '-f', `q="${OWNER}/${REPO}" path:.github/workflows -user:${OWNER}`]);
const week = await npm(`downloads/point/last-week/${PACKAGE}`);
const month = await npm(`downloads/point/last-month/${PACKAGE}`);

const row = {
  at: new Date().toISOString(),
  stars: repo?.stargazers_count ?? null,
  forks: repo?.forks_count ?? null,
  watchers: repo?.subscribers_count ?? null,
  views14d: views?.count ?? null,
  uniqueViews14d: views?.uniques ?? null,
  clones14d: clones?.count ?? null,
  uniqueClones14d: clones?.uniques ?? null,
  topReferrers: Array.isArray(referrers) ? referrers.slice(0, 5).map((r) => `${r.referrer}:${r.count}`) : null,
  actionUsesOutside: uses?.total_count ?? null,
  npmWeek: week?.downloads ?? null,
  npmMonth: month?.downloads ?? null,
};

// Progi z planu: po 30 dniach co najmniej 25 pobrań tygodniowo albo 10 gwiazdek, po 60 dniach
// poniżej 15 pobrań tygodniowo i zero zapisów to sygnał do zatrzymania dalszej budowy.
// Sygnał ma sens dopiero po 30 i 60 dniach od publikacji. Bez pakietu na npm nie ma czego mierzyć.
row.signal =
  row.npmWeek === null
    ? 'brak pakietu na npm'
    : row.npmWeek >= 25 || (row.stars ?? 0) >= 10
      ? 'ruch jest'
      : row.npmWeek < 15
        ? 'poniżej progu'
        : 'obserwuj';

const dir = join(root, '.measure');
mkdirSync(dir, { recursive: true });
appendFileSync(join(dir, 'metrics.jsonl'), JSON.stringify(row) + '\n');
console.log(JSON.stringify(row, null, 2));
