// Wspólne funkcje skryptów pomiarowych: parametry, pobieranie i rozpakowanie archiwów, ładowanie skanera.
// Pobrany kod wtyczek jest niezaufany. Skrypty go tylko rozpakowują i parsują, niczego z niego nie uruchamiają.
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

export const here = dirname(fileURLToPath(import.meta.url));
export const CACHE = join(here, '.cache');
export const RESULTS = join(here, 'results');

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function args(options) {
  return parseArgs({ options, allowPositionals: true }).values;
}

// Ładuje skompilowany skaner (dist/index.js z npm run build) i zwraca funkcję scan.
export async function loadScanner(libPath) {
  const { scan } = await import(pathToFileURL(resolve(libPath)).href);
  return scan;
}

// Klasa podatności z opisu CVE. Od niej zależy, które reguły skanera liczą się jako trafienie.
export function vulnClass(desc) {
  const d = desc.toLowerCase();
  if (d.includes('sql injection')) return 'sqli';
  if (d.includes('object injection') || d.includes('deserialization')) return 'unserialize';
  if (d.includes('file inclusion')) return 'include';
  if (d.includes('cross-site scripting') || d.includes('xss')) return d.includes('stored') ? 'xss_stored' : 'xss';
  if (d.includes('missing authorization') || d.includes('missing capability') || d.includes('authorization')) return 'authz';
  if (d.includes('cross-site request forgery') || d.includes('csrf')) return 'csrf';
  return 'other';
}

export const RULES_FOR = {
  sqli: ['wp.sqli.unprepared', 'wp.sqli.param_unprepared'],
  unserialize: ['wp.unserialize.user_input'],
  include: ['wp.rce.dynamic'],
  xss: ['wp.xss.echo_superglobal'],
  xss_stored: ['wp.xss.echo_superglobal'],
  authz: ['wp.auth.unprotected_action', 'wp.rest.no_permission_callback'],
  csrf: ['wp.auth.unprotected_action'],
  other: [],
};

// Pobiera archiwum, jeśli go jeszcze nie ma w pamięci podręcznej. Zwraca true, gdy plik jest gotowy.
export async function download(url, file) {
  if (existsSync(file)) return true;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(120000) });
    if (res.status !== 200) return false;
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, Buffer.from(await res.arrayBuffer()));
    await sleep(250);
    return true;
  } catch {
    return false;
  }
}

// Rozpakowuje zip do pustego katalogu. Najpierw tar (bsdtar czyta zip i odrzuca ścieżki z ..), potem unzip.
export function extract(zip, dir) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  let r = spawnSync('tar', ['-xf', zip, '-C', dir], { encoding: 'utf8' });
  if (r.status !== 0) r = spawnSync('unzip', ['-q', '-o', zip, '-d', dir], { encoding: 'utf8' });
  if (r.status !== 0) {
    rmSync(dir, { recursive: true, force: true });
    return false;
  }
  return true;
}
