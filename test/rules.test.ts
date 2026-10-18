import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { scan } from '../src/index';

const here = dirname(fileURLToPath(import.meta.url));
const vulnerable = join(here, 'fixtures', 'vulnerable', 'sqli.php');
const safe = join(here, 'fixtures', 'safe', 'sqli_safe.php');
const restVulnerable = join(here, 'fixtures', 'vulnerable', 'rest.php');
const restSafe = join(here, 'fixtures', 'safe', 'rest_safe.php');
const rceVulnerable = join(here, 'fixtures', 'vulnerable', 'rce.php');
const rceSafe = join(here, 'fixtures', 'safe', 'rce_safe.php');
const unserVulnerable = join(here, 'fixtures', 'vulnerable', 'unserialize.php');
const unserSafe = join(here, 'fixtures', 'safe', 'unserialize_safe.php');
const regSettingVulnerable = join(here, 'fixtures', 'vulnerable', 'register_setting.php');
const regSettingSafe = join(here, 'fixtures', 'safe', 'register_setting_safe.php');
const xssVulnerable = join(here, 'fixtures', 'vulnerable', 'xss.php');
const xssSafe = join(here, 'fixtures', 'safe', 'xss_safe.php');
const nonceVulnerable = join(here, 'fixtures', 'vulnerable', 'nonce_capability.php');
const nonceSafe = join(here, 'fixtures', 'safe', 'nonce_capability_safe.php');

describe('reguła SQL injection', () => {
  it('wykrywa niezabezpieczone zapytania $wpdb', async () => {
    const r = await scan(vulnerable, {});
    const sqli = r.findings.filter((f) => f.ruleId === 'wp.sqli.unprepared');
    // Superglobal wprost jest pewny. Zmienne zasilone superglobalem to heurystyka.
    const firm = sqli.filter((f) => f.confidence === 'firm');
    const heur = sqli.filter((f) => f.confidence === 'heuristic');
    expect(firm).toHaveLength(1);
    expect(firm[0].severity).toBe('critical');
    // $id, $name, $item w pętli foreach oraz $sql złożone z $search.
    expect(heur).toHaveLength(4);
    expect(heur.every((f) => f.severity === 'high')).toBe(true);
    expect(r.errors).toHaveLength(0);
  });

  it('nie zgłasza zapytań z prepare i nazw tabel', async () => {
    const r = await scan(safe, {});
    const sqli = r.findings.filter((f) => f.ruleId === 'wp.sqli.unprepared');
    expect(sqli).toHaveLength(0);
    expect(r.errors).toHaveLength(0);
  });
});

describe('reguła REST permission_callback', () => {
  it('wykrywa brak permission_callback i __return_true', async () => {
    const r = await scan(restVulnerable, {});
    const rest = r.findings.filter((f) => f.ruleId === 'wp.rest.no_permission_callback');
    // Dwa braki (/items oraz DELETE w /multi) są pewne. __return_true na
    // trasie zapisującej (/write) to heurystyka. Na trasie GET (/open) pomijamy.
    const missing = rest.filter((f) => f.severity === 'high');
    const open = rest.filter((f) => f.severity === 'medium');
    expect(missing).toHaveLength(2);
    expect(missing.every((f) => f.confidence === 'firm')).toBe(true);
    expect(open).toHaveLength(1);
    expect(open[0].confidence).toBe('heuristic');
    expect(r.errors).toHaveLength(0);
  });

  it('nie zgłasza tras z realnym permission_callback', async () => {
    const r = await scan(restSafe, {});
    const rest = r.findings.filter((f) => f.ruleId === 'wp.rest.no_permission_callback');
    expect(rest).toHaveLength(0);
    expect(r.errors).toHaveLength(0);
  });
});

describe('reguła RCE i wykonanie poleceń', () => {
  it('wykrywa eval, dynamiczne include i polecenia systemowe', async () => {
    const r = await scan(rceVulnerable, {});
    const rce = r.findings.filter((f) => f.ruleId === 'wp.rce.dynamic');
    // eval($_POST), require($_GET), shell_exec($_POST) i backtick z $_GET: pewne, krytyczne.
    const firm = rce.filter((f) => f.confidence === 'firm');
    expect(firm).toHaveLength(4);
    expect(firm.every((f) => f.severity === 'critical')).toBe(true);
    // include po $page i exec po $host: heurystyka, wysoka waga.
    // eval($user_code) o nieznanym pochodzeniu: heurystyka, średnia waga.
    const heur = rce.filter((f) => f.confidence === 'heuristic');
    expect(heur).toHaveLength(3);
    expect(heur.filter((f) => f.severity === 'high')).toHaveLength(2);
    expect(heur.filter((f) => f.severity === 'medium')).toHaveLength(1);
    expect(r.errors).toHaveLength(0);
  });

  it('nie zgłasza include ze stałych ani poleceń z literału', async () => {
    const r = await scan(rceSafe, {});
    const rce = r.findings.filter((f) => f.ruleId === 'wp.rce.dynamic');
    expect(rce).toHaveLength(0);
    expect(r.errors).toHaveLength(0);
  });
});

describe('reguła unserialize', () => {
  it('wykrywa unserialize na superglobalach', async () => {
    const r = await scan(unserVulnerable, {});
    const u = r.findings.filter((f) => f.ruleId === 'wp.unserialize.user_input');
    expect(u).toHaveLength(3);
    expect(u.every((f) => f.severity === 'high' && f.confidence === 'firm')).toBe(true);
    expect(r.errors).toHaveLength(0);
  });

  it('nie zgłasza deserializacji danych z bazy ani json_decode', async () => {
    const r = await scan(unserSafe, {});
    const u = r.findings.filter((f) => f.ruleId === 'wp.unserialize.user_input');
    expect(u).toHaveLength(0);
    expect(r.errors).toHaveLength(0);
  });
});

describe('reguła register_setting', () => {
  it('wykrywa brak sanitize_callback', async () => {
    const r = await scan(regSettingVulnerable, {});
    const s = r.findings.filter((f) => f.ruleId === 'wp.option.no_sanitize_callback');
    expect(s).toHaveLength(2);
    expect(s.every((f) => f.severity === 'medium' && f.confidence === 'firm')).toBe(true);
    expect(r.errors).toHaveLength(0);
  });

  it('nie zgłasza opcji z sanitize_callback ani starej sygnatury', async () => {
    const r = await scan(regSettingSafe, {});
    const s = r.findings.filter((f) => f.ruleId === 'wp.option.no_sanitize_callback');
    expect(s).toHaveLength(0);
    expect(r.errors).toHaveLength(0);
  });
});

describe('reguła XSS echo/print', () => {
  it('wykrywa superglobal w echo i print bez ucieczki', async () => {
    const r = await scan(xssVulnerable, {});
    const xss = r.findings.filter((f) => f.ruleId === 'wp.xss.echo_superglobal');
    expect(xss).toHaveLength(5);
    expect(xss.every((f) => f.confidence === 'heuristic')).toBe(true);
    // Cztery z superglobala wprost, jedno ze zmiennej $query.
    expect(xss.filter((f) => f.severity === 'high')).toHaveLength(4);
    expect(xss.filter((f) => f.severity === 'medium')).toHaveLength(1);
    expect(r.errors).toHaveLength(0);
  });

  it('nie zgłasza danych po ucieczce, sanitizacji lub rzutowaniu', async () => {
    const r = await scan(xssSafe, {});
    const xss = r.findings.filter((f) => f.ruleId === 'wp.xss.echo_superglobal');
    expect(xss).toHaveLength(0);
    expect(r.errors).toHaveLength(0);
  });
});

describe('reguła nonce i uprawnień', () => {
  it('wykrywa brak nonce i brak sprawdzenia uprawnień w uchwytach akcji', async () => {
    const r = await scan(nonceVulnerable, {});
    const a = r.findings.filter((f) => f.ruleId === 'wp.auth.unprotected_action');
    const noNonce = a.filter((f) => (f.cwe ?? []).includes('CWE-352'));
    const noCap = a.filter((f) => (f.cwe ?? []).includes('CWE-862'));
    // delete_item i domknięcie nie mają nonce. Trzy uchwyty nie mają uprawnień.
    expect(noNonce).toHaveLength(2);
    expect(noCap).toHaveLength(3);
    expect(a.every((f) => f.severity === 'high' && f.confidence === 'heuristic')).toBe(true);
    expect(r.errors).toHaveLength(0);
  });

  it('nie zgłasza uchwytów z kontrolami ani callbacków metod', async () => {
    const r = await scan(nonceSafe, {});
    const a = r.findings.filter((f) => f.ruleId === 'wp.auth.unprotected_action');
    expect(a).toHaveLength(0);
    expect(r.errors).toHaveLength(0);
  });
});

describe('reguła sekretów', () => {
  // Atrapy sekretów składane z kawałków, żeby pełny wzorzec nie trafił do repo.
  let dir = '';
  let file = '';
  beforeAll(() => {
    const aws = 'AKIA' + 'IOSFODNN7EXAMPLE';
    const stripe = 'sk_' + 'live_' + '0123456789abcdefABCD1234';
    const github = 'ghp_' + 'A'.repeat(36);
    const google = 'AIza' + 'B'.repeat(35);
    const pem = '-----BEGIN ' + 'RSA PRIVATE KEY' + '-----\n' + 'MIIEowIBAAKCAQEA'.repeat(5);
    const pemHeaderOnly = '-----BEGIN ' + 'PRIVATE KEY' + '-----';
    const dbPass = 'S3cr3t' + 'Pass' + 'w0rd123';
    const apiKeyVal = 'abcdef' + 'gh123456';
    const php = [
      '<?php',
      `$a = '${aws}';`,
      `$b = '${stripe}';`,
      `$c = '${github}';`,
      `$d = '${google}';`,
      `$e = "${pem}";`,
      `$h = '${pemHeaderOnly}';`,
      `define('DB_PASSWORD', '${dbPass}');`,
      `$api_key = '${apiKeyVal}';`,
      "define('API_KEY', 'YOUR_API_KEY_HERE');",
      "$password = 'changeme';",
      "$password_label = 'Podaj hasło do konta';",
      "$bypass = 'abcdefgh123456';",
      "$accessTokenURL = 'https://api.provider.org/oauth/token/12345678';",
      '',
    ].join('\n');
    dir = mkdtempSync(join(tmpdir(), 'wpcs-sec-'));
    file = join(dir, 'secrets.php');
    writeFileSync(file, php, 'utf8');
  });
  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('wykrywa klucze znanych dostawców jako pewne', async () => {
    const r = await scan(file, { cwd: dir });
    const firm = r.findings.filter(
      (f) => f.ruleId === 'wp.secret.hardcoded' && f.confidence === 'firm',
    );
    // AWS, Stripe, GitHub, Google, klucz prywatny.
    expect(firm).toHaveLength(5);
    expect(firm.filter((f) => f.severity === 'critical')).toHaveLength(4);
    expect(firm.filter((f) => f.severity === 'high')).toHaveLength(1);
    expect(r.errors).toHaveLength(0);
  });

  it('zgłasza sekrety po nazwie jako heurystykę i pomija atrapy', async () => {
    const r = await scan(file, { cwd: dir });
    const heur = r.findings.filter(
      (f) => f.ruleId === 'wp.secret.hardcoded' && f.confidence === 'heuristic',
    );
    // DB_PASSWORD i $api_key, bez YOUR_API_KEY_HERE i changeme.
    expect(heur).toHaveLength(2);
    expect(heur.every((f) => f.severity === 'medium')).toBe(true);
  });
});
