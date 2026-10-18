import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
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

describe('reguła SQL injection', () => {
  it('wykrywa niezabezpieczone zapytania $wpdb', async () => {
    const r = await scan(vulnerable, {});
    const sqli = r.findings.filter((f) => f.ruleId === 'wp.sqli.unprepared');
    expect(sqli.length).toBeGreaterThanOrEqual(2);
    expect(sqli.some((f) => f.severity === 'critical')).toBe(true);
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
    // Dwa braki (/items oraz DELETE w /multi) i jeden __return_true (/open).
    expect(rest.filter((f) => f.severity === 'high')).toHaveLength(2);
    expect(rest.filter((f) => f.severity === 'medium')).toHaveLength(1);
    expect(rest.every((f) => f.confidence === 'firm')).toBe(true);
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
    // eval, require($_GET), shell_exec($_POST) sa krytyczne.
    expect(rce.filter((f) => f.severity === 'critical')).toHaveLength(3);
    // include $template, system($cmd), backtick $path sa wysokie.
    expect(rce.filter((f) => f.severity === 'high')).toHaveLength(3);
    expect(rce.every((f) => f.confidence === 'firm')).toBe(true);
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
