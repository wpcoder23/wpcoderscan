import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan } from '../src/index';

const here = dirname(fileURLToPath(import.meta.url));
const vulnerable = join(here, 'fixtures', 'vulnerable', 'sqli.php');
const safe = join(here, 'fixtures', 'safe', 'sqli_safe.php');
const restVulnerable = join(here, 'fixtures', 'vulnerable', 'rest.php');
const restSafe = join(here, 'fixtures', 'safe', 'rest_safe.php');

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
