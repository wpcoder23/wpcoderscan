import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan } from '../src/index';

const here = dirname(fileURLToPath(import.meta.url));
const vulnerable = join(here, 'fixtures', 'vulnerable', 'sqli.php');
const safe = join(here, 'fixtures', 'safe', 'sqli_safe.php');

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
