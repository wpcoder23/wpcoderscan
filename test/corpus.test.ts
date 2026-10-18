// Korpus wzorowany na typowych CVE. Realistyczna mini-wtyczka łącząca kilka
// klas podatności naraz, oraz jej poprawny odpowiednik. Pilnuje, żeby reguły
// działały razem na realnym kodzie i nie dawały fałszywych alarmów.
import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan } from '../src/index';

const here = dirname(fileURLToPath(import.meta.url));
const vuln = join(here, 'fixtures', 'corpus', 'vuln_plugin.php');
const safe = join(here, 'fixtures', 'corpus', 'safe_plugin.php');

function byRule(findings: { ruleId: string }[]): Record<string, number> {
  const m: Record<string, number> = {};
  for (const f of findings) m[f.ruleId] = (m[f.ruleId] ?? 0) + 1;
  return m;
}

describe('korpus CVE: dziurawa mini-wtyczka', () => {
  it('wykrywa wszystkie zasiane klasy podatności', async () => {
    const r = await scan(vuln, {});
    expect(r.errors).toHaveLength(0);
    const m = byRule(r.findings);
    expect(m['wp.sqli.unprepared']).toBe(2);
    expect(m['wp.auth.unprotected_action']).toBe(3);
    expect(m['wp.xss.echo_superglobal']).toBe(1);
    expect(m['wp.rest.no_permission_callback']).toBe(1);
    expect(m['wp.unserialize.user_input']).toBe(1);
    expect(m['wp.option.no_sanitize_callback']).toBe(1);
    expect(r.findings).toHaveLength(9);

    // Podział nonce kontra uprawnienia w uchwytach akcji.
    const auth = r.findings.filter((f) => f.ruleId === 'wp.auth.unprotected_action');
    expect(auth.filter((f) => (f.cwe ?? []).includes('CWE-352'))).toHaveLength(2);
    expect(auth.filter((f) => (f.cwe ?? []).includes('CWE-862'))).toHaveLength(1);
  });
});

describe('korpus CVE: poprawna mini-wtyczka', () => {
  it('nie daje żadnego fałszywego alarmu', async () => {
    const r = await scan(safe, {});
    expect(r.errors).toHaveLength(0);
    expect(r.findings).toHaveLength(0);
    expect(r.score.value).toBe(100);
  });
});
