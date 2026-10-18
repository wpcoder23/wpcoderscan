import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan } from '../src/index';
import { buildSarif } from '../src/report/sarif';
import { allRules } from '../src/rules';

const here = dirname(fileURLToPath(import.meta.url));
const vulnDir = join(here, 'fixtures', 'vulnerable');

describe('raport SARIF', () => {
  it('buduje poprawny dokument SARIF 2.1.0', async () => {
    const r = await scan(vulnDir, { cwd: vulnDir });
    const sarif = buildSarif(r);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif');
    expect(sarif.runs).toHaveLength(1);
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe('WPCoderScaner');
    expect(run.tool.driver.rules).toHaveLength(allRules.length);
    expect(run.results).toHaveLength(r.findings.length);
  });

  it('daje każdemu wynikowi poziom, lokalizację i odcisk', async () => {
    const r = await scan(vulnDir, { cwd: vulnDir });
    const run = buildSarif(r).runs[0];
    for (const res of run.results) {
      expect(['error', 'warning', 'note', 'none']).toContain(res.level);
      const loc = res.locations[0].physicalLocation;
      expect(loc.artifactLocation.uri.length).toBeGreaterThan(0);
      expect(loc.artifactLocation.uri).not.toContain('\\');
      expect(loc.region.startLine).toBeGreaterThanOrEqual(1);
      expect(res.partialFingerprints.wpcsFingerprint).toMatch(/^[0-9a-f]{16}$/);
      if (res.ruleIndex !== undefined) {
        expect(run.tool.driver.rules[res.ruleIndex].id).toBe(res.ruleId);
      }
    }
  });

  it('mapuje pewne krytyczne na error, a heurystykę nigdy na error', async () => {
    const r = await scan(vulnDir, { cwd: vulnDir });
    const run = buildSarif(r).runs[0];

    const firmHigh = run.results.filter(
      (x) =>
        x.properties.confidence === 'firm' &&
        (x.properties.severity === 'critical' || x.properties.severity === 'high'),
    );
    expect(firmHigh.length).toBeGreaterThan(0);
    expect(firmHigh.every((x) => x.level === 'error')).toBe(true);

    const heuristic = run.results.filter((x) => x.properties.confidence === 'heuristic');
    expect(heuristic.length).toBeGreaterThan(0);
    expect(heuristic.every((x) => x.level !== 'error')).toBe(true);
  });
});
