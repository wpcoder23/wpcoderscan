// Tryb jawnej listy plików, na którym opiera się skan --diff.
import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan } from '../src/index';

const here = dirname(fileURLToPath(import.meta.url));

describe('silnik: jawna lista plików', () => {
  it('skanuje tylko podane pliki i pomija kolektor', async () => {
    const f = join(here, 'fixtures', 'vulnerable', 'sqli.php');
    const r = await scan('diff:test', { files: [f] });
    expect(r.filesScanned).toBe(1);
    expect(r.findings.some((x) => x.ruleId === 'wp.sqli.unprepared')).toBe(true);
    expect(r.errors).toHaveLength(0);
  });

  it('pusta lista plików daje pusty wynik i pełny wynik oceny', async () => {
    const r = await scan('diff:test', { files: [] });
    expect(r.filesScanned).toBe(0);
    expect(r.findings).toHaveLength(0);
    expect(r.score.value).toBe(100);
  });
});
