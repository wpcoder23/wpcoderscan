// Odciski znalezisk i baseline.
import { describe, it, expect } from 'vitest';
import { assignFingerprints, baseFingerprint } from '../src/engine/fingerprint';
import {
  applyBaseline,
  BaselineError,
  createBaseline,
  parseBaseline,
  serializeBaseline,
  type Baseline,
} from '../src/engine/baseline';
import { createTranslator } from '../src/i18n';
import type { Finding } from '../src/rules/types';

const en = createTranslator('en');
const pl = createTranslator('pl');

function finding(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'wp.rce.dynamic',
    severity: 'critical',
    confidence: 'firm',
    message: 'm',
    file: 'a.php',
    line: 10,
    column: 1,
    snippet: "eval( $_POST['x'] );",
    ...over,
  };
}

describe('odcisk znaleziska', () => {
  it('nie zależy od numeru linii ani od komunikatu', () => {
    expect(baseFingerprint(finding({ line: 10 }))).toBe(baseFingerprint(finding({ line: 250, message: 'inny' })));
  });

  it('zależy od reguły, pliku i treści linii', () => {
    const base = baseFingerprint(finding());
    expect(baseFingerprint(finding({ ruleId: 'wp.xss.echo_superglobal' }))).not.toBe(base);
    expect(baseFingerprint(finding({ file: 'b.php' }))).not.toBe(base);
    expect(baseFingerprint(finding({ snippet: "eval( $_POST['y'] );" }))).not.toBe(base);
  });

  it('ma 16 znaków szesnastkowych', () => {
    expect(baseFingerprint(finding())).toMatch(/^[0-9a-f]{16}$/);
  });

  it('identyczne znaleziska w pliku dostają kolejne numery wystąpień', () => {
    const list = [finding({ line: 30 }), finding({ line: 10 }), finding({ line: 20 })];
    assignFingerprints(list);
    const h = baseFingerprint(finding());
    const byLine = new Map(list.map((f) => [f.line, f.fingerprint]));
    expect(byLine.get(10)).toBe(h);
    expect(byLine.get(20)).toBe(`${h}:2`);
    expect(byLine.get(30)).toBe(`${h}:3`);
  });

  it('numeruje osobno każdy odcisk i nie zależy od kolejności na liście', () => {
    const a = [finding({ line: 1 }), finding({ line: 2, snippet: 'inna linia' }), finding({ line: 3 })];
    const b = [...a].reverse().map((f) => ({ ...f }));
    assignFingerprints(a);
    assignFingerprints(b);
    const ids = (list: Finding[]) => list.map((f) => [f.line, f.fingerprint]).sort((x, y) => (x[0] as number) - (y[0] as number));
    expect(ids(a)).toEqual(ids(b));
    expect(a[1].fingerprint).toMatch(/^[0-9a-f]{16}$/);
    expect(a[2].fingerprint).toMatch(/^[0-9a-f]{16}:2$/);
  });
});

describe('baseline', () => {
  function withIds(...items: Array<Partial<Finding>>): Finding[] {
    const list = items.map((i) => finding(i));
    assignFingerprints(list);
    return list;
  }

  it('zapisuje wpisy posortowane po pliku, linii i regule i pomija znaleziska bez odcisku', () => {
    const list = withIds({ file: 'b.php', line: 5 }, { file: 'a.php', line: 9 }, { file: 'a.php', line: 2, snippet: 'x' });
    const noId = finding({ file: 'z.php' });
    const baseline = createBaseline([...list, noId]);
    expect(baseline.version).toBe(1);
    expect(baseline.tool).toBe('wpcoderscan');
    expect(baseline.entries.map((e) => `${e.file}:${e.line}`)).toEqual(['a.php:2', 'a.php:9', 'b.php:5']);
  });

  it('serializuje do czytelnego JSON-a z nową linią na końcu i da się go wczytać z powrotem', () => {
    const baseline = createBaseline(withIds({ line: 4 }, { line: 8, snippet: 'y' }));
    const text = serializeBaseline(baseline);
    expect(text.endsWith('}\n')).toBe(true);
    expect(text).toContain('\n  "entries"');
    expect(parseBaseline(text, en)).toEqual(baseline);
  });

  it('odrzuca plik, który nie jest baseline, komunikatem w języku tłumacza', () => {
    for (const bad of ['to nie json', '[]', '{}', '{"version":2,"entries":[]}', '{"version":1,"entries":{}}', '{"version":1,"entries":[{"rule":"x"}]}']) {
      expect(() => parseBaseline(bad, en), bad).toThrow(BaselineError);
    }
    expect(() => parseBaseline('to nie json', en)).toThrow(/baseline file is not valid/);
    expect(() => parseBaseline('to nie json', pl)).toThrow(/plik baseline jest nieprawidłowy/);
  });

  it('toleruje brakujące pola informacyjne we wpisach', () => {
    const baseline = parseBaseline('{"version":1,"entries":[{"id":"abc"}]}', en);
    expect(baseline.entries).toEqual([{ id: 'abc', rule: '', file: '', line: 0 }]);
  });

  describe('applyBaseline', () => {
    const scope = { rules: new Set(['wp.rce.dynamic']), files: new Set(['a.php']) };

    it('dzieli znaleziska na nowe i znane', () => {
      const known = withIds({ line: 3 });
      const baseline = createBaseline(known);
      const current = withIds({ line: 30 }, { line: 40, snippet: 'nowa linia' });
      const r = applyBaseline(current, baseline, scope);
      expect(r.baselined.map((f) => f.line)).toEqual([30]);
      expect(r.kept.map((f) => f.line)).toEqual([40]);
      expect(r.stale).toBe(0);
    });

    it('liczy wpisy bez dopasowania tylko dla reguł i plików z tego skanu', () => {
      const baseline: Baseline = {
        version: 1,
        tool: 'wpcoderscan',
        entries: [
          { id: 'aaa', rule: 'wp.rce.dynamic', file: 'a.php', line: 1 },
          { id: 'bbb', rule: 'wp.sqli.param_unprepared', file: 'a.php', line: 1 },
          { id: 'ccc', rule: 'wp.rce.dynamic', file: 'inny.php', line: 1 },
          { id: 'ddd', rule: '', file: '', line: 0 },
        ],
      };
      const r = applyBaseline([], baseline, scope);
      // aaa: reguła i plik w skanie. bbb: reguła wyłączona. ccc: plik nieczytany. ddd: bez danych, liczony zawsze.
      expect(r.stale).toBe(2);
    });
  });
});
