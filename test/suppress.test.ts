// Komentarze wyciszające wpcoderscan-ignore: czytanie i stosowanie.
import { describe, it, expect } from 'vitest';
import { applyIgnores, matchesPattern, parseIgnores, type IgnoreDirective } from '../src/engine/suppress';
import type { Finding } from '../src/rules/types';

const KNOWN = ['wp.xss.echo_superglobal', 'wp.sqli.unprepared', 'wp.secret.hardcoded'];

function finding(ruleId: string, line: number): Finding {
  return { ruleId, severity: 'high', confidence: 'firm', message: 'm', file: 'a.php', line, column: 1 };
}

describe('wzorce reguł', () => {
  it('pasują do całego identyfikatora, gwiazdka zastępuje dowolny ciąg', () => {
    expect(matchesPattern('wp.xss.echo_superglobal', 'wp.xss.echo_superglobal')).toBe(true);
    expect(matchesPattern('wp.xss.*', 'wp.xss.echo_superglobal')).toBe(true);
    expect(matchesPattern('*', 'wp.sqli.unprepared')).toBe(true);
    expect(matchesPattern('wp.xss', 'wp.xss.echo_superglobal')).toBe(false);
    expect(matchesPattern('wp.sqli.*', 'wp.xss.echo_superglobal')).toBe(false);
  });

  it('kropka w identyfikatorze nie jest dowolnym znakiem', () => {
    expect(matchesPattern('wp.xss.echo_superglobal', 'wpXxssXecho_superglobal')).toBe(false);
  });
});

describe('parseIgnores', () => {
  it('komentarz w osobnej linii dotyczy następnej linii i niesie powód', () => {
    const code = ['<?php', '// wpcoderscan-ignore wp.xss.echo_superglobal -- znany przypadek', "echo $_GET['a'];"].join('\n');
    const r = parseIgnores(code, KNOWN);
    expect(r.problems).toEqual([]);
    expect(r.directives).toEqual([
      { line: 2, target: 3, scope: 'line', patterns: ['wp.xss.echo_superglobal'], reason: 'znany przypadek' },
    ]);
  });

  it('komentarz za kodem dotyczy swojej linii', () => {
    const code = ['<?php', "echo $_GET['a']; // wpcoderscan-ignore wp.xss.echo_superglobal"].join('\n');
    const r = parseIgnores(code, KNOWN);
    expect(r.directives).toEqual([{ line: 2, target: 2, scope: 'line', patterns: ['wp.xss.echo_superglobal'] }]);
  });

  it('komentarz w linii z otwarciem <?php dotyczy następnej linii', () => {
    const code = ['<?php // wpcoderscan-ignore wp.sqli.unprepared', 'run();'].join('\n');
    expect(parseIgnores(code, KNOWN).directives[0].target).toBe(2);
  });

  it('rozumie komentarze //, # oraz /* */ i /** */', () => {
    const code = [
      '<?php',
      '// wpcoderscan-ignore wp.sqli.unprepared',
      '# wpcoderscan-ignore wp.sqli.unprepared',
      '/* wpcoderscan-ignore wp.sqli.unprepared */',
      '/** wpcoderscan-ignore wp.sqli.unprepared */',
    ].join('\n');
    const r = parseIgnores(code, KNOWN);
    expect(r.directives.map((d) => d.line)).toEqual([2, 3, 4, 5]);
    expect(r.directives.every((d) => d.patterns.join(',') === 'wp.sqli.unprepared')).toBe(true);
  });

  it('wersja -file dotyczy całego pliku', () => {
    const r = parseIgnores('<?php\n// wpcoderscan-ignore-file wp.secret.hardcoded -- klucz publiczny\n', KNOWN);
    expect(r.directives).toEqual([
      { line: 2, target: 0, scope: 'file', patterns: ['wp.secret.hardcoded'], reason: 'klucz publiczny' },
    ]);
  });

  it('czyta kilka reguł oddzielonych przecinkiem lub spacją, także po dwukropku', () => {
    const r = parseIgnores('<?php\n// wpcoderscan-ignore: wp.xss.echo_superglobal, wp.sqli.unprepared -- a -- b\nx();', KNOWN);
    expect(r.directives[0].patterns).toEqual(['wp.xss.echo_superglobal', 'wp.sqli.unprepared']);
    expect(r.directives[0].reason).toBe('a -- b');
  });

  it('działa z końcami linii CRLF', () => {
    const r = parseIgnores('<?php\r\n// wpcoderscan-ignore wp.sqli.unprepared\r\nrun();\r\n', KNOWN);
    expect(r.directives).toEqual([{ line: 2, target: 3, scope: 'line', patterns: ['wp.sqli.unprepared'] }]);
  });

  it('komentarz bez identyfikatora reguły jest problemem i niczego nie wycisza', () => {
    const r = parseIgnores('<?php\n// wpcoderscan-ignore\n// wpcoderscan-ignore -- sam powód\n', KNOWN);
    expect(r.directives).toEqual([]);
    expect(r.problems).toEqual([
      { line: 2, kind: 'noRule' },
      { line: 3, kind: 'noRule' },
    ]);
  });

  it('nieznana reguła to ostrzeżenie o literówce, a komentarz nadal obowiązuje', () => {
    const r = parseIgnores('<?php\n// wpcoderscan-ignore wp.nope.rule\nx();', KNOWN);
    expect(r.problems).toEqual([{ line: 2, kind: 'unknownRule', rule: 'wp.nope.rule' }]);
    expect(r.directives).toHaveLength(1);
  });

  it('wzorzec z gwiazdką pasujący do znanej reguły nie jest literówką', () => {
    const r = parseIgnores('<?php\n// wpcoderscan-ignore wp.xss.*\n// wpcoderscan-ignore *\nx();', KNOWN);
    expect(r.problems).toEqual([]);
    expect(r.directives).toHaveLength(2);
  });

  it('nie bierze za komentarz podobnych słów ani kodu bez znacznika', () => {
    const similar = parseIgnores('<?php\n// wpcoderscan-ignored wp.sqli.unprepared\n// wpcoderscan-ignore-files wp.sqli.unprepared\n', KNOWN);
    expect(similar).toEqual({ directives: [], problems: [] });
    expect(parseIgnores('<?php echo 1;', KNOWN)).toEqual({ directives: [], problems: [] });
  });
});

describe('applyIgnores', () => {
  const line: IgnoreDirective = { line: 2, target: 3, scope: 'line', patterns: ['wp.sqli.unprepared'], reason: 'powód' };
  const file: IgnoreDirective = { line: 1, target: 0, scope: 'file', patterns: ['wp.xss.*'] };

  it('wycisza tylko wskazaną linię i tylko pasującą regułę', () => {
    const input = [finding('wp.sqli.unprepared', 3), finding('wp.sqli.unprepared', 4), finding('wp.xss.echo_superglobal', 3)];
    const r = applyIgnores(input, [line]);
    expect(r.suppressed.map((f) => [f.ruleId, f.line])).toEqual([['wp.sqli.unprepared', 3]]);
    expect(r.kept.map((f) => [f.ruleId, f.line])).toEqual([
      ['wp.sqli.unprepared', 4],
      ['wp.xss.echo_superglobal', 3],
    ]);
    expect(r.suppressed[0].suppressedBy).toEqual({ line: 2, scope: 'line', reason: 'powód' });
  });

  it('komentarz z -file wycisza regułę w każdej linii pliku', () => {
    const input = [finding('wp.xss.echo_superglobal', 10), finding('wp.xss.echo_superglobal', 99), finding('wp.sqli.unprepared', 10)];
    const r = applyIgnores(input, [file]);
    expect(r.suppressed).toHaveLength(2);
    expect(r.kept.map((f) => f.ruleId)).toEqual(['wp.sqli.unprepared']);
    expect(r.suppressed[0].suppressedBy).toEqual({ line: 1, scope: 'file' });
  });

  it('bez komentarzy oddaje listę bez zmian', () => {
    const input = [finding('wp.sqli.unprepared', 3)];
    const r = applyIgnores(input, []);
    expect(r.kept).toBe(input);
    expect(r.suppressed).toEqual([]);
  });
});
