// Wzorce ścieżek dla pola exclude w pliku ustawień.
import { describe, it, expect } from 'vitest';
import { compileGlob, isExcluded } from '../src/glob';

const excluded = (path: string, ...patterns: string[]) => isExcluded(path, patterns.map(compileGlob));

describe('wzorce ścieżek', () => {
  it('nazwa bez ukośnika działa na każdej głębokości i obejmuje całe drzewo', () => {
    expect(excluded('tests/a.php', 'tests')).toBe(true);
    expect(excluded('src/tests/a.php', 'tests')).toBe(true);
    expect(excluded('src/tests/deep/a.php', 'tests')).toBe(true);
    expect(excluded('src/attests/a.php', 'tests')).toBe(false);
    expect(excluded('tests.php', 'tests')).toBe(false);
  });

  it('gwiazdka nie przekracza granicy katalogu, podwójna przekracza', () => {
    expect(excluded('src/a.php', 'src/*.php')).toBe(true);
    expect(excluded('src/sub/a.php', 'src/*.php')).toBe(false);
    expect(excluded('src/a/b/legacy/x.php', 'src/**/legacy')).toBe(true);
    expect(excluded('src/legacy/x.php', 'src/**/legacy')).toBe(true);
    expect(excluded('lib/legacy/x.php', 'src/**/legacy')).toBe(false);
    expect(excluded('web/node_modules/pkg/a.php', '**/node_modules/**')).toBe(true);
  });

  it('wzorzec z rozszerzeniem łapie plik na każdej głębokości', () => {
    expect(excluded('app.min.php', '*.min.php')).toBe(true);
    expect(excluded('assets/js/app.min.php', '*.min.php')).toBe(true);
    expect(excluded('assets/js/app.php', '*.min.php')).toBe(false);
  });

  it('ukośnik na końcu oznacza katalog, nie plik o tej nazwie', () => {
    expect(excluded('vendor/lib/a.php', 'vendor/')).toBe(true);
    expect(excluded('vendor', 'vendor/')).toBe(false);
    expect(excluded('vendor', 'vendor')).toBe(true);
  });

  it('ukośnik albo ./ na początku zakotwicza wzorzec w katalogu z ustawieniami', () => {
    expect(excluded('vendor/a.php', '/vendor')).toBe(true);
    expect(excluded('plugin/vendor/a.php', '/vendor')).toBe(false);
    expect(excluded('vendor/a.php', './vendor')).toBe(true);
    expect(excluded('plugin/vendor/a.php', './vendor')).toBe(false);
    expect(excluded('plugin/vendor/a.php', 'plugin/vendor')).toBe(true);
    expect(excluded('other/plugin/vendor/a.php', 'plugin/vendor')).toBe(false);
  });

  it('znak zapytania zastępuje jeden znak poza ukośnikiem', () => {
    expect(excluded('file1.php', 'file?.php')).toBe(true);
    expect(excluded('file12.php', 'file?.php')).toBe(false);
  });

  it('znaki specjalne wyrażeń regularnych są traktowane dosłownie', () => {
    expect(excluded('a+b.php', 'a+b.php')).toBe(true);
    expect(excluded('aab.php', 'a+b.php')).toBe(false);
    expect(excluded('(x).php', '(x).php')).toBe(true);
    expect(excluded('axphp', 'a.php')).toBe(false);
  });

  it('akceptuje ukośniki odwrotne ze ścieżek Windows', () => {
    expect(excluded('src\\tests\\a.php', 'tests')).toBe(true);
    expect(excluded('src/a.php', 'src\\*.php')).toBe(true);
  });

  it('pusta lista wzorców niczego nie wyklucza', () => {
    expect(excluded('a.php')).toBe(false);
  });
});
