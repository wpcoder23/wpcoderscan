// Proste wzorce ścieżek dla pola exclude w .wpcoderscan.json. Bez zależności.
//   *   dowolne znaki poza ukośnikiem
//   **  dowolna liczba katalogów
//   ?   jeden znak poza ukośnikiem
// Wzorzec bez ukośnika działa na każdej głębokości (tests, *.min.php). Ukośnik na końcu oznacza katalog.
// Ukośnik albo ./ na początku zakotwicza wzorzec w katalogu z plikiem konfiguracji (/vendor).
// Wzorzec dopasowujemy do pliku i do każdego katalogu na jego drodze, więc "tests" wyklucza całe drzewo.

export interface GlobPattern {
  source: string;
  re: RegExp;
  dirOnly: boolean;
}

function normalize(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');
}

export function compileGlob(pattern: string): GlobPattern {
  const anchored = /^\.?[\\/]/.test(pattern.trim());
  let p = normalize(pattern.trim());
  const dirOnly = p.endsWith('/');
  if (dirOnly) p = p.replace(/\/+$/, '');
  if (!anchored && !p.includes('/')) p = `**/${p}`;
  let re = '';
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '*') {
      if (p[i + 1] === '*') {
        if (p[i + 2] === '/') {
          re += '(?:.*/)?';
          i += 2;
        } else {
          re += '.*';
          i += 1;
        }
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return { source: pattern, re: new RegExp(`^${re}$`), dirOnly };
}

// relPath: ścieżka względna z ukośnikami, liczona od katalogu z plikiem konfiguracji.
export function isExcluded(relPath: string, patterns: readonly GlobPattern[]): boolean {
  if (patterns.length === 0) return false;
  const parts = normalize(relPath).split('/');
  for (let k = 1; k <= parts.length; k++) {
    const candidate = parts.slice(0, k).join('/');
    const isDir = k < parts.length;
    for (const g of patterns) {
      if (g.dirOnly && !isDir) continue;
      if (g.re.test(candidate)) return true;
    }
  }
  return false;
}
