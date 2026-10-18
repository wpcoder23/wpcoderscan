// Wykrywanie stylu kodu w pliku, żeby poprawka wyglądała jak reszta kodu.
// Standard WordPressa wymaga spacji wewnątrz nawiasów i tablic array(),
// ale część wtyczek pisze ciasno albo krótką składnią. Idziemy za plikiem.

export type ParenStyle = 'spaced' | 'tight';
export type ArrayStyle = 'long' | 'short';

// Wywołania funkcji ze spacją po nawiasie otwierającym: foo( $x ).
const SPACED_CALL = /[A-Za-z_]\( [^\s)]/g;
// Wywołania ciasne: foo($x).
const TIGHT_CALL = /[A-Za-z_]\([^\s)]/g;

function count(re: RegExp, code: string): number {
  const m = code.match(re);
  return m ? m.length : 0;
}

export function detectParenStyle(code: string): ParenStyle {
  const spaced = count(SPACED_CALL, code);
  const tight = count(TIGHT_CALL, code);
  // Przy remisie (lub braku wywołań) wybieramy styl WordPressa.
  return spaced >= tight ? 'spaced' : 'tight';
}

// Tablice długie: array( ... ). Krótkie: [ ... ] po znaku przypisania, przecinku lub nawiasie.
const LONG_ARRAY = /\barray\s*\(/gi;
const SHORT_ARRAY = /(?:=|=>|,|\()\s*\[/g;

export function detectArrayStyle(code: string): ArrayStyle {
  const long = count(LONG_ARRAY, code);
  const short = count(SHORT_ARRAY, code);
  return long >= short ? 'long' : 'short';
}

// Składa wywołanie funkcji z jednym argumentem w stylu pliku.
export function wrapCall(fn: string, style: ParenStyle): { open: string; close: string } {
  return style === 'spaced' ? { open: `${fn}( `, close: ' )' } : { open: `${fn}(`, close: ')' };
}

// Tekst dodatkowego argumentu allowed_classes => false w stylu pliku.
export function allowedClassesArg(paren: ParenStyle, array: ArrayStyle): string {
  const pad = paren === 'spaced' ? ' ' : '';
  if (array === 'short') return `[${pad}'allowed_classes' => false${pad}]`;
  return `array(${pad}'allowed_classes' => false${pad})`;
}
