// Nakładanie zmian tekstowych na treść pliku.
// Zmiany liczymy z offsetów AST, nie z wyszukiwania tekstu, więc nie ma
// niejednoznacznych dopasowań. Nakładanie się zakresów odrzucamy.
import type { Patch, TextEdit } from '../rules/types';

// Zwraca nową treść albo null, gdy zmiany są niepoprawne albo nachodzą na siebie.
export function applyEdits(code: string, edits: TextEdit[]): string | null {
  const sorted = [...edits].sort((a, b) => a.start - b.start || a.end - b.end);
  let out = '';
  let pos = 0;
  for (const e of sorted) {
    if (e.start < pos || e.end < e.start || e.end > code.length || e.start < 0) return null;
    out += code.slice(pos, e.start) + e.replacement;
    pos = e.end;
  }
  return out + code.slice(pos);
}

// Czy dwie podpowiedzi dotykają tego samego miejsca. Wstawienia w tym samym
// punkcie też traktujemy jako konflikt, bo kolejność byłaby niejednoznaczna.
export function patchesConflict(a: Patch, b: Patch): boolean {
  for (const x of a.edits) {
    for (const y of b.edits) {
      if (x.start === y.start) return true;
      if (x.start < y.end && y.start < x.end) return true;
    }
  }
  return false;
}
