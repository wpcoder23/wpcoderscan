// Typy wspólne dla silnika reguł.
// Identyfikatory po angielsku. Komunikaty dla użytkownika pochodzą z katalogu
// tłumaczeń (src/i18n), więc wynik jest w języku wybranym przy skanie.
import type { Lang, MessageKey, Translate } from '../i18n';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// Poziom pewności reguły. 'firm' to wykrycie strukturalne, pewne, łamie build.
// 'heuristic' to przesłanka, która może być fałszywym alarmem, więc domyślnie
// tylko ostrzega i nie wywala CI. Zasada przyjęta za rekomendacją Fable 5.1.
export type Confidence = 'firm' | 'heuristic';

// Pozycja w pliku. Linie liczone od 1.
export interface Position {
  line: number;
  column: number;
  offset?: number;
}

// Jedna zmiana tekstu pliku. Offsety to indeksy UTF-16 w oryginalnej treści pliku,
// zgodne z pozycjami z parsera. Przedział [start, end) jest zastępowany tekstem replacement.
export interface TextEdit {
  start: number;
  end: number;
  replacement: string;
}

// Podpowiedź naprawy. 'complete' to zmiana, którą można zastosować bez dalszej
// pracy (po przeglądzie). 'manual' wymaga decyzji człowieka, np. doboru kontekstu.
export interface Patch {
  safety: 'complete' | 'manual';
  label: string; // krótki opis zmiany, w języku skanu
  edits: TextEdit[];
}

// Pojedyncze znalezisko zgłaszane przez regułę.
export interface Finding {
  ruleId: string;
  severity: Severity;
  confidence: Confidence; // pewne czy heurystyka
  message: string; // dla człowieka, w języku skanu
  file: string; // ścieżka względna do katalogu skanowania
  line: number;
  column: number;
  endLine?: number;
  snippet?: string; // fragment kodu z okolicy
  cwe?: string[]; // np. ['CWE-89']
  asvs?: string[]; // np. ['5.3.4']
  fix?: string; // krótka wskazówka naprawy, w języku skanu
  patch?: Patch; // konkretna zmiana kodu, gdy da się ją wyliczyć i zweryfikować
  fingerprint?: string; // odcisk stabilny mimo przesunięć linii, ustawia silnik po skanie
}

// Węzeł AST z php-parser. Trzymamy luźny typ, bo biblioteka nie daje pełnych typów.
export interface PhpNode {
  kind: string;
  loc?: { start: Position; end: Position };
  [key: string]: unknown;
}

// Kontekst pojedynczego pliku przekazywany regułom.
export interface FileContext {
  file: string; // ścieżka względna
  absolutePath: string;
  code: string;
  lines: string[]; // kod rozbity na linie, do snippetów
  lang: Lang; // język komunikatów tego skanu
  t: Translate; // tłumaczy klucz z katalogu na język skanu
  ast: PhpNode; // korzeń AST (Program)
  snippetAt(line: number): string; // fragment kodu dla danej linii
}

// Reguła wykrywająca jedną klasę podatności.
export interface Rule {
  id: string; // slug, np. 'wp.sqli.unprepared'
  titleKey: MessageKey; // klucz krótkiego opisu reguły w katalogu tłumaczeń
  severity: Severity; // domyślny poziom
  confidence: Confidence; // domyślny poziom pewności reguły
  cwe?: string[];
  asvs?: string[];
  check(ctx: FileContext): Finding[];
}
