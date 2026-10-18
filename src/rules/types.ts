// Typy wspólne dla silnika reguł.
// Identyfikatory po angielsku, komunikaty dla użytkownika po polsku.

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
  label: string; // po polsku, krótki opis zmiany
  edits: TextEdit[];
}

// Pojedyncze znalezisko zgłaszane przez regułę.
export interface Finding {
  ruleId: string;
  severity: Severity;
  confidence: Confidence; // pewne czy heurystyka
  message: string; // po polsku, dla człowieka
  file: string; // ścieżka względna do katalogu skanowania
  line: number;
  column: number;
  endLine?: number;
  snippet?: string; // fragment kodu z okolicy
  cwe?: string[]; // np. ['CWE-89']
  asvs?: string[]; // np. ['5.3.4']
  fix?: string; // krótka wskazówka naprawy, po polsku
  patch?: Patch; // konkretna zmiana kodu, gdy da się ją wyliczyć i zweryfikować
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
  ast: PhpNode; // korzeń AST (Program)
  snippetAt(line: number): string; // fragment kodu dla danej linii
}

// Reguła wykrywająca jedną klasę podatności.
export interface Rule {
  id: string; // slug, np. 'wp.sqli.unprepared'
  title: string; // krótki opis po polsku
  severity: Severity; // domyślny poziom
  confidence: Confidence; // domyślny poziom pewności reguły
  cwe?: string[];
  asvs?: string[];
  check(ctx: FileContext): Finding[];
}
