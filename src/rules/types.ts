// Typy wspólne dla silnika reguł.
// Identyfikatory po angielsku, komunikaty dla użytkownika po polsku.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// Pozycja w pliku. Linie liczone od 1.
export interface Position {
  line: number;
  column: number;
  offset?: number;
}

// Pojedyncze znalezisko zgłaszane przez regułę.
export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string; // po polsku, dla człowieka
  file: string; // ścieżka względna do katalogu skanowania
  line: number;
  column: number;
  endLine?: number;
  snippet?: string; // fragment kodu z okolicy
  cwe?: string[]; // np. ['CWE-89']
  asvs?: string[]; // np. ['5.3.4']
  fix?: string; // krótka wskazówka naprawy, po polsku
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
  cwe?: string[];
  asvs?: string[];
  check(ctx: FileContext): Finding[];
}
