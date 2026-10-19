// Reguła: zapis wysłanego pliku pod nazwą od klienta bez sprawdzenia rozszerzenia i typu.
// move_uploaded_file z miejscem docelowym zbudowanym z nazwy pliku użytkownika pozwala wysłać skrypt PHP,
// o ile funkcja nie sprawdza typu pliku. Za sprawdzenie uznajemy wołanie funkcji rdzenia i PHP, które
// weryfikują typ (wp_check_filetype, getimagesize, finfo), odczyt rozszerzenia razem z porównaniem,
// porównanie pola typu z listą, sprawdzenie końcówki nazwy (ends_with( $nazwa, '.json' )) oraz własną funkcję
// o nazwie walidującej plik. Sprawdzenie liczy się, gdy stoi przed zapisem. Sprawdzenie po zapisie liczy się
// tylko wtedy, gdy funkcja potem usuwa plik. wp_check_filetype po wysłaniu służy zwykle do odczytu typu,
// a nie do jego egzekwowania.
// Druga postać to wp_handle_upload z wyłączonym sprawdzaniem typu ('test_type' => false).
// Za bramką administratora wynik jest słabą wskazówką.
import { walk } from '../parser';
import { asNode, calledName, callArgs, entryKeyName, findEntry, nodeStart, type AnyNode } from './ast-utils';
import { linkCallers } from './callers';
import { adminGated, calleeName, downgradeGated, enclosingScope, fixedExtension, gradeHit, type Grade } from './sink-utils';
import { literalString, TaintAnalyzer, UPLOAD_SPEC, type TaintHit } from './taint';
import type { Finding, FileContext, PhpNode, Rule } from './types';

// Funkcje, które sprawdzają typ pliku. Samo wywołanie uznajemy za sprawdzenie.
const TYPE_CHECKS = new Set([
  'wp_check_filetype',
  'wp_check_filetype_and_ext',
  'wp_get_image_mime',
  'getimagesize',
  'exif_imagetype',
  'mime_content_type',
  'finfo_open',
  'finfo_file',
  'image_type_to_extension',
  'image_type_to_mime_type',
]);

// Porównanie rozszerzenia z listą albo wzorcem.
const EXT_COMPARERS = new Set(['in_array', 'preg_match', 'strcasecmp', 'strcmp', 'array_search']);

// Własna funkcja albo metoda, która po nazwie waliduje wysyłany plik: is_allowed_file_type(), validateUpload().
// Samo "allowed" nie wystarcza, bo et_pb_is_allowed( 'theme_builder' ) pyta o uprawnienia, a nie o typ pliku.
const TYPE_CHECK_NAME =
  /(?:^|_)(?:valid\w*|(?:allowed|permitted|supported|accepted)_(?:file|type|ext|mime|image|format)\w*|(?:file|type|ext|mime|image|format)\w*_(?:allowed|permitted|supported|accepted)|mimes?|file_?types?|extensions?|whitelist\w*|is_(?:image|safe)\w*|check_(?:file|upload|type|ext)\w*)(?:_|$)/;

// Pola wpisu pliku, w których klient podaje typ albo rozszerzenie.
const TYPE_KEYS = new Set(['type', 'ext', 'extension', 'mime', 'mime_type']);

// Sprawdzenie końcówki nazwy: ends_with( $nazwa, '.json' ), str_ends_with( $nazwa, '.csv' ).
const ENDS_WITH = /^(?:str_)?ends_?with$/;
const EXTENSION_LITERAL = /^\.[a-z0-9]{2,5}$/i;
// Wzorzec kończący się rozszerzeniem: '/\.(jpe?g|png)$/i'.
const EXTENSION_PATTERN = /\\\.\(?[a-z0-9|?:]+\)?\$/i;

// Funkcje usuwające plik.
const FILE_REMOVERS = new Set(['unlink', 'wp_delete_file']);

// Czy w poddrzewie jest odczyt pola typu pliku: $plik['type'], $_FILES['x']['type'].
function readsTypeField(node: unknown): boolean {
  if (Array.isArray(node)) return (node as unknown[]).some(readsTypeField);
  const n = asNode(node);
  if (!n) return false;
  if (n.kind === 'offsetlookup') {
    const key = literalString(n.offset);
    if (key !== undefined && TYPE_KEYS.has(key)) return true;
  }
  for (const k of Object.keys(n)) {
    if (k === 'loc' || k === 'leadingComments' || k === 'trailingComments') continue;
    const v = n[k];
    if (v && typeof v === 'object' && readsTypeField(v)) return true;
  }
  return false;
}

function startOffset(n: AnyNode): number {
  const loc = n.loc as { start?: { offset?: number } } | undefined;
  return loc?.start?.offset ?? Number.MAX_SAFE_INTEGER;
}

// Ślady sprawdzania typu w jednej części funkcji (przed zapisem albo po nim).
interface Evidence {
  check: boolean; // samo w sobie wystarcza
  read: boolean; // odczyt rozszerzenia: pathinfo, strrchr, substr
  end: boolean;
  explode: boolean;
  compare: boolean; // porównanie z listą albo wzorcem
}

const newEvidence = (): Evidence => ({ check: false, read: false, end: false, explode: false, compare: false });
const sufficient = (e: Evidence): boolean => e.check || ((e.read || (e.end && e.explode)) && e.compare);

function note(e: Evidence, call: AnyNode): void {
  const fn = calledName(call);
  const name = calleeName(call);
  const args = callArgs(call);
  if (fn) {
    if (TYPE_CHECKS.has(fn)) e.check = true;
    if (fn === 'pathinfo' || fn === 'strrchr' || fn === 'substr') e.read = true;
    if (fn === 'end') e.end = true;
    if (fn === 'explode') e.explode = true;
    if (EXT_COMPARERS.has(fn)) {
      e.compare = true;
      if (readsTypeField(call.arguments)) e.check = true;
    }
    if (fn === 'preg_match') {
      const pattern = literalString(args[0]);
      if (pattern !== undefined && EXTENSION_PATTERN.test(pattern)) e.check = true;
    }
  }
  if (!name) return;
  if (!/nonce|referer/.test(name) && TYPE_CHECK_NAME.test(name)) e.check = true;
  if (ENDS_WITH.test(name) && args.some((a) => EXTENSION_LITERAL.test(literalString(a) ?? ''))) e.check = true;
}

// Czy funkcja sprawdza typ pliku przed zapisem (sink).
function validatesType(scope: AnyNode, sink: AnyNode): boolean {
  const at = startOffset(sink);
  const before = newEvidence();
  const after = newEvidence();
  let removesAfter = false;
  walk(scope, (node) => {
    const n = node as AnyNode;
    const early = startOffset(n) < at;
    const e = early ? before : after;
    if (n.kind === 'call') {
      note(e, n);
      const fn = calledName(n);
      if (!early && fn && FILE_REMOVERS.has(fn)) removesAfter = true;
    } else if (n.kind === 'bin' && ['==', '!=', '===', '!=='].includes(String(n.type))) {
      if (readsTypeField(n.left) || readsTypeField(n.right)) e.check = true;
    }
  });
  if (sufficient(before)) return true;
  // Sprawdzenie po zapisie ma sens, gdy funkcja usuwa plik, który go nie przeszedł.
  if (!removesAfter) return false;
  return sufficient({
    check: before.check || after.check,
    read: before.read || after.read,
    end: before.end || after.end,
    explode: before.explode || after.explode,
    compare: before.compare || after.compare,
  });
}

// Rozszerzenie, po którym serwer wykona plik. Stałe rozszerzenie PHP nie chroni, bo treść pliku wybiera klient.
const EXECUTABLE_EXTENSION = /^(?:php\d?|phtml|pht|phar|phps|inc|shtml|cgi|pl|py|sh|asp|aspx|jsp)$/;

const UPLOAD_HANDLERS = new Set(['wp_handle_upload', 'wp_handle_sideload']);

export const uploadRule: Rule = {
  id: 'wp.upload.unrestricted',
  titleKey: 'rule.wp.upload.unrestricted.title',
  severity: 'critical',
  confidence: 'firm',
  cwe: ['CWE-434'],
  asvs: ['12.1.2'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const taint = new TaintAnalyzer(ctx.ast, UPLOAD_SPEC);
    linkCallers(taint, ctx.ast, ctx.code);

    const push = (n: AnyNode, grade: Pick<Grade, 'severity' | 'confidence'>, message: string) => {
      const loc = nodeStart(n);
      findings.push({
        ruleId: uploadRule.id,
        severity: grade.severity,
        confidence: grade.confidence,
        message,
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: ['CWE-434'],
        asvs: ['12.1.2'],
        fix: ctx.t('upload.fix'),
      });
    };

    walk(ctx.ast, (node, stack: PhpNode[]) => {
      const n = node as AnyNode;
      if (n.kind !== 'call') return;
      const name = calledName(n);
      if (!name) return;
      const args = callArgs(n);
      const scope = enclosingScope(stack, ctx.ast);

      if (name === 'move_uploaded_file' && args[1]) {
        const ext = fixedExtension(stack, args[1]);
        if (ext !== undefined && !EXECUTABLE_EXTENSION.test(ext)) return;
        const hit = taint.analyze(args[1], stack, n);
        const found = gradeHit(hit, 'critical', 'high', ctx.t);
        if (!found || validatesType(scope, n)) return;
        const grade = adminGated(scope, hit, taint) ? downgradeGated(found) : found;
        push(n, grade, ctx.t('upload.move.message', { from: grade.from }));
        return;
      }

      if (UPLOAD_HANDLERS.has(name)) {
        const overrides = asNode(args[1]);
        const entry = overrides && overrides.kind === 'array' ? findEntry(overrides, 'test_type') : undefined;
        const value = asNode(entry?.value);
        const off = value?.kind === 'boolean' && value.value === false;
        if (!entry || entryKeyName(entry) !== 'test_type' || !off || validatesType(scope, n)) return;
        // Plik z żądania to pewne wykrycie. Plik o nieznanym pochodzeniu (pobrany, wskazany przez parametr) jest słabszy.
        const hit: TaintHit = args[0] ? taint.analyze(args[0], stack, n) : { direct: false, viaVar: false };
        const found = gradeHit(hit, 'high', 'high', ctx.t);
        const grade: Pick<Grade, 'severity' | 'confidence'> =
          found && !adminGated(scope, hit, taint)
            ? found
            : { severity: found || name === 'wp_handle_sideload' ? 'low' : 'medium', confidence: 'heuristic' };
        push(n, grade, ctx.t('upload.notype.message', { name }));
      }
    });

    return findings;
  },
};
