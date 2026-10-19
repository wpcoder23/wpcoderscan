// Reguła: odczyt, zapis i usuwanie plików pod ścieżką pochodzącą od użytkownika (path traversal).
// Ścieżka z superglobala wprost to wykrycie pewne. Zmienna zasilona danymi użytkownika to heurystyka.
// Nie zgłaszamy ścieżki oczyszczonej przez basename albo sanitize_file_name, ścieżki sprawdzonej w tej samej
// funkcji (validate_file, realpath, szukanie "..") ani adresu z ustalonym hostem, bo to nie jest odczyt
// lokalnego pliku. Funkcje, które czytają adres z danych użytkownika, obejmuje reguła SSRF.
// Pomijamy też ścieżkę, w której dane stoją tylko w nazwie pliku za stałym fragmentem ('img-' . $id), oraz
// odczyt i usunięcie pliku o stałym, niegroźnym rozszerzeniu. Za bramką administratora wynik jest słabą wskazówką.
import { walk } from '../parser';
import { asNode, calledName, callArgs, nodeStart, offsetName, type AnyNode } from './ast-utils';
import { linkCallers } from './callers';
import { findShortcodeHandlers } from './shortcodes';
import {
  adminGated,
  downgradeGated,
  enclosingScope,
  fixedExtension,
  gradeHit,
  hostIsFixed,
  pathGuardedVars,
  taintOnlyInNameFragments,
} from './sink-utils';
import { chainParts, literalString, PATH_SPEC, TaintAnalyzer } from './taint';
import type { Finding, FileContext, Rule, Severity } from './types';

type Op = 'read' | 'write' | 'delete';

interface Target {
  op: Op;
  arg: number; // pozycja argumentu ze ścieżką
}

// Funkcje plikowe i argumenty, które niosą ścieżkę.
const SINKS: Record<string, Target[]> = {
  unlink: [{ op: 'delete', arg: 0 }],
  wp_delete_file: [{ op: 'delete', arg: 0 }],
  file_put_contents: [{ op: 'write', arg: 0 }],
  copy: [
    { op: 'read', arg: 0 },
    { op: 'write', arg: 1 },
  ],
  rename: [
    { op: 'delete', arg: 0 },
    { op: 'write', arg: 1 },
  ],
  file_get_contents: [{ op: 'read', arg: 0 }],
  readfile: [{ op: 'read', arg: 0 }],
  file: [{ op: 'read', arg: 0 }],
  fopen: [{ op: 'read', arg: 0 }],
  parse_ini_file: [{ op: 'read', arg: 0 }],
  simplexml_load_file: [{ op: 'read', arg: 0 }],
  highlight_file: [{ op: 'read', arg: 0 }],
  show_source: [{ op: 'read', arg: 0 }],
};

// Metody globalnego obiektu $wp_filesystem.
const FILESYSTEM_METHODS: Record<string, Target[]> = {
  delete: [{ op: 'delete', arg: 0 }],
  get_contents: [{ op: 'read', arg: 0 }],
  get_contents_array: [{ op: 'read', arg: 0 }],
  put_contents: [{ op: 'write', arg: 0 }],
  move: [
    { op: 'delete', arg: 0 },
    { op: 'write', arg: 1 },
  ],
  copy: [
    { op: 'read', arg: 0 },
    { op: 'write', arg: 1 },
  ],
};

const MESSAGE = { read: 'file.read.message', write: 'file.write.message', delete: 'file.delete.message' } as const;

const FIRM: Record<Op, Severity> = { read: 'high', write: 'critical', delete: 'high' };
const HEURISTIC: Record<Op, Severity> = { read: 'medium', write: 'high', delete: 'medium' };

// Rozszerzenia dopisane na stałe, przy których odczyt albo usunięcie pliku niczego groźnego nie ujawnia.
const HARMLESS_EXTENSIONS = new Set([
  'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'ico', 'svg', 'mp3', 'mp4', 'webm', 'ogg', 'wav', 'pdf',
  'css', 'csv', 'txt', 'md', 'json',
]);

// fopen z trybem zapisu (w, a, x, c) zapisuje, a nie czyta.
function fopenWrites(call: AnyNode): boolean {
  const mode = literalString(callArgs(call)[1]);
  return mode !== undefined && !mode.startsWith('r');
}

export const filePathRule: Rule = {
  id: 'wp.file.path_traversal',
  titleKey: 'rule.wp.file.path_traversal.title',
  severity: 'high',
  confidence: 'firm',
  cwe: ['CWE-22'],
  asvs: ['12.3.1'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const taint = new TaintAnalyzer(ctx.ast, PATH_SPEC);
    // Atrybuty shortcode pochodzą od autora wpisu, więc są danymi użytkownika.
    for (const h of findShortcodeHandlers(ctx.ast, ctx.code)) taint.seed(h.scope, h.param, 'shortcode');
    linkCallers(taint, ctx.ast, ctx.code);

    walk(ctx.ast, (node, stack) => {
      const n = node as AnyNode;
      if (n.kind !== 'call') return;

      let name = calledName(n);
      let targets = name ? SINKS[name] : undefined;
      if (name === 'fopen' && fopenWrites(n)) targets = [{ op: 'write', arg: 0 }];
      if (!targets) {
        const what = asNode(n.what);
        const base = what && what.kind === 'propertylookup' ? asNode(what.what) : undefined;
        if (base && base.kind === 'variable' && base.name === 'wp_filesystem') {
          name = offsetName(what?.offset);
          targets = name ? FILESYSTEM_METHODS[name] : undefined;
          if (name) name = `$wp_filesystem->${name}`;
        }
      }
      if (!name || !targets) return;

      const args = callArgs(n);
      const scope = enclosingScope(stack, ctx.ast);
      for (const target of targets) {
        const expr = args[target.arg];
        if (!expr) continue;

        // Adres z ustalonym hostem to nie jest odczyt lokalnego pliku.
        const parts: AnyNode[] = [];
        chainParts(expr, parts);
        const head = literalString(parts[0]);
        if (head !== undefined && /^[a-z][a-z0-9+.-]*:\/\//i.test(head) && hostIsFixed(head)) continue;

        const hit = taint.analyze(expr, stack, n);
        const found = gradeHit(hit, FIRM[target.op], HEURISTIC[target.op], ctx.t);
        if (!found) continue;
        if (hit.viaVar && hit.via && pathGuardedVars(scope).has(hit.via)) continue;
        if (taintOnlyInNameFragments(taint, stack, expr)) continue;
        // Stałe, niegroźne rozszerzenie: odczyt i usunięcie pomijamy, a zapis tylko nie wykonuje kodu, więc jest słabszy.
        const ext = fixedExtension(stack, expr);
        const harmless = ext !== undefined && HARMLESS_EXTENSIONS.has(ext);
        if (harmless && target.op !== 'write') continue;
        const grade = harmless || adminGated(scope, hit, taint) ? downgradeGated(found) : found;

        const loc = nodeStart(n);
        findings.push({
          ruleId: filePathRule.id,
          severity: grade.severity,
          confidence: grade.confidence,
          message: ctx.t(MESSAGE[target.op], { name, from: grade.from }),
          file: ctx.file,
          line: loc?.line ?? 1,
          column: loc?.column ?? 0,
          cwe: target.op === 'write' ? ['CWE-22', 'CWE-73'] : ['CWE-22'],
          asvs: ['12.3.1'],
          fix: ctx.t('file.fix'),
        });
        break; // jedno znalezisko na wywołanie
      }
    });

    return findings;
  },
};
