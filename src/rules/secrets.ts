// Reguła: zaszyte sekrety w kodzie.
// Dwa tryby. Wzorce znanych dostawców (AWS, Stripe, Google, GitHub, klucz
// prywatny) są pewne i mają wysoki poziom. Wykrycie po nazwie zmiennej lub
// stałej (password, secret, api_key) jest heurystyczne, bo bywa fałszywym
// alarmem, więc tylko ostrzega.
import { walk } from '../parser';
import { asNode, calledName, callArgs, offsetName, type AnyNode } from './ast-utils';
import type { Finding, FileContext, Rule, Severity } from './types';

interface ProviderPattern {
  re: RegExp;
  severity: Severity;
  label: string;
  // Domyślnie pewne. Heurystyka tylko ostrzega i nie łamie build.
  confidence?: 'firm' | 'heuristic';
  note?: string;
}

// Wzorce znanych dostawców. Dobrane tak, żeby trafiać w realne klucze,
// a nie w zwykły tekst.
const PROVIDER_PATTERNS: ProviderPattern[] = [
  { re: /\bAKIA[0-9A-Z]{16}\b/, severity: 'critical', label: 'klucz dostępu AWS' },
  { re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/, severity: 'critical', label: 'klucz Stripe (live)' },
  { re: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/, severity: 'critical', label: 'token GitHub' },
  // Klucze Google do map w przeglądarce bywają publiczne z założenia, a ten sam format
  // mają klucze płatnych API. Nie da się tego rozstrzygnąć z kodu, więc tylko ostrzegamy.
  {
    re: /\bAIza[0-9A-Za-z_-]{35}\b/,
    severity: 'high',
    label: 'klucz API Google',
    confidence: 'heuristic',
    note: ' Klucz do map w przeglądarce bywa publiczny z założenia, ale ten sam format mają klucze płatnych API. Sprawdź w konsoli Google, czy klucz ma ograniczenia.',
  },
  { re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, severity: 'high', label: 'token Slack' },
  // Sam nagłówek PEM to zwykle tekst parsera. Klucz to nagłówek i treść base64.
  { re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{40,}/, severity: 'critical', label: 'klucz prywatny' },
  { re: /\bSG\.[\w-]{16,}\.[\w-]{16,}\b/, severity: 'high', label: 'klucz API SendGrid' },
];

// Nazwy sugerujące sekret.
const SECRET_NAME = /(pass(word|wd|phrase)|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)/i;

// Nazwa wygląda jak identyfikator (zmienna, stała, klucz tablicy), nie jak etykieta dla człowieka.
const IDENTIFIER_LIKE = /^[A-Za-z_][\w-]*$/;

// Wartość wygląda jak token: bez spacji, bez cudzysłowów, co najmniej litera i cyfra.
function looksLikeToken(value: string): boolean {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return false; // adres URL, nie sekret
  return value.length >= 12 && !/\s/.test(value) && /[A-Za-z]/.test(value) && /\d/.test(value);
}

// Oczywiste atrapy, których nie zgłaszamy.
const PLACEHOLDER = /(example|changeme|your[_-]?|placeholder|xxxx|dummy|<[^>]+>|\{\{.*\}\}|%s|^\*+$|^\.\.\.$|^$)/i;

function matchProvider(value: string): ProviderPattern | undefined {
  return PROVIDER_PATTERNS.find((p) => p.re.test(value));
}

// Nazwa przypisywanego celu (zmienna, właściwość, stała statyczna).
function assignTargetName(left: unknown): string | undefined {
  const l = asNode(left);
  if (!l) return undefined;
  if (l.kind === 'variable' && typeof l.name === 'string') return l.name;
  if (l.kind === 'propertylookup' || l.kind === 'staticlookup') return offsetName(l.offset);
  return undefined;
}

export const secretsRule: Rule = {
  id: 'wp.secret.hardcoded',
  title: 'Zaszyty sekret w kodzie',
  severity: 'high',
  confidence: 'firm',
  cwe: ['CWE-798'],
  asvs: ['6.4.1'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];

    const emit = (
      node: AnyNode,
      severity: Severity,
      confidence: 'firm' | 'heuristic',
      message: string,
    ) => {
      const loc = (node.loc as { start?: { line: number; column: number } } | undefined)?.start;
      findings.push({
        ruleId: secretsRule.id,
        severity,
        confidence,
        message,
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: secretsRule.cwe,
        asvs: secretsRule.asvs,
        fix: 'Przenieś sekret poza kod, do zmiennej środowiskowej albo do wp-config.php poza repozytorium. Jeśli trafił do repo, rotuj go.',
      });
    };

    // Przypisania sekretu do nazwanego celu oceniamy po nazwie.
    const nameBased = (nameSource: string, valueNode: AnyNode | undefined): boolean => {
      const v = asNode(valueNode);
      if (!v || v.kind !== 'string' || typeof v.value !== 'string') return false;
      const value = v.value;
      if (matchProvider(value)) return false; // pokryje to przebieg dostawców
      if (!IDENTIFIER_LIKE.test(nameSource) || !SECRET_NAME.test(nameSource)) return false;
      if (!looksLikeToken(value) || PLACEHOLDER.test(value)) return false;
      emit(
        v,
        'medium',
        'heuristic',
        `Wartość przypisana do "${nameSource}" wygląda na zaszyty sekret.`,
      );
      return true;
    };

    walk(ctx.ast, (node) => {
      const n = node as AnyNode;

      // Przebieg dostawców na każdym literale tekstowym.
      if (n.kind === 'string' && typeof n.value === 'string') {
        const hit = matchProvider(n.value);
        if (hit) emit(n, hit.severity, hit.confidence ?? 'firm', `Wykryto ${hit.label} zaszyty w kodzie.${hit.note ?? ''}`);
        return;
      }

      if (n.kind === 'assign') {
        const name = assignTargetName(n.left);
        if (name) nameBased(name, asNode(n.right));
        return;
      }

      if (n.kind === 'entry') {
        const key = asNode(n.key);
        if (key && key.kind === 'string' && typeof key.value === 'string') {
          nameBased(key.value, asNode(n.value));
        }
        return;
      }

      if (calledName(n) === 'define') {
        const args = callArgs(n);
        const nameArg = asNode(args[0]);
        if (nameArg && nameArg.kind === 'string' && typeof nameArg.value === 'string') {
          nameBased(nameArg.value, asNode(args[1]));
        }
      }
    });

    return findings;
  },
};
