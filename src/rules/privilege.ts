// Reguła: rola, logowanie i klucz meta użytkownika sterowane danymi z żądania (eskalacja uprawnień).
// Cztery postacie. Rola z żądania przekazana do wp_insert_user, wp_update_user, set_role albo add_role.
// Klucz meta użytkownika z żądania, przez który atakujący może zapisać wp_capabilities. Wartość zapisana do
// meta uprawnień. Oraz logowanie użytkownika wskazanego przez żądanie (wp_set_auth_cookie, wp_set_current_user),
// gdy nic w tej funkcji nie potwierdza, kim jest odwiedzający.
// Funkcja za bramką na uprawnienie administratora (current_user_can( 'promote_users' )) nie jest zgłaszana,
// bo wybór roli należy wtedy do administratora. To samo dotyczy bramki w funkcji, która ją woła.
// Logowanie w funkcji, która sprawdza środowisko deweloperskie, też pomijamy, bo na produkcji nie działa.
import { walk } from '../parser';
import { asNode, baseVariable, calledName, callArgs, nodeStart, offsetName, SUPERGLOBALS, type AnyNode } from './ast-utils';
import { linkCallers } from './callers';
import { adminGated, callsAny, callsMatching, devGated, enclosingScope, gradeHit, leadingTaint, scopeGatedByCallers } from './sink-utils';
import { KEY_SPEC, literalString, LOGIN_SPEC, TaintAnalyzer, type TaintHit } from './taint';
import type { Finding, FileContext, PhpNode, Rule } from './types';

const USER_WRITERS = new Set(['wp_insert_user', 'wp_update_user']);
const ROLE_METHODS = new Set(['set_role', 'add_role', 'add_cap']);
const LOGIN_SINKS = new Set(['wp_set_auth_cookie', 'wp_set_current_user']);
const META_WRITERS = new Set(['update_user_meta', 'add_user_meta']);

// Funkcje, którymi kod potwierdza tożsamość odwiedzającego przed zalogowaniem. Nonce nie jest dowodem
// tożsamości, bo dostaje go każdy odwiedzający, więc nie ma go na liście. Wywołanie żądania do dostawcy
// logowania uznajemy za weryfikację tokenu.
const IDENTITY_CHECKS = new Set([
  'wp_check_password', 'wp_authenticate', 'wp_authenticate_username_password', 'wp_signon', 'check_password_reset_key',
  'hash_equals', 'password_verify', 'wp_validate_auth_cookie', 'openssl_verify', 'hash_hmac',
  'wp_remote_get', 'wp_remote_post', 'wp_remote_request', 'wp_safe_remote_get', 'wp_safe_remote_post',
  'current_user_can', 'is_super_admin', 'user_can',
]);

// Funkcje i metody własnego kodu, które po nazwie weryfikują odwiedzającego: verifyToken(), validate_request(),
// authenticate(), decode_jwt(), check_signature(). Samo wołanie wp_set_auth_cookie nie pasuje do tego wzorca.
const IDENTITY_NAME = /(?:^|_)(?:verif\w*|valid\w*|authenticat\w*|authoriz\w*|oauth\w*|jwt|signature|credential\w*|otp|two_factor|2fa)(?:_|$)/;

// Czy w poddrzewie jest tekst wskazujący na uprawnienia użytkownika ($wpdb->prefix . 'capabilities').
function mentionsCapabilities(node: unknown): boolean {
  if (Array.isArray(node)) return (node as unknown[]).some(mentionsCapabilities);
  const n = asNode(node);
  if (!n) return false;
  if (n.kind === 'string' && typeof n.value === 'string') return /capabilities|user_level/i.test(n.value);
  for (const k of Object.keys(n)) {
    if (k === 'loc' || k === 'leadingComments' || k === 'trailingComments') continue;
    const v = n[k];
    if (v && typeof v === 'object' && mentionsCapabilities(v)) return true;
  }
  return false;
}

function verifiesIdentity(scope: AnyNode): boolean {
  return callsAny(scope, IDENTITY_CHECKS) || callsMatching(scope, IDENTITY_NAME);
}

export const privilegeRule: Rule = {
  id: 'wp.privilege.escalation',
  titleKey: 'rule.wp.privilege.escalation.title',
  severity: 'critical',
  confidence: 'firm',
  cwe: ['CWE-269'],
  asvs: ['4.1.1'],
  check(ctx: FileContext): Finding[] {
    const findings: Finding[] = [];
    const keyTaint = new TaintAnalyzer(ctx.ast, KEY_SPEC);
    const loginTaint = new TaintAnalyzer(ctx.ast, LOGIN_SPEC);
    linkCallers(keyTaint, ctx.ast, ctx.code);
    linkCallers(loginTaint, ctx.ast, ctx.code);

    const push = (
      n: AnyNode,
      severity: Finding['severity'],
      confidence: Finding['confidence'],
      message: string,
      fix: string,
    ) => {
      const loc = nodeStart(n);
      findings.push({
        ruleId: privilegeRule.id,
        severity,
        confidence,
        message,
        file: ctx.file,
        line: loc?.line ?? 1,
        column: loc?.column ?? 0,
        cwe: ['CWE-269'],
        asvs: ['4.1.1'],
        fix,
      });
    };

    // Czy funkcja albo wywołanie, które przekazało jej dane, potwierdza tożsamość odwiedzającego.
    const confirmsIdentity = (scope: AnyNode, hit: TaintHit): boolean => {
      if (verifiesIdentity(scope)) return true;
      if (hit.source !== 'caller' || !hit.via) return false;
      return loginTaint
        .seedSites(scope, hit.via)
        .some((site) => site.kind !== 'program' && verifiesIdentity(site));
    };

    // Rola ustawiana w tablicy danych użytkownika: 'role' => $x albo $dane['role'] = $x.
    const checkRoleValue = (at: AnyNode, value: unknown, stack: PhpNode[]) => {
      const scope = enclosingScope(stack, ctx.ast);
      if (!callsAny(scope, USER_WRITERS)) return;
      const hit = keyTaint.analyze(value, stack, at);
      const grade = gradeHit(hit, 'critical', 'high', ctx.t);
      if (!grade || adminGated(scope, hit, keyTaint)) return;
      push(at, grade.severity, grade.confidence, ctx.t('privilege.role.message', { from: grade.from }), ctx.t('privilege.role.fix'));
    };

    walk(ctx.ast, (node, stack: PhpNode[]) => {
      const n = node as AnyNode;

      if (n.kind === 'entry') {
        const key = literalString(n.key);
        if (key !== undefined && key.toLowerCase() === 'role') checkRoleValue(n, n.value, stack);
        return;
      }

      if (n.kind === 'assign') {
        const left = asNode(n.left);
        if (left && left.kind === 'offsetlookup' && literalString(left.offset)?.toLowerCase() === 'role') {
          checkRoleValue(n, n.right, stack);
        }
        return;
      }

      if (n.kind !== 'call') return;
      const name = calledName(n);
      const args = callArgs(n);
      const scope = enclosingScope(stack, ctx.ast);

      // $user->set_role( $x ), $user->add_role( $x ), $user->add_cap( $x ).
      if (!name) {
        const what = asNode(n.what);
        const method = what && what.kind === 'propertylookup' ? offsetName(what.offset) : undefined;
        if (method && ROLE_METHODS.has(method) && args[0]) {
          const hit = keyTaint.analyze(args[0], stack, n);
          const grade = gradeHit(hit, 'critical', 'high', ctx.t);
          if (grade && !adminGated(scope, hit, keyTaint)) {
            push(n, grade.severity, grade.confidence, ctx.t('privilege.setrole.message', { name: `${method}()`, from: grade.from }), ctx.t('privilege.role.fix'));
          }
        }
        return;
      }

      // wp_insert_user( $_POST ): całe żądanie jako dane użytkownika, więc żądanie ustawia też rolę.
      if (USER_WRITERS.has(name) && args[0]) {
        const base = baseVariable(args[0]);
        const isWholeRequest = !!base && base.kind === 'variable' && SUPERGLOBALS.has(base.name as string) && base.name !== '_SERVER' && base.name !== '_FILES';
        if (isWholeRequest && !scopeGatedByCallers(scope, ctx.ast)) {
          push(n, 'high', 'firm', ctx.t('privilege.userdata.message', { name }), ctx.t('privilege.role.fix'));
        }
        return;
      }

      // update_user_meta( $id, $klucz, $wartość ): klucz z żądania pozwala zapisać wp_capabilities.
      if (META_WRITERS.has(name) && args[1]) {
        const keyHit = leadingTaint(keyTaint, args[1], stack, n, (text) => text.length > 0);
        const grade = gradeHit(keyHit, 'critical', 'high', ctx.t);
        if (grade) {
          if (!adminGated(scope, keyHit, keyTaint)) {
            push(n, grade.severity, grade.confidence, ctx.t('privilege.meta.message', { name, from: grade.from }), ctx.t('privilege.meta.fix'));
          }
          return;
        }
        // Klucz uprawnień zapisywany wartością z żądania.
        if (args[2] && mentionsCapabilities(args[1])) {
          const valueHit = keyTaint.analyze(args[2], stack, n);
          const valueGrade = gradeHit(valueHit, 'critical', 'high', ctx.t);
          if (valueGrade && !adminGated(scope, valueHit, keyTaint)) {
            push(n, valueGrade.severity, valueGrade.confidence, ctx.t('privilege.caps.message', { name, from: valueGrade.from }), ctx.t('privilege.role.fix'));
          }
        }
        return;
      }

      // wp_set_auth_cookie( $id ), wp_set_current_user( $id ) z identyfikatorem wskazanym przez żądanie.
      if (LOGIN_SINKS.has(name) && args[0]) {
        const hit = loginTaint.analyze(args[0], stack, n);
        const grade = gradeHit(hit, 'critical', 'high', ctx.t);
        if (!grade || confirmsIdentity(scope, hit) || devGated(scope)) return;
        push(n, grade.severity, grade.confidence, ctx.t('privilege.login.message', { name, from: grade.from }), ctx.t('privilege.login.fix'));
      }
    });

    return findings;
  },
};
