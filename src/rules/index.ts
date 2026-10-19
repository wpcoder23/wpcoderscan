// Rejestr reguł. Kolejne klasy podatności dokładamy tutaj.
import type { Rule } from './types';
import { sqliRule } from './sqli';
import { restPermissionRule } from './rest';
import { rceRule } from './rce';
import { unserializeRule } from './unserialize';
import { registerSettingRule } from './register-setting';
import { secretsRule } from './secrets';
import { xssEchoRule } from './xss';
import { nonceCapabilityRule } from './nonce-capability';
import { sqliParamRule } from './sqli-param';
import { filePathRule } from './file-path';
import { ssrfRule } from './ssrf';
import { uploadRule } from './upload';
import { privilegeRule } from './privilege';
import { optionUpdateRule } from './option-update';

// Reguły rozszerzone. Mają większą czułość i więcej fałszywych alarmów, więc
// działają tylko z opcją extended (--extended w CLI).
export const extendedRules: Rule[] = [sqliParamRule, filePathRule, ssrfRule, uploadRule, privilegeRule, optionUpdateRule];

export const allRules: Rule[] = [
  sqliRule,
  restPermissionRule,
  rceRule,
  unserializeRule,
  registerSettingRule,
  secretsRule,
  xssEchoRule,
  nonceCapabilityRule,
];
