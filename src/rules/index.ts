// Rejestr reguł. Kolejne klasy podatności dokładamy tutaj.
import type { Rule } from './types';
import { sqliRule } from './sqli';
import { restPermissionRule } from './rest';
import { rceRule } from './rce';
import { unserializeRule } from './unserialize';
import { registerSettingRule } from './register-setting';
import { secretsRule } from './secrets';

export const allRules: Rule[] = [
  sqliRule,
  restPermissionRule,
  rceRule,
  unserializeRule,
  registerSettingRule,
  secretsRule,
];
