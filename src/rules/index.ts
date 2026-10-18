// Rejestr reguł. Kolejne klasy podatności dokładamy tutaj.
import type { Rule } from './types';
import { sqliRule } from './sqli';
import { restPermissionRule } from './rest';
import { rceRule } from './rce';

export const allRules: Rule[] = [sqliRule, restPermissionRule, rceRule];
