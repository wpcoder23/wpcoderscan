// Rejestr reguł. Kolejne klasy podatności dokładamy tutaj.
import type { Rule } from './types';
import { sqliRule } from './sqli';
import { restPermissionRule } from './rest';

export const allRules: Rule[] = [sqliRule, restPermissionRule];
