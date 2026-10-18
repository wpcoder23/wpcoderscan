// Rejestr reguł. Kolejne klasy podatności dokładamy tutaj.
import type { Rule } from './types';
import { sqliRule } from './sqli';

export const allRules: Rule[] = [sqliRule];
