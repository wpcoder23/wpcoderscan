// Publiczne API biblioteki WPCoderScan.
export { scan } from './engine';
export type { ScanOptions, ScanResult, ScanError, ScanWarning } from './engine';
export { scoreFindings } from './engine/score';
export type { Score } from './engine/score';
export { createBaseline, parseBaseline, serializeBaseline, BaselineError } from './engine/baseline';
export type { Baseline, BaselineEntry } from './engine/baseline';
export type { SuppressedFinding, Suppression } from './engine/suppress';
export { allRules, extendedRules } from './rules';
export type { Finding, Rule, Severity, FileContext, PhpNode, Patch, TextEdit } from './rules/types';
export { createTranslator, parseLang, DEFAULT_LANG, LANGS } from './i18n';
export type { Lang, MessageKey, Translate } from './i18n';
export { renderTerminal } from './report/terminal';
export { renderSarif, buildSarif } from './report/sarif';
export type { SarifLog } from './report/sarif';
