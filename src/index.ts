// Publiczne API biblioteki WPCoderScan.
export { scan } from './engine';
export type { ScanOptions, ScanResult, ScanError } from './engine';
export { scoreFindings } from './engine/score';
export type { Score } from './engine/score';
export { allRules } from './rules';
export type { Finding, Rule, Severity, FileContext, PhpNode, Patch, TextEdit } from './rules/types';
export { renderTerminal } from './report/terminal';
export { renderSarif, buildSarif } from './report/sarif';
export type { SarifLog } from './report/sarif';
