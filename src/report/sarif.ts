// Raport w formacie SARIF 2.1.0.
// To format, który GitHub przyjmuje przez upload-sarif i pokazuje w zakładce
// Security. Mapujemy poziom i pewność na poziom SARIF tak, żeby heurystyka
// nigdy nie była błędem (error), bo domyślnie nie łamie build. Dzięki temu
// zakładka Security zgadza się z zachowaniem CI.
import { createHash } from 'node:crypto';
import { allRules } from '../rules';
import type { Confidence, Finding, Severity } from '../rules/types';
import type { ScanResult } from '../engine';

// Wersja narzędzia. Trzymać zgodnie z package.json.
const TOOL_VERSION = '0.1.0';
const TOOL_NAME = 'WPCoderScaner';
const INFO_URI = 'https://www.npmjs.com/package/wpcoderscaner';
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

type SarifLevel = 'error' | 'warning' | 'note' | 'none';

interface SarifRegion {
  startLine: number;
  startColumn?: number;
  endLine?: number;
}

interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level: SarifLevel;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: SarifRegion;
    };
  }>;
  properties: Record<string, unknown>;
  partialFingerprints: Record<string, string>;
}

interface SarifRuleDescriptor {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  help: { text: string };
  defaultConfiguration: { level: SarifLevel };
  properties: Record<string, unknown>;
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      informationUri: string;
      version: string;
      rules: SarifRuleDescriptor[];
    };
  };
  results: SarifResult[];
}

export interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

// Liczbowa waga dla zakładki Security GitHuba (skala w stylu CVSS).
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.0',
  high: '7.0',
  medium: '5.0',
  low: '3.0',
  info: '0.0',
};

// Poziom SARIF. Heurystyka nigdy nie jest błędem, bo domyślnie nie łamie build.
function sarifLevel(severity: Severity, confidence: Confidence): SarifLevel {
  if (confidence === 'heuristic') {
    return severity === 'low' || severity === 'info' ? 'note' : 'warning';
  }
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    default:
      return 'none';
  }
}

function tags(cwe?: string[], asvs?: string[]): string[] {
  const t = ['security', 'wordpress', 'php'];
  if (cwe) t.push(...cwe);
  if (asvs) t.push(...asvs.map((a) => `ASVS-${a}`));
  return t;
}

// Odcisk stabilny mimo przesunięć linii, żeby GitHub nie mnożył alertów.
function fingerprint(f: Finding): string {
  return createHash('sha256')
    .update(`${f.ruleId}\n${f.file}\n${f.snippet ?? ''}`)
    .digest('hex')
    .slice(0, 16);
}

export function buildSarif(result: ScanResult): SarifLog {
  const ruleIndex = new Map<string, number>();
  allRules.forEach((r, i) => ruleIndex.set(r.id, i));

  const rules: SarifRuleDescriptor[] = allRules.map((r) => ({
    id: r.id,
    name: r.id,
    shortDescription: { text: r.title },
    fullDescription: { text: r.title },
    helpUri: INFO_URI,
    help: { text: r.title },
    defaultConfiguration: { level: sarifLevel(r.severity, r.confidence) },
    properties: {
      tags: tags(r.cwe, r.asvs),
      'security-severity': SECURITY_SEVERITY[r.severity],
    },
  }));

  const results: SarifResult[] = result.findings.map((f) => {
    const region: SarifRegion = { startLine: Math.max(1, f.line) };
    if (Number.isFinite(f.column)) region.startColumn = Math.max(1, f.column + 1);
    if (f.endLine) region.endLine = f.endLine;

    const res: SarifResult = {
      ruleId: f.ruleId,
      level: sarifLevel(f.severity, f.confidence),
      message: { text: f.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region,
          },
        },
      ],
      properties: {
        confidence: f.confidence,
        severity: f.severity,
        'security-severity': SECURITY_SEVERITY[f.severity],
        ...(f.cwe ? { cwe: f.cwe } : {}),
        ...(f.asvs ? { asvs: f.asvs } : {}),
        ...(f.fix ? { fix: f.fix } : {}),
      },
      partialFingerprints: { wpcsFingerprint: fingerprint(f) },
    };

    const idx = ruleIndex.get(f.ruleId);
    if (idx !== undefined) res.ruleIndex = idx;
    return res;
  });

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            informationUri: INFO_URI,
            version: TOOL_VERSION,
            rules,
          },
        },
        results,
      },
    ],
  };
}

export function renderSarif(result: ScanResult): string {
  return JSON.stringify(buildSarif(result), null, 2) + '\n';
}
