// Lista zmienionych plików PHP z gita, do szybkiego skanu w CI (tryb diff).
// Skanujemy tylko to, co ruszył pull request albo lokalna zmiana, zamiast
// całego repozytorium.
import { execFileSync } from 'node:child_process';
import { statSync } from 'node:fs';
import path from 'node:path';
import { createTranslator, DEFAULT_LANG, type Translate } from '../i18n';

// Zwraca bezwzględne ścieżki istniejących plików PHP zmienionych wobec ref.
// diff-filter ACMR pomija pliki usunięte, których i tak nie ma na dysku.
export function gitChangedPhpFiles(ref: string, cwd: string, t: Translate = createTranslator(DEFAULT_LANG)): string[] {
  let top: string;
  try {
    top = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    throw new Error(t('git.notRepo'));
  }

  let out: string;
  try {
    out = execFileSync(
      'git',
      ['diff', '--name-only', '--diff-filter=ACMR', '-z', ref, '--', '*.php'],
      { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    );
  } catch {
    throw new Error(t('git.diffFailed', { ref }));
  }

  const files: string[] = [];
  for (const rel of out.split('\0')) {
    if (!rel) continue;
    const full = path.resolve(top, rel);
    try {
      if (statSync(full).isFile()) files.push(full);
    } catch {
      // Plik zniknął między diffem a odczytem, pomijamy.
    }
  }
  return files;
}
