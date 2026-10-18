// Wersja narzędzia. Czytana z package.json, żeby była w jednym miejscu.
// Plik leży poziom wyżej zarówno względem src/, jak i dist/.
import { readFileSync } from 'node:fs';

function readVersion(): string {
  try {
    const raw = readFileSync(new URL('../package.json', import.meta.url), 'utf8');
    const v = (JSON.parse(raw) as { version?: unknown }).version;
    return typeof v === 'string' ? v : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export const VERSION = readVersion();
