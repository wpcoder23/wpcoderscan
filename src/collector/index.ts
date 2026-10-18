// Kolektor plików PHP. Zbiera pliki do skanowania z katalogu wtyczki,
// motywu albo pojedynczego pliku. Pomija katalogi zależności.
import { promises as fs } from 'node:fs';
import path from 'node:path';

export interface CollectOptions {
  ignoreDirs?: string[]; // katalogi pomijane
  extensions?: string[]; // rozszerzenia traktowane jako PHP
}

const DEFAULT_IGNORE = ['vendor', 'node_modules', '.git', '.svn', 'dist', 'build'];
const DEFAULT_EXT = ['.php'];

export async function collectPhpFiles(target: string, opts: CollectOptions = {}): Promise<string[]> {
  const ignore = new Set(opts.ignoreDirs ?? DEFAULT_IGNORE);
  const exts = opts.extensions ?? DEFAULT_EXT;
  const out: string[] = [];

  const stat = await fs.stat(target);
  if (stat.isFile()) {
    if (exts.includes(path.extname(target).toLowerCase())) out.push(target);
    return out;
  }

  async function walkDir(dir: string): Promise<void> {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (ignore.has(e.name)) continue;
        await walkDir(full);
      } else if (e.isFile() && exts.includes(path.extname(e.name).toLowerCase())) {
        out.push(full);
      }
    }
  }

  await walkDir(target);
  out.sort();
  return out;
}
