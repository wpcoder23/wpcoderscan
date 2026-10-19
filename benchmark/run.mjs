// Uruchamia pełny pomiar dla jednej wersji skanera: recall domyślny, recall z --extended i szum.
// Użycie: node benchmark/run.mjs --lib dist/index.js --label current
// Wyniki trafiają do benchmark/results/<etykieta>-*.json. Porównanie: node benchmark/compare.mjs.
// Pomiar trwa kilka minut. Pierwsze uruchomienie pobiera około 700 archiwów wtyczek z wordpress.org.
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { args, here, RESULTS } from './common.mjs';

const opt = args({ lib: { type: 'string', default: 'dist/index.js' }, label: { type: 'string', default: 'current' } });

function run(script, extra) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [join(here, script), '--lib', opt.lib, ...extra], { stdio: 'inherit' });
    child.on('exit', (code) => resolve(code ?? 1));
  });
}

// Pierwsze uruchomienie pobiera archiwa, więc robimy je po kolei, żeby nie pobierać tych samych plików dwa razy.
const codes = [];
codes.push(await run('recall.mjs', ['--out', join(RESULTS, `${opt.label}-recall.json`)]));
codes.push(await run('recall.mjs', ['--extended', '--out', join(RESULTS, `${opt.label}-recall-extended.json`)]));
codes.push(await run('noise.mjs', ['--out', join(RESULTS, `${opt.label}-noise.json`)]));
process.exit(codes.some((c) => c !== 0) ? 1 : 0);
