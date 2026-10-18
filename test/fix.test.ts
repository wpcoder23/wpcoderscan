// Podpowiedzi napraw: dobór ucieczki, bramki weryfikacji, łatka, SARIF.
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { scan, buildSarif } from '../src/index';
import type { Finding, Patch } from '../src/index';
import { applyEdits, patchesConflict } from '../src/fix/apply';
import { renderUnifiedDiff } from '../src/fix/diff';
import { buildPatchFile } from '../src/fix/suggest';
import { contextAt, chooseEscaper } from '../src/fix/xss-context';

const dirs: string[] = [];
function tempDir(): string {
  const d = mkdtempSync(join(tmpdir(), 'wpcs-fix-'));
  dirs.push(d);
  return d;
}
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

// Skanuje jeden plik i zwraca znaleziska oraz kod po nałożeniu pełnych poprawek.
async function run(code: string, name = 'sample.php') {
  const dir = tempDir();
  writeFileSync(join(dir, name), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  const patches = result.findings.filter((f) => f.patch?.safety === 'complete').map((f) => f.patch as Patch);
  const patched = applyEdits(code, patches.flatMap((p) => p.edits));
  return { dir, result, findings: result.findings, patched };
}

function only(findings: Finding[], ruleId: string): Finding[] {
  return findings.filter((f) => f.ruleId === ruleId);
}

describe('automat kontekstu HTML', () => {
  it('rozpoznaje tekst, atrybut w cudzysłowie i adres URL', () => {
    expect(contextAt('<p>')).toEqual({ kind: 'text' });
    expect(contextAt('<p>Witaj ')).toEqual({ kind: 'text' });
    expect(contextAt('<input value="')).toEqual({ kind: 'attr', quote: '"', name: 'value', atStart: true });
    expect(contextAt("<input value='ab")).toEqual({ kind: 'attr', quote: "'", name: 'value', atStart: false });
    expect(contextAt('<a href="')).toMatchObject({ kind: 'attr', name: 'href', atStart: true });
  });

  it('oznacza konteksty bez bezpiecznej ucieczki jako unsafe', () => {
    expect(contextAt('<script>var a = ')).toEqual({ kind: 'unsafe' });
    expect(contextAt('<style>p { color: ')).toEqual({ kind: 'unsafe' });
    expect(contextAt('<div class=')).toEqual({ kind: 'unsafe' });
    expect(contextAt('<div class=abc')).toEqual({ kind: 'unsafe' });
    expect(contextAt('<div ')).toEqual({ kind: 'unsafe' });
    expect(contextAt('<!-- ')).toEqual({ kind: 'unsafe' });
  });

  it('wraca do tekstu po zamknięciu znacznika i skryptu', () => {
    expect(contextAt('<script>var a;</script><p>')).toEqual({ kind: 'text' });
    expect(contextAt('<!-- x --><p>')).toEqual({ kind: 'text' });
    expect(contextAt('<a href="/x">')).toEqual({ kind: 'text' });
  });

  it('dobiera funkcję ucieczki', () => {
    expect(chooseEscaper({ kind: 'text' }, '')).toBe('esc_html');
    expect(chooseEscaper(contextAt('<input value="'), '"')).toBe('esc_attr');
    expect(chooseEscaper(contextAt('<a href="'), '"')).toBe('esc_url');
    expect(chooseEscaper(contextAt('<a href="'), '/')).toBeNull();
    expect(chooseEscaper(contextAt('<a href="/x?q='), '"')).toBe('esc_attr');
    expect(chooseEscaper(contextAt('<a onclick="'), '"')).toBeNull();
    expect(chooseEscaper(contextAt('<a style="'), '"')).toBeNull();
  });
});

describe('podpowiedzi XSS', () => {
  it('opakowuje dane w treści w esc_html', async () => {
    const src = '<p><?php echo $_GET["q"]; ?></p>\n';
    const { findings, patched } = await run(src);
    const f = only(findings, 'wp.xss.echo_superglobal');
    expect(f).toHaveLength(1);
    expect(f[0].patch?.safety).toBe('complete');
    expect(patched).toBe('<p><?php echo esc_html( $_GET["q"] ); ?></p>\n');
  });

  it('używa esc_attr w atrybucie i esc_url w całym adresie', async () => {
    const src = [
      '<input value="<?php echo $_GET["v"]; ?>">',
      '<a href="<?php echo $_GET["u"]; ?>">x</a>',
      '',
    ].join('\n');
    const { patched } = await run(src);
    expect(patched).toContain('value="<?php echo esc_attr( $_GET["v"] ); ?>"');
    expect(patched).toContain('href="<?php echo esc_url( $_GET["u"] ); ?>"');
  });

  it('łańcuch konkatenacji: osobna ucieczka dla każdego fragmentu', async () => {
    const src = `<?php echo '<a href="' . $_GET['u'] . '" title="' . $_GET['t'] . '">' . $_GET['n'] . '</a>';\n`;
    const { patched, findings } = await run(src);
    expect(only(findings, 'wp.xss.echo_superglobal')).toHaveLength(1);
    expect(patched).toBe(
      `<?php echo '<a href="' . esc_url( $_GET['u'] ) . '" title="' . esc_attr( $_GET['t'] ) . '">' . esc_html( $_GET['n'] ) . '</a>';\n`,
    );
  });

  it('zmienna zasilona superglobalem też dostaje ucieczkę', async () => {
    const src = `<?php\n$name = $_GET['name'];\necho '<b>' . $name . '</b>';\n`;
    const { patched } = await run(src);
    expect(patched).toContain(`echo '<b>' . esc_html( $name ) . '</b>';`);
  });

  it('adres zaczynający się od danych, ale z dalszym tekstem, nie dostaje podpowiedzi', async () => {
    const src = '<a href="<?php echo $_GET["u"]; ?>/x">x</a>\n';
    const { findings } = await run(src);
    const f = only(findings, 'wp.xss.echo_superglobal');
    expect(f).toHaveLength(1);
    expect(f[0].patch).toBeUndefined();
  });

  it('skrypty, style i zdarzenia nie dostają podpowiedzi', async () => {
    const src = [
      '<script>var a = "<?php echo $_GET["a"]; ?>";</script>',
      '<div onclick="go(<?php echo $_GET["b"]; ?>)">x</div>',
      '<div style="width:<?php echo $_GET["c"]; ?>px">x</div>',
      '<div class=<?php echo $_GET["d"]; ?>>x</div>',
      '',
    ].join('\n');
    const { findings } = await run(src);
    const f = only(findings, 'wp.xss.echo_superglobal');
    expect(f.length).toBe(4);
    expect(f.every((x) => x.patch === undefined)).toBe(true);
  });

  it('bez znanego kontekstu proponuje esc_html jako zmianę do decyzji', async () => {
    const { findings } = await run(`<?php\necho $_GET['x'];\n`);
    const f = only(findings, 'wp.xss.echo_superglobal');
    expect(f[0].patch?.safety).toBe('manual');
    expect(f[0].patch?.label).toContain('esc_html');
  });

  it('nie podpowiada przy złożonych operandach, żeby nie zepsuć znaczników', async () => {
    const { findings } = await run(`<?php echo sprintf('<b>%s</b>', $_GET['x']);\n`);
    const f = only(findings, 'wp.xss.echo_superglobal');
    expect(f.every((x) => x.patch === undefined)).toBe(true);
  });

  it('trzyma ciasny styl nawiasów, gdy plik go używa', async () => {
    const src = `<?php\n$a = trim($x);\n$b = strlen($y);\necho '<p>' . $_GET['q'] . '</p>';\n`;
    const { patched } = await run(src);
    expect(patched).toContain(`esc_html($_GET['q'])`);
  });

  it('obsługuje print i krótką składnię echo', async () => {
    const src = '<p><?= $_GET["a"] ?></p>\n<p><?php print $_GET["b"]; ?></p>\n';
    const { patched } = await run(src);
    expect(patched).toContain('<?= esc_html( $_GET["a"] ) ?>');
    expect(patched).toContain('print esc_html( $_GET["b"] );');
  });

  it('po poprawce kolejny skan nie znajduje już tych samych problemów (idempotencja)', async () => {
    const src = '<p><?php echo $_GET["q"]; ?></p>\n<a href="<?php echo $_GET["u"]; ?>">x</a>\n';
    const first = await run(src);
    expect(first.patched).not.toBeNull();
    const second = await run(first.patched as string);
    expect(only(second.findings, 'wp.xss.echo_superglobal')).toHaveLength(0);
  });

  it('zachowuje końce linii CRLF i znaki spoza ASCII', async () => {
    const src = '<p>Zażółć gęślą jaźń</p>\r\n<p><?php echo $_GET["q"]; ?></p>\r\n';
    const { patched } = await run(src);
    expect(patched).toBe('<p>Zażółć gęślą jaźń</p>\r\n<p><?php echo esc_html( $_GET["q"] ); ?></p>\r\n');
  });

  it('widzi znacznik otwarty przed blokiem if albo pętlą', async () => {
    const insideScript = [
      '<script>',
      '<?php if ( $a ) { ?>',
      'var q = <?php echo $_GET["q"] ?>;',
      '<?php } ?>',
      '</script>',
      '',
    ].join('\n');
    const first = await run(insideScript);
    const f1 = only(first.findings, 'wp.xss.echo_superglobal');
    expect(f1).toHaveLength(1);
    expect(f1[0].patch).toBeUndefined();

    const insideDiv = ['<div>', '<?php if ( $a ) { ?>', '<b><?php echo $_GET["q"] ?></b>', '<?php } ?>', '</div>', ''].join('\n');
    const second = await run(insideDiv);
    expect(second.patched).toContain('<b><?php echo esc_html( $_GET["q"] ) ?></b>');
  });

  it('nie dziedziczy kontekstu HTML spoza funkcji', async () => {
    const src = ['<script>', '<?php function show() { echo "<p>" . $_GET["q"] . "</p>"; } ?>', ''].join('\n');
    const { patched } = await run(src);
    expect(patched).toContain('"<p>" . esc_html( $_GET["q"] ) . "</p>"');
  });

  it('plik z błędem składni nie dostaje podpowiedzi', async () => {
    const src = '<p><?php echo $_GET["q"]; ?></p>\n<?php function broken( { ?>\n';
    const { findings } = await run(src);
    expect(findings.every((f) => f.patch === undefined)).toBe(true);
  });
});

describe('podpowiedzi unserialize', () => {
  it('dopisuje allowed_classes => false do jednoargumentowego wywołania', async () => {
    const src = `<?php\n$d = unserialize( $_POST['d'] );\n`;
    const { patched, findings } = await run(src);
    expect(only(findings, 'wp.unserialize.user_input')).toHaveLength(1);
    expect(patched).toBe(`<?php\n$d = unserialize( $_POST['d'], array( 'allowed_classes' => false ) );\n`);
  });

  it('trzyma ciasny styl i krótką tablicę, gdy plik ich używa', async () => {
    const src = `<?php\n$a = [1, 2];\n$b = foo($a);\n$d = unserialize($_POST['d']);\n`;
    const { patched } = await run(src);
    expect(patched).toContain(`unserialize($_POST['d'], ['allowed_classes' => false])`);
  });

  it('nie zgłasza wywołania z allowed_classes => false', async () => {
    const src = `<?php\n$d = unserialize( $_POST['d'], array( 'allowed_classes' => false ) );\n`;
    const { findings } = await run(src);
    expect(only(findings, 'wp.unserialize.user_input')).toHaveLength(0);
  });

  it('nie proponuje poprawki dla maybe_unserialize ani dla wywołania z innym drugim argumentem', async () => {
    const src = `<?php\n$a = maybe_unserialize( $_POST['a'] );\n$b = unserialize( $_POST['b'], array( 'max_depth' => 3 ) );\n`;
    const { findings } = await run(src);
    const f = only(findings, 'wp.unserialize.user_input');
    expect(f).toHaveLength(2);
    expect(f.every((x) => x.patch === undefined)).toBe(true);
  });
});

describe('reguły bez automatycznych poprawek', () => {
  it('RCE i sekrety nigdy nie dostają podpowiedzi', async () => {
    // Wartość składana w teście, żeby plik testu nie zawierał gotowego sekretu.
    const tokenValue = ['abcd1234', 'efgh5678', 'ijkl'].join('');
    const src = `<?php\ninclude $_GET['f'];\n$api_key = '${tokenValue}';\n`;
    const { findings } = await run(src);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.patch === undefined)).toBe(true);
  });
});

describe('narzędzia łatek', () => {
  it('applyEdits odrzuca nachodzące zakresy', () => {
    expect(applyEdits('abcdef', [{ start: 1, end: 3, replacement: 'X' }, { start: 2, end: 4, replacement: 'Y' }])).toBeNull();
    expect(applyEdits('abcdef', [{ start: 4, end: 9, replacement: 'X' }])).toBeNull();
    expect(applyEdits('abcdef', [{ start: 1, end: 3, replacement: 'X' }, { start: 3, end: 3, replacement: 'Y' }])).toBe('aXYdef');
  });

  it('patchesConflict wykrywa to samo miejsce i nakładanie', () => {
    const ins = (n: number): Patch => ({ safety: 'complete', label: 'x', edits: [{ start: n, end: n, replacement: '(' }] });
    expect(patchesConflict(ins(5), ins(5))).toBe(true);
    expect(patchesConflict(ins(5), ins(6))).toBe(false);
    const range: Patch = { safety: 'complete', label: 'x', edits: [{ start: 2, end: 8, replacement: '' }] };
    expect(patchesConflict(range, ins(5))).toBe(true);
  });

  it('renderUnifiedDiff zachowuje CRLF i znacznik braku końcowej nowej linii', () => {
    const before = 'a\r\nb\r\nc';
    const after = 'a\r\nB\r\nc';
    const diff = renderUnifiedDiff('x.php', before, after);
    expect(diff).toContain('--- a/x.php');
    expect(diff).toContain('-b\r');
    expect(diff).toContain('+B\r');
    expect(diff).toContain('\\ No newline at end of file');
  });
});

describe('łatka i weryfikacja zewnętrzna', () => {
  const src = [
    '<?php',
    "$d = unserialize( $_POST['d'] );",
    '?>',
    '<p><?php echo $_GET["q"]; ?></p>',
    '<a href="<?php echo $_GET["u"]; ?>">x</a>',
    '',
  ].join('\n');

  it('łatka przechodzi git apply --check i git apply, a kod przechodzi php -l', async () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'a.php'), src, 'utf8');
    const result = await scan(dir, { cwd: dir });
    const built = buildPatchFile(result, dir);
    expect(built.patches).toBe(3);
    expect(built.files).toBe(1);
    writeFileSync(join(dir, 'fix.patch'), built.diff, 'utf8');

    const init = spawnSync('git', ['init', '-q'], { cwd: dir });
    expect(init.status).toBe(0);
    const check = spawnSync('git', ['apply', '--check', 'fix.patch'], { cwd: dir, encoding: 'utf8' });
    expect(check.status, check.stderr).toBe(0);
    const apply = spawnSync('git', ['apply', 'fix.patch'], { cwd: dir, encoding: 'utf8' });
    expect(apply.status, apply.stderr).toBe(0);

    const after = readFileSync(join(dir, 'a.php'), 'utf8');
    expect(after).toContain("unserialize( $_POST['d'], array( 'allowed_classes' => false ) )");
    expect(after).toContain('esc_html( $_GET["q"] )');
    expect(after).toContain('esc_url( $_GET["u"] )');

    const lint = spawnSync('php', ['-l', join(dir, 'a.php')], { encoding: 'utf8' });
    if (lint.error) return; // brak PHP w środowisku, pomijamy sprawdzenie składni
    expect(lint.status, lint.stdout + lint.stderr).toBe(0);
  });

  it('łatka nie zawiera poprawek do decyzji', async () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'b.php'), `<?php\necho $_GET['x'];\n`, 'utf8');
    const result = await scan(dir, { cwd: dir });
    const built = buildPatchFile(result, dir);
    expect(built.patches).toBe(0);
    expect(built.manual).toBe(1);
    expect(built.diff).toBe('');
  });

  it('SARIF niesie poprawki w polu fixes', async () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'a.php'), src, 'utf8');
    const result = await scan(dir, { cwd: dir });
    const sarif = buildSarif(result);
    const withFix = sarif.runs[0].results.filter((r) => r.fixes);
    expect(withFix.length).toBe(3);
    const fix = withFix[0].fixes![0];
    expect(fix.artifactChanges[0].artifactLocation.uri).toBe('a.php');
    expect(fix.artifactChanges[0].replacements[0].deletedRegion.charLength).toBeGreaterThanOrEqual(0);
    expect(['complete', 'manual']).toContain(fix.properties.safety);
  });
});
