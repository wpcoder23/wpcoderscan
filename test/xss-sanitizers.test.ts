// Reguła wp.xss.echo_superglobal: sanitize_text_field i strip_tags usuwają znaczniki, ale zostawiają cudzysłowy.
// W treści strony to wystarcza. W atrybucie, znaczniku i skrypcie nie. Każdy przypadek ujemny ma dodatni odpowiednik.
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scan } from '../src/index';
import type { Finding } from '../src/index';
import { applyEdits } from '../src/fix/apply';
import { contextAt, textSanitizerExposure } from '../src/fix/xss-context';

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function xss(code: string): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-xsssan-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === 'wp.xss.echo_superglobal');
}

describe('ocena miejsca po funkcji usuwającej znaczniki', () => {
  it('treść, komentarz i styl są chronione', () => {
    expect(textSanitizerExposure('<p>')).toBe('covered');
    expect(textSanitizerExposure('')).toBe('covered');
    expect(textSanitizerExposure('<!-- ')).toBe('covered');
    expect(textSanitizerExposure('<style>p { color: ')).toBe('covered');
    expect(textSanitizerExposure('<script>var a;</script><p>')).toBe('covered');
  });

  it('atrybut, znacznik i skrypt nie są chronione', () => {
    expect(textSanitizerExposure('<input value="')).toBe('exposed');
    expect(textSanitizerExposure("<input value='ab")).toBe('exposed');
    expect(textSanitizerExposure('<div class=')).toBe('exposed');
    expect(textSanitizerExposure('<div class=abc')).toBe('exposed');
    expect(textSanitizerExposure('<div ')).toBe('exposed');
    expect(textSanitizerExposure('<script>var a = "')).toBe('exposed');
  });

  it('contextAt zachowuje dotychczasowe wyniki', () => {
    expect(contextAt('<style>p { color: ')).toEqual({ kind: 'unsafe' });
    expect(contextAt('<!-- ')).toEqual({ kind: 'unsafe' });
    expect(contextAt('<p>')).toEqual({ kind: 'text' });
  });
});

describe('sanitize_text_field w atrybucie', () => {
  it('echo z atrybutem w tym samym wyrażeniu', async () => {
    const f = await xss(`<?php
echo '<input value="' . sanitize_text_field( $_GET['q'] ) . '">';`);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('medium');
    expect(f[0].message).toContain('only strips tags');
  });

  it('szablon z echo w wartości atrybutu', async () => {
    const f = await xss(`<form>
<input type="text" name="q" value="<?php echo sanitize_text_field( $_GET['q'] ); ?>">
</form>`);
    expect(f).toHaveLength(1);
  });

  it('dwa osobne echo: atrybut otwarty w pierwszym', async () => {
    const f = await xss(`<?php
echo '<input value="';
echo sanitize_text_field( $_GET['q'] );
echo '">';`);
    expect(f).toHaveLength(1);
  });

  it('zmienna oczyszczona wcześniej i wklejona w atrybut', async () => {
    const f = await xss(`<?php
$q = sanitize_text_field( $_GET['q'] );
echo '<input value="' . $q . '">';`);
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('Variable $q');
  });

  it('zmienna oczyszczona i wypisana w atrybucie szablonu', async () => {
    const f = await xss(`<?php
$q = sanitize_text_field( $_GET['q'] );
?>
<input value="<?php echo $q; ?>">`);
    expect(f).toHaveLength(1);
  });

  it('wc_clean, sanitize_textarea_field, sanitize_user i strip_tags', async () => {
    for (const fn of ['wc_clean', 'sanitize_textarea_field', 'sanitize_user', 'strip_tags', 'wp_strip_all_tags']) {
      const f = await xss(`<?php
echo '<a title="' . ${fn}( $_GET['t'] ) . '">x</a>';`);
      expect(f, fn).toHaveLength(1);
    }
  });

  it('wynik w skrypcie', async () => {
    const f = await xss(`<script>
var query = "<?php echo sanitize_text_field( $_GET['q'] ); ?>";
</script>`);
    expect(f).toHaveLength(1);
    expect(f[0].patch).toBeUndefined();
  });

  it('atrybut bez cudzysłowu', async () => {
    const f = await xss(`<?php
echo '<input value=' . sanitize_text_field( $_GET['q'] ) . '>';`);
    expect(f).toHaveLength(1);
  });

  it('atrybut shortcode w atrybucie to zapisany XSS', async () => {
    const f = await xss(`<?php
add_shortcode( 'box', function ( $atts ) {
	$a = shortcode_atts( array( 'title' => '' ), $atts );
	return '<div title="' . sanitize_text_field( $a['title'] ) . '"></div>';
} );`);
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('stored XSS');
  });

  it('poprawka opakowuje wywołanie w esc_attr', async () => {
    const code = `<?php
echo '<input value="' . sanitize_text_field( $_GET['q'] ) . '">';`;
    const f = await xss(code);
    expect(f).toHaveLength(1);
    expect(f[0].patch?.safety).toBe('complete');
    const patched = applyEdits(code, f[0].patch?.edits ?? []);
    expect(patched).toContain(`esc_attr( sanitize_text_field( $_GET['q'] ) )`);
    expect(await xss(patched ?? '')).toHaveLength(0);
  });

  it('poprawka w szablonie dobiera esc_attr', async () => {
    const code = `<input value="<?php echo sanitize_text_field( $_GET['q'] ); ?>">`;
    const f = await xss(code);
    expect(f).toHaveLength(1);
    const patched = applyEdits(code, f[0].patch?.edits ?? []);
    expect(patched).toContain('esc_attr(');
    expect(await xss(patched ?? '')).toHaveLength(0);
  });
});

describe('sanitize_text_field w treści strony', () => {
  it('echo w akapicie', async () => {
    const f = await xss(`<?php
echo '<p>' . sanitize_text_field( $_GET['q'] ) . '</p>';`);
    expect(f).toHaveLength(0);
  });

  it('szablon z echo w akapicie', async () => {
    const f = await xss(`<p><?php echo sanitize_text_field( $_GET['q'] ); ?></p>`);
    expect(f).toHaveLength(0);
  });

  it('textarea i komentarz HTML', async () => {
    const f = await xss(`<textarea name="t"><?php echo sanitize_textarea_field( $_POST['t'] ); ?></textarea>
<!-- <?php echo sanitize_text_field( $_GET['q'] ); ?> -->`);
    expect(f).toHaveLength(0);
  });

  it('wypisanie bez żadnego znanego HTML wokół', async () => {
    const f = await xss(`<?php
echo sanitize_text_field( $_GET['q'] );
$q = sanitize_text_field( $_GET['q'] );
echo $q;
echo 'Szukano: ' . $q;`);
    expect(f).toHaveLength(0);
  });

  it('zmienna oczyszczona i wypisana w akapicie', async () => {
    const f = await xss(`<?php
$q = sanitize_text_field( $_GET['q'] );
echo '<p>' . $q . '</p>';`);
    expect(f).toHaveLength(0);
  });

  it('esc_attr na oczyszczonej wartości w atrybucie', async () => {
    const f = await xss(`<?php
echo '<input value="' . esc_attr( sanitize_text_field( $_GET['q'] ) ) . '">';`);
    expect(f).toHaveLength(0);
  });

  it('sanitize_email i absint w atrybucie zostają czyste', async () => {
    const f = await xss(`<?php
echo '<input value="' . sanitize_email( $_GET['e'] ) . '">';
echo '<input value="' . absint( $_GET['n'] ) . '">';`);
    expect(f).toHaveLength(0);
  });

  it('shortcode po sanitize_text_field w akapicie', async () => {
    const f = await xss(`<?php
add_shortcode( 'box', function ( $atts ) {
	$a = shortcode_atts( array( 'title' => '' ), $atts );
	return '<p>' . sanitize_text_field( $a['title'] ) . '</p>';
} );`);
    expect(f).toHaveLength(0);
  });
});

describe('strip_tags z listą znaczników i odkodowanie', () => {
  it('strip_tags z dozwolonymi znacznikami przenosi skażenie', async () => {
    const f = await xss(`<?php
echo strip_tags( $_GET['t'], '<b><i>' );`);
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('without an escaping function');
  });

  it('html_entity_decode po sanitize_text_field przywraca znaczniki', async () => {
    const f = await xss(`<?php
echo '<p>' . html_entity_decode( sanitize_text_field( $_GET['t'] ) ) . '</p>';`);
    expect(f).toHaveLength(1);
  });

  it('zwykły wp_unslash i trim nie zdejmują oceny kontekstu', async () => {
    const f = await xss(`<?php
echo '<p>' . trim( wp_unslash( sanitize_text_field( $_GET['t'] ) ) ) . '</p>';
echo '<input value="' . trim( sanitize_text_field( $_GET['t'] ) ) . '">';`);
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(3);
  });
});
