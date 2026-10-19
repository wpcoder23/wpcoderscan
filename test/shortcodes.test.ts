// Atrybuty shortcode jako dane użytkownika, unserialize na zmiennej i miejsce zgłoszenia uchwytu akcji.
import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scan } from '../src/index';
import type { Finding } from '../src/index';

const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

async function findingsFor(code: string): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-sc-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings;
}

const byRule = (f: Finding[], id: string) => f.filter((x) => x.ruleId === id);

describe('funkcja obsługująca shortcode rozpoznana po shortcode_atts', () => {
  it('stored XSS: atrybut wklejony do HTML zwracanego z funkcji bez rejestracji w pliku', async () => {
    const f = byRule(
      await findingsFor(`<?php
class Renderer {
	public function render( $atts ) {
		$atts = shortcode_atts( array( 'class' => '' ), $atts );
		return '<div class="' . $atts['class'] . '">x</div>';
	}
}`),
      'wp.xss.echo_superglobal',
    );
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(5);
    expect(f[0].severity).toBe('medium');
    expect(f[0].message).toMatch(/stored XSS/);
  });

  it('atrybut ujęty w esc_attr nie jest zgłaszany', async () => {
    const f = byRule(
      await findingsFor(`<?php
class Renderer {
	public function render( $atts ) {
		$atts = shortcode_atts( array( 'class' => '' ), $atts );
		return '<div class="' . esc_attr( $atts['class'] ) . '">x</div>';
	}
}`),
      'wp.xss.echo_superglobal',
    );
    expect(f).toHaveLength(0);
  });

  it('shortcode_atts na zmiennej, która nie jest parametrem, nie zasila analizy', async () => {
    const f = byRule(
      await findingsFor(`<?php
function build() {
	$atts = array( 'class' => 'a' );
	$atts = shortcode_atts( array( 'class' => '' ), $atts );
	return '<div class="' . $atts['class'] . '">x</div>';
}`),
      'wp.xss.echo_superglobal',
    );
    expect(f).toHaveLength(0);
  });

  it('LFI: ścieżka szablonu z atrybutu shortcode trafia do include', async () => {
    const f = byRule(
      await findingsFor(`<?php
function render_box( $atts ) {
	extract( shortcode_atts( array( 'style' => 'a' ), $atts ) );
	ob_start();
	include 'templates/' . $style . '.php';
	return ob_get_clean();
}`),
      'wp.rce.dynamic',
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
  });

  it('LFI: sanitize_file_name nie usuwa ukośnika z zapisu bez niego, ale basename zdejmuje skażenie', async () => {
    const f = byRule(
      await findingsFor(`<?php
function render_box( $atts ) {
	extract( shortcode_atts( array( 'style' => 'a' ), $atts ) );
	include 'templates/' . basename( $style ) . '.php';
}`),
      'wp.rce.dynamic',
    );
    expect(f).toHaveLength(0);
  });

  it('SQL injection: atrybut shortcode sklejony z zapytaniem', async () => {
    const f = byRule(
      await findingsFor(`<?php
add_shortcode( 'rows', 'rows_sc' );
function rows_sc( $atts ) {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}rows WHERE id = " . $atts['id'] );
}`),
      'wp.sqli.unprepared',
    );
    expect(f).toHaveLength(1);
    expect(f[0].message).toMatch(/shortcode attributes/);
  });

  it('SQL injection: absint na atrybucie zdejmuje skażenie', async () => {
    const f = byRule(
      await findingsFor(`<?php
add_shortcode( 'rows', 'rows_sc' );
function rows_sc( $atts ) {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}rows WHERE id = " . absint( $atts['id'] ) );
}`),
      'wp.sqli.unprepared',
    );
    expect(f).toHaveLength(0);
  });

  it('shortcode_atts na drugim parametrze to funkcja pomocnicza, nie uchwyt', async () => {
    const f = byRule(
      await findingsFor(`<?php
class Form {
	private function props( $field, $atts = array() ) {
		$args  = shortcode_atts( array( 'width' => '' ), $atts );
		$props = 'style="' . $args['width'] . '"';
		return $props;
	}
}`),
      'wp.xss.echo_superglobal',
    );
    expect(f).toHaveLength(0);
  });

  it('funkcja zwracająca sparsowane atrybuty jako tablicę nie jest zgłaszana', async () => {
    const f = byRule(
      await findingsFor(`<?php
function parse_args( $atts ) {
	$atts = shortcode_atts( array( 'src' => '' ), $atts );
	$atts['src'] = trim( $atts['src'] );
	return $atts;
}
function parse_direct( $atts ) {
	return shortcode_atts( array( 'src' => '' ), $atts );
}`),
      'wp.xss.echo_superglobal',
    );
    expect(f).toHaveLength(0);
  });

  it('zmienna budowana jako tekst nadal jest zgłaszana przy zwrocie', async () => {
    const f = byRule(
      await findingsFor(`<?php
function render_box( $atts ) {
	$a   = shortcode_atts( array( 'title' => '' ), $atts );
	$out = '<h3>';
	$out .= $a['title'];
	return $out;
}`),
      'wp.xss.echo_superglobal',
    );
    expect(f).toHaveLength(1);
  });
});

describe('unserialize na zmiennej zasilonej danymi użytkownika', () => {
  it('zmienna z $_POST przez str_replace to heurystyka', async () => {
    const f = byRule(
      await findingsFor(`<?php
function import_content() {
	$text = $_POST['text'];
	$text = str_replace( 'a', 'b', $text );
	$obj  = unserialize( $text );
	return $obj;
}`),
      'wp.unserialize.user_input',
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
    expect(f[0].severity).toBe('high');
    expect(f[0].message).toMatch(/variable \$text/);
  });

  it('wynik base64_decode ze zmiennej z żądania też jest zgłaszany', async () => {
    const f = byRule(
      await findingsFor(`<?php
function load() {
	$raw = $_GET['data'];
	return maybe_unserialize( base64_decode( $raw ) );
}`),
      'wp.unserialize.user_input',
    );
    expect(f).toHaveLength(1);
  });

  it('allowed_classes => false blokuje zgłoszenie także przy zmiennej', async () => {
    const f = byRule(
      await findingsFor(`<?php
function load() {
	$raw = $_GET['data'];
	return unserialize( $raw, array( 'allowed_classes' => false ) );
}`),
      'wp.unserialize.user_input',
    );
    expect(f).toHaveLength(0);
  });

  it('zmienna z innego źródła niż żądanie nie jest zgłaszana', async () => {
    const f = byRule(
      await findingsFor(`<?php
function load( $post_id ) {
	$raw = get_post_meta( $post_id, 'data', true );
	return unserialize( $raw );
}`),
      'wp.unserialize.user_input',
    );
    expect(f).toHaveLength(0);
  });

  it('is_serialized_string przed odczytem to sam napis, więc obiekt nie powstanie', async () => {
    const f = byRule(
      await findingsFor(`<?php
function show_value() {
	$raw = $_POST['value'];
	if ( is_serialized_string( $raw ) ) {
		return maybe_unserialize( $raw );
	}
	return $raw;
}`),
      'wp.unserialize.user_input',
    );
    expect(f).toHaveLength(0);
  });

  it('samo is_serialized niczego nie potwierdza, bo zserializowany może być obiekt', async () => {
    const f = byRule(
      await findingsFor(`<?php
function show_value() {
	$raw = $_POST['value'];
	if ( is_serialized( $raw ) ) {
		return maybe_unserialize( $raw );
	}
	return $raw;
}`),
      'wp.unserialize.user_input',
    );
    expect(f).toHaveLength(1);
  });
  it('superglobal wprost nadal daje wykrycie pewne', async () => {
    const f = byRule(
      await findingsFor(`<?php
function load() {
	return unserialize( $_POST['data'] );
}`),
      'wp.unserialize.user_input',
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('firm');
  });
});

describe('miejsce zgłoszenia uchwytu akcji', () => {
  it('uchwyt będący funkcją jest zgłaszany w definicji funkcji, nie w add_action', async () => {
    const f = byRule(
      await findingsFor(`<?php
add_action( 'wp_ajax_demo_save', 'demo_save' );
add_action( 'init', 'demo_init' );
function demo_init() {}

/**
 * Zapis.
 */
function demo_save() {
	update_option( 'demo', $_POST['v'] );
	wp_send_json_success();
}`),
      'wp.auth.unprotected_action',
    );
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) expect(x.line).toBe(9);
  });

  it('uchwyt będący metodą klasy jest zgłaszany w definicji metody', async () => {
    const f = byRule(
      await findingsFor(`<?php
class Demo {
	public function __construct() {
		add_action( 'wp_ajax_demo_save', array( $this, 'save' ) );
	}

	public function save() {
		update_option( 'demo', $_POST['v'] );
		wp_send_json_success();
	}
}`),
      'wp.auth.unprotected_action',
    );
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) expect(x.line).toBe(7);
  });

  it('domknięcie jest zgłaszane w miejscu add_action', async () => {
    const f = byRule(
      await findingsFor(`<?php
add_action( 'wp_ajax_demo_save', function () {
	update_option( 'demo', $_POST['v'] );
	wp_send_json_success();
} );`),
      'wp.auth.unprotected_action',
    );
    expect(f.length).toBeGreaterThan(0);
    for (const x of f) expect(x.line).toBe(2);
  });
});
