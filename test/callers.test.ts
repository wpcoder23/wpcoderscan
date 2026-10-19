// Dane użytkownika przekazane do funkcji wywołaniem z tego samego pliku.
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

async function findingsFor(code: string, extended = false): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-call-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir, extended });
  expect(result.errors).toHaveLength(0);
  return result.findings;
}

const byRule = (f: Finding[], id: string) => f.filter((x) => x.ruleId === id);

describe('parametr funkcji zasilony wywołaniem z danymi użytkownika', () => {
  it('SQL injection: parametr trafia do zapytania, a wywołanie przekazuje $_GET', async () => {
    const f = byRule(
      await findingsFor(`<?php
function load_items( $orderby ) {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}items ORDER BY " . $orderby );
}
function render_page() {
	return load_items( $_GET['orderby'] );
}`),
      'wp.sqli.unprepared',
    );
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(4);
    expect(f[0].confidence).toBe('heuristic');
    expect(f[0].message).toMatch(/passed in by a caller/);
  });

  it('wywołanie ze stałą albo z wartością po absint niczego nie zasiewa', async () => {
    const f = byRule(
      await findingsFor(`<?php
function load_items( $orderby ) {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}items ORDER BY " . $orderby );
}
function a() { return load_items( 'id' ); }
function b() { return load_items( absint( $_GET['orderby'] ) ); }`),
      'wp.sqli.unprepared',
    );
    expect(f).toHaveLength(0);
  });

  it('metoda wywołana przez $this i self', async () => {
    const f = byRule(
      await findingsFor(`<?php
class Repo {
	public function run() {
		$a = $this->find( $_POST['name'] );
		$b = self::count_by( $_POST['kind'] );
	}
	private function find( $name ) {
		global $wpdb;
		return $wpdb->get_row( "SELECT * FROM {$wpdb->prefix}t WHERE name = '$name'" );
	}
	private static function count_by( $kind ) {
		global $wpdb;
		return $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}t WHERE kind = '" . $kind . "'" );
	}
}`),
      'wp.sqli.unprepared',
    );
    expect(f).toHaveLength(2);
  });

  it('wywołanie statyczne po nazwie klasy z tego pliku', async () => {
    const f = byRule(
      await findingsFor(`<?php
class Finder {
	public static function by_slug( $slug ) {
		global $wpdb;
		return $wpdb->get_row( "SELECT * FROM {$wpdb->prefix}t WHERE slug = '$slug'" );
	}
}
function lookup() {
	return Finder::by_slug( $_REQUEST['slug'] );
}`),
      'wp.sqli.unprepared',
    );
    expect(f).toHaveLength(1);
  });

  it('łańcuch wywołań: dane przechodzą przez kolejną funkcję', async () => {
    const f = byRule(
      await findingsFor(`<?php
function entry() {
	return middle( $_GET['q'] );
}
function middle( $term ) {
	return deep( trim( $term ) );
}
function deep( $text ) {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE title LIKE '%" . $text . "%'" );
}`),
      'wp.sqli.unprepared',
    );
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(10);
  });

  it('funkcja czyszcząca parametr przed zapytaniem nie jest zgłaszana', async () => {
    const f = byRule(
      await findingsFor(`<?php
function load_item( $id ) {
	global $wpdb;
	$id = absint( $id );
	return $wpdb->get_row( "SELECT * FROM {$wpdb->prefix}t WHERE id = " . $id );
}
function a() { return load_item( $_GET['id'] ); }`),
      'wp.sqli.unprepared',
    );
    expect(f).toHaveLength(0);
  });

  it('parametr o typie int nie jest zasiewany', async () => {
    const f = byRule(
      await findingsFor(`<?php
function load_item( int $id ) {
	global $wpdb;
	return $wpdb->get_row( "SELECT * FROM {$wpdb->prefix}t WHERE id = " . $id );
}
function a() { return load_item( $_GET['id'] ); }`),
      'wp.sqli.unprepared',
    );
    expect(f).toHaveLength(0);
  });

  it('funkcja zdefiniowana w innym pliku nie jest rozwiązywana', async () => {
    const f = byRule(
      await findingsFor(`<?php
function a() {
	return external_loader( $_GET['id'] );
}`),
      'wp.sqli.unprepared',
    );
    expect(f).toHaveLength(0);
  });

  it('XSS: funkcja pomocnicza wypisuje parametr, a wywołanie przekazuje dane z żądania', async () => {
    const f = byRule(
      await findingsFor(`<?php
function print_notice( $text ) {
	echo '<div class="notice">' . $text . '</div>';
}
function show() {
	print_notice( $_GET['msg'] );
}`),
      'wp.xss.echo_superglobal',
    );
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(3);
  });

  it('XSS: wywołanie z esc_html nie zasiewa parametru', async () => {
    const f = byRule(
      await findingsFor(`<?php
function print_notice( $text ) {
	echo '<div class="notice">' . $text . '</div>';
}
function show() {
	print_notice( esc_html( $_GET['msg'] ) );
}`),
      'wp.xss.echo_superglobal',
    );
    expect(f).toHaveLength(0);
  });

  it('LFI: ścieżka szablonu przekazana parametrem do include', async () => {
    const f = byRule(
      await findingsFor(`<?php
function load_template_file( $name ) {
	include __DIR__ . '/templates/' . $name . '.php';
}
function show() {
	load_template_file( $_GET['tpl'] );
}`),
      'wp.rce.dynamic',
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
  });

  it('unserialize na parametrze zasilonym z żądania', async () => {
    const f = byRule(
      await findingsFor(`<?php
function restore( $blob ) {
	return unserialize( $blob );
}
function a() {
	return restore( $_POST['state'] );
}`),
      'wp.unserialize.user_input',
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
  });

  it('tryb rozszerzony nie zgłasza drugi raz tego, co wykryła zwykła reguła', async () => {
    const f = await findingsFor(
      `<?php
function load_items( $orderby ) {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}items ORDER BY " . $orderby );
}
function a() { return load_items( $_GET['orderby'] ); }`,
      true,
    );
    expect(byRule(f, 'wp.sqli.unprepared')).toHaveLength(1);
    expect(byRule(f, 'wp.sqli.param_unprepared')).toHaveLength(0);
  });

  it('tryb rozszerzony nadal zgłasza parametr, którego nikt w pliku nie zasila', async () => {
    const f = await findingsFor(
      `<?php
function load_items( $orderby ) {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}items ORDER BY " . $orderby );
}`,
      true,
    );
    expect(byRule(f, 'wp.sqli.unprepared')).toHaveLength(0);
    expect(byRule(f, 'wp.sqli.param_unprepared')).toHaveLength(1);
  });

  it('tablica podana wprost: klucz ze stałą jest czysty, pozostałe klucze niosą skażenie', async () => {
    const code = (key: string) => `<?php
function load_form( $args ) {
	include __DIR__ . '/templates/' . $args['${key}'] . '.php';
}
function show() {
	load_form( array( 'template' => 'login', 'redirect' => $_POST['to'] ) );
}`;
    expect(byRule(await findingsFor(code('template')), 'wp.rce.dynamic')).toHaveLength(0);
    expect(byRule(await findingsFor(code('redirect')), 'wp.rce.dynamic')).toHaveLength(1);
  });

  it('zmienna-tablica z oczyszczonym kluczem przekazana dalej zachowuje ten klucz jako czysty', async () => {
    const f = byRule(
      await findingsFor(`<?php
function render( $atts ) {
	$atts = shortcode_atts( array( 'template' => 'a' ), $atts );
	$atts['template'] = locate_allowed_template( $atts['template'] );
	return include_template( $atts );
}
function include_template( $atts ) {
	ob_start();
	include $atts['template'];
	return ob_get_clean();
}
add_shortcode( 'demo', 'render' );`),
      'wp.rce.dynamic',
    );
    expect(f).toHaveLength(0);
  });

  it('array_filter z is_numeric zostawia same liczby, więc lista w IN() nie jest skażona', async () => {
    const f = byRule(
      await findingsFor(`<?php
function delete_rows( $ids ) {
	global $wpdb;
	$ids = array_filter( $ids, 'is_numeric' );
	return $wpdb->query( "DELETE FROM {$wpdb->prefix}t WHERE id IN (" . implode( ',', $ids ) . ")" );
}
function a() { return delete_rows( $_POST['ids'] ); }`),
      'wp.sqli.unprepared',
    );
    expect(f).toHaveLength(0);
  });

  it('atrybut shortcode przekazany dalej zachowuje pochodzenie', async () => {
    const f = byRule(
      await findingsFor(`<?php
add_shortcode( 'rows', 'rows_sc' );
function rows_sc( $atts ) {
	return fetch_rows( $atts['id'] );
}
function fetch_rows( $id ) {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}rows WHERE id = " . $id );
}`),
      'wp.sqli.unprepared',
    );
    expect(f).toHaveLength(1);
    expect(f[0].message).toMatch(/shortcode attributes/);
  });
});
