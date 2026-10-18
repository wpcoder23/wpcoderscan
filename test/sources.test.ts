// Dodatkowe źródła danych użytkownika: filter_input, php://input, obiekt żądania REST.
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
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-src-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings;
}

const sqli = (f: Finding[]) => f.filter((x) => x.ruleId === 'wp.sqli.unprepared');

describe('filter_input i php://input', () => {
  it('filter_input bez filtra czyszczącego to dane wprost (pewne)', async () => {
    const f = sqli(
      await findingsFor(`<?php
function a() {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM t WHERE id = " . filter_input( INPUT_GET, 'id' ) );
}`),
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('firm');
  });

  it('filter_input z FILTER_VALIDATE_INT jest czysty', async () => {
    const f = sqli(
      await findingsFor(`<?php
function a() {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM t WHERE id = " . filter_input( INPUT_GET, 'id', FILTER_VALIDATE_INT ) );
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('php://input przechodzi przez json_decode do zmiennej', async () => {
    const f = sqli(
      await findingsFor(`<?php
function a() {
	global $wpdb;
	$data = json_decode( file_get_contents( 'php://input' ), true );
	$id = $data['id'];
	return $wpdb->query( "DELETE FROM t WHERE id = " . $id );
}`),
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
  });

  it('zwykły file_get_contents nie jest źródłem', async () => {
    const f = sqli(
      await findingsFor(`<?php
function a() {
	global $wpdb;
	return $wpdb->query( "DELETE FROM t WHERE id = " . file_get_contents( __DIR__ . '/id.txt' ) );
}`),
    );
    expect(f).toHaveLength(0);
  });
});

describe('żądanie REST', () => {
  it('get_param w parametrze typu WP_REST_Request to heurystyka', async () => {
    const f = sqli(
      await findingsFor(`<?php
function handler( WP_REST_Request $req ) {
	global $wpdb;
	$id = $req->get_param( 'id' );
	return $wpdb->get_row( "SELECT * FROM t WHERE id = $id" );
}`),
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
    expect(f[0].message).toContain('żądania REST');
  });

  it('parametr o nazwie $request bez typu też działa, w tym $request[...]', async () => {
    const f = sqli(
      await findingsFor(`<?php
function handler( $request ) {
	global $wpdb;
	return $wpdb->get_row( "SELECT * FROM t WHERE slug = '" . $request['slug'] . "'" );
}`),
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
  });

  it('absint, prepare i rzutowanie zdejmują skażenie', async () => {
    const f = sqli(
      await findingsFor(`<?php
function handler( WP_REST_Request $request ) {
	global $wpdb;
	$id = absint( $request->get_param( 'id' ) );
	$n  = (int) $request['n'];
	$wpdb->get_row( "SELECT * FROM t WHERE id = $id AND n = $n" );
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM t WHERE s = %s", $request->get_param( 's' ) ) );
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('metody niezwiązane z danymi klienta nie skażają', async () => {
    const f = sqli(
      await findingsFor(`<?php
function handler( WP_REST_Request $request ) {
	global $wpdb;
	return $wpdb->get_row( "SELECT * FROM t WHERE route = " . $request->get_route() );
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('zwykła zmienna $other->get_param nie jest żądaniem', async () => {
    const f = sqli(
      await findingsFor(`<?php
function handler( $widget ) {
	global $wpdb;
	return $wpdb->get_row( "SELECT * FROM t WHERE x = " . $widget->get_param( 'x' ) );
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('nadpisanie $request wartością bezpieczną zdejmuje status żądania', async () => {
    const f = sqli(
      await findingsFor(`<?php
function handler( $request ) {
	global $wpdb;
	$request = new Foo();
	return $wpdb->get_row( "SELECT * FROM t WHERE x = " . $request->get_param( 'x' ) );
}`),
    );
    expect(f).toHaveLength(0);
  });
});

const xss = (f: Finding[]) => f.filter((x) => x.ruleId === 'wp.xss.echo_superglobal');

describe('add_query_arg bez adresu jako źródło XSS', () => {
  it('echo add_query_arg( klucz, wartość ) bez esc_url jest zgłaszane', async () => {
    const f = xss(
      await findingsFor(`<?php
function view() {
	?><a href="<?php echo add_query_arg( 'generate', 'missing' ); ?>">Generuj</a><?php
}`),
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('medium');
    expect(f[0].message).toContain('add_query_arg');
  });

  it('wariant tablicowy i remove_query_arg z jednym argumentem', async () => {
    const f = xss(
      await findingsFor(`<?php
function view() {
	echo '<a href="' . add_query_arg( array( 'tab' => 'a' ) ) . '">A</a>';
	echo '<a href="' . remove_query_arg( 'paged' ) . '">B</a>';
}`),
    );
    expect(f).toHaveLength(2);
  });

  it('esc_url, esc_attr i podany adres czyszczą', async () => {
    const f = xss(
      await findingsFor(`<?php
function view() {
	echo '<a href="' . esc_url( add_query_arg( 'a', 'b' ) ) . '">A</a>';
	echo '<a href="' . esc_attr( remove_query_arg( 'paged' ) ) . '">B</a>';
	echo '<a href="' . add_query_arg( 'a', 'b', admin_url( 'admin.php' ) ) . '">C</a>';
	echo '<a href="' . add_query_arg( array( 'a' => 'b' ), admin_url() ) . '">D</a>';
	echo '<a href="' . remove_query_arg( 'a', home_url() ) . '">E</a>';
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('zmienna zasilona add_query_arg trafia do echo', async () => {
    const f = xss(
      await findingsFor(`<?php
function view( $section ) {
	$link = add_query_arg( array( 'tab' => $section ) );
	echo "<a href='$link'>x</a>";
}`),
    );
    expect(f).toHaveLength(1);
  });

  it('add_query_arg nie jest źródłem dla SQL', async () => {
    const f = sqli(
      await findingsFor(`<?php
function a() {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM t WHERE u = '" . add_query_arg( 'a', 'b' ) . "'" );
}`),
    );
    expect(f).toHaveLength(0);
  });
});

describe('dodatkowe ujścia XSS', () => {
  it('printf, wp_die i die z danymi użytkownika', async () => {
    const f = xss(
      await findingsFor(`<?php
function a() {
	printf( '<b>%s</b>', $_GET['x'] );
	wp_die( 'Błąd: ' . $_GET['e'] );
	die( $_POST['m'] );
}`),
    );
    expect(f).toHaveLength(3);
    expect(f.every((x) => !x.patch)).toBe(true);
  });

  it('printf z esc_html i literałami jest czysty', async () => {
    const f = xss(
      await findingsFor(`<?php
function a() {
	printf( '<b>%s</b>', esc_html( $_GET['x'] ) );
	wp_die( esc_html__( 'Brak dostępu', 'x' ) );
	die( 'Koniec' );
	exit( 1 );
}`),
    );
    expect(f).toHaveLength(0);
  });
});

describe('elementy tablic o literalnych kluczach', () => {
  it('skażony element nie skaża innego klucza tej samej tablicy', async () => {
    const f = xss(
      await findingsFor(`<?php
function view() {
	$fields = array(
		'url'  => add_query_arg( array( 'show' => 1 ) ),
		'text' => __( 'Hide', 'x' ),
	);
	?><a href="<?php echo esc_url( $fields['url'] ); ?>"><?php echo $fields['text']; ?></a><?php
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('skażony klucz nadal jest zgłaszany', async () => {
    const f = xss(
      await findingsFor(`<?php
function view() {
	$fields = array( 'url' => 'x', 'text' => $_GET['t'] );
	echo $fields['text'];
	$fields['url'] = $_GET['u'];
	echo $fields['url'];
}`),
    );
    expect(f).toHaveLength(2);
  });

  it('nieznany klucz i cała tablica dziedziczą skażenie', async () => {
    const f = xss(
      await findingsFor(`<?php
function view( $k ) {
	$data = $_POST;
	echo $data['title'];
	$map = array( 'a' => $_GET['a'] );
	echo $map[ $k ];
}`),
    );
    expect(f).toHaveLength(2);
  });

  it('nadpisanie całej tablicy unieważnia stary klucz', async () => {
    const f = xss(
      await findingsFor(`<?php
function view() {
	$row = array( 'name' => $_GET['n'] );
	$row = array( 'name' => 'stały' );
	echo $row['name'];
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('dopisanie do klucza przez .= zachowuje skażenie', async () => {
    const f = xss(
      await findingsFor(`<?php
function view() {
	$row = array( 'name' => 'a' );
	$row['name'] .= $_GET['n'];
	echo $row['name'];
}`),
    );
    expect(f).toHaveLength(1);
  });
});

describe('JSON w die i wp_die', () => {
  it('json_encode w ujściach pomocniczych jest pomijane, w echo nadal zgłaszane', async () => {
    const f = xss(
      await findingsFor(`<?php
function a() {
	wp_die( json_encode( array( 'x' => $_GET['x'] ) ) );
	die( wp_json_encode( $_POST ) );
	echo json_encode( $_GET );
}`),
    );
    expect(f).toHaveLength(1);
  });
});

describe('reguła rozszerzona wp.sqli.param_unprepared', () => {
  async function extendedFindings(code: string): Promise<Finding[]> {
    const dir = mkdtempSync(join(tmpdir(), 'wpcs-ext-'));
    dirs.push(dir);
    writeFileSync(join(dir, 'sample.php'), code, 'utf8');
    const result = await scan(dir, { cwd: dir, extended: true });
    return result.findings;
  }
  const ext = (f: Finding[]) => f.filter((x) => x.ruleId === 'wp.sqli.param_unprepared');

  it('parametr w zapytaniu bez prepare jest zgłaszany tylko w trybie rozszerzonym', async () => {
    const code = `<?php
function get_meta( $map_id ) {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}maps WHERE id = $map_id" );
}`;
    expect(ext(await extendedFindings(code))).toHaveLength(1);
    expect(ext(await findingsFor(code))).toHaveLength(0);
  });

  it('absint, typ int, prepare i nadpisanie zdejmują podejrzenie', async () => {
    const f = ext(
      await extendedFindings(`<?php
function a( $id ) {
	global $wpdb;
	$id = absint( $id );
	return $wpdb->get_row( "SELECT * FROM t WHERE id = $id" );
}
function b( int $id ) {
	global $wpdb;
	return $wpdb->get_row( "SELECT * FROM t WHERE id = $id" );
}
function c( $name ) {
	global $wpdb;
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM t WHERE n = %s", $name ) );
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('nie dubluje zwykłej reguły dla superglobala', async () => {
    const f = await extendedFindings(`<?php
function a( $x ) {
	global $wpdb;
	return $wpdb->get_row( "SELECT * FROM t WHERE id = " . $_GET['id'] . $x );
}`);
    expect(ext(f)).toHaveLength(0);
    expect(f.filter((x) => x.ruleId === 'wp.sqli.unprepared')).toHaveLength(1);
  });
});

describe('atrybuty shortcode (zapisany XSS)', () => {
  it('atrybut zwracany w HTML bez ucieczki jest zgłaszany', async () => {
    const f = xss(
      await findingsFor(`<?php
add_shortcode( 'demo', 'demo_shortcode' );
function demo_shortcode( $atts ) {
	$a = shortcode_atts( array( 'title' => '', 'color' => 'red' ), $atts );
	return '<h2 style="color:' . $a['color'] . '">' . esc_html( $a['title'] ) . '</h2>';
}`),
    );
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('atrybutów shortcode');
    expect(f[0].message).toContain('zapisany XSS');
  });

  it('extract( shortcode_atts ) tworzy zmienne ze skażeniem', async () => {
    const f = xss(
      await findingsFor(`<?php
class Demo {
	public function __construct() {
		add_shortcode( 'demo', array( $this, 'render' ) );
	}
	public function render( $atts, $content = null ) {
		extract( shortcode_atts( array( 'class' => 'x', 'id' => 0 ), $atts ) );
		$id = absint( $id );
		return "<div id='item-$id' class='$class'>" . $content . '</div>';
	}
}`),
    );
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('$class');
  });

  it('echo w callbacku shortcode i domknięcie', async () => {
    const f = xss(
      await findingsFor(`<?php
add_shortcode( 'one', function ( $atts ) {
	$a = shortcode_atts( array( 'text' => '' ), $atts );
	ob_start();
	echo '<p>' . $a['text'] . '</p>';
	return ob_get_clean();
} );`),
    );
    expect(f).toHaveLength(1);
  });

  it('ucieczka, absint i inne atrybuty zdejmują podejrzenie', async () => {
    const f = xss(
      await findingsFor(`<?php
add_shortcode( 'safe', 'safe_shortcode' );
function safe_shortcode( $atts ) {
	$a = shortcode_atts( array( 'title' => '', 'n' => 1, 'cls' => '' ), $atts );
	$n = absint( $a['n'] );
	return '<h2 class="' . esc_attr( $a['cls'] ) . '">' . esc_html( $a['title'] ) . ' ' . $n . '</h2>';
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('funkcja niebędąca callbackiem shortcode nie jest oceniana', async () => {
    const f = xss(
      await findingsFor(`<?php
function helper( $atts ) {
	return '<b>' . $atts['x'] . '</b>';
}`),
    );
    expect(f).toHaveLength(0);
  });
});

describe('unserialize z ograniczoną listą klas', () => {
  it('lista klas obniża zgłoszenie do heurystyki, a false je usuwa', async () => {
    const f = await findingsFor(`<?php
function a() {
	$one = unserialize( base64_decode( $_POST['d'] ), array( 'allowed_classes' => array( 'Foo' ) ) );
	$two = unserialize( base64_decode( $_POST['d'] ), array( 'allowed_classes' => false ) );
	$three = unserialize( $_POST['d'] );
}`);
    const u = f.filter((x) => x.ruleId === 'wp.unserialize.user_input');
    expect(u).toHaveLength(2);
    const limited = u.find((x) => x.confidence === 'heuristic');
    expect(limited?.severity).toBe('medium');
    expect(u.filter((x) => x.confidence === 'firm')).toHaveLength(1);
  });
});
