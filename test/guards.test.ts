// Zmienne sprawdzone listą dozwolonych wartości przed użyciem nie są już skażone.
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

async function rce(code: string): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-guard-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === 'wp.rce.dynamic');
}

describe('sprawdzenie zmiennej przed użyciem', () => {
  it('bez sprawdzenia include ze zmiennej od użytkownika jest zgłaszane', async () => {
    const f = await rce(`<?php
function a() {
	$page = $_GET['page'];
	include __DIR__ . '/views/' . $page . '.php';
}`);
    expect(f).toHaveLength(1);
  });

  it('in_array w warunku if uspokaja ciało', async () => {
    const f = await rce(`<?php
function a() {
	$page = $_GET['page'];
	if ( in_array( $page, array( 'one', 'two' ), true ) ) {
		include __DIR__ . '/views/' . $page . '.php';
	}
}`);
    expect(f).toHaveLength(0);
  });

  it('wczesne wyjście po nieudanym sprawdzeniu uspokaja dalszy kod', async () => {
    const f = await rce(`<?php
function a() {
	$page = $_GET['page'];
	if ( ! in_array( $page, array( 'one', 'two' ), true ) ) {
		return;
	}
	include __DIR__ . '/views/' . $page . '.php';
}`);
    expect(f).toHaveLength(0);
  });

  it('isset na tablicy z kluczem ze zmiennej i wyjście przez wp_die', async () => {
    const f = await rce(`<?php
class A {
	private $steps = array();
	function run() {
		$step = sanitize_text_field( $_GET['step'] );
		if ( ! isset( $this->steps[ $step ] ) ) {
			wp_die( 'x' );
		}
		$file = __DIR__ . '/steps/' . $step . '.php';
		include_once $file;
	}
}`);
    expect(f).toHaveLength(0);
  });

  it('zakotwiczone wyrażenie regularne, ctype i porównanie z literałem', async () => {
    const f = await rce(`<?php
function a() {
	$p = $_GET['p'];
	if ( preg_match( '/^[a-z-]+$/', $p ) ) { include $p . '.php'; }
	$q = $_GET['q'];
	if ( ctype_alnum( $q ) ) { include $q . '.php'; }
	$r = $_GET['r'];
	if ( $r === 'main' ) { include $r . '.php'; }
}`);
    expect(f).toHaveLength(0);
  });

  it('else po negacji sprawdzenia też jest uspokojone', async () => {
    const f = await rce(`<?php
function a() {
	$page = $_GET['page'];
	if ( ! in_array( $page, array( 'one' ), true ) ) {
		echo 'x';
	} else {
		include $page . '.php';
	}
}`);
    expect(f).toHaveLength(0);
  });

  it('sprawdzenie innej zmiennej, isset na superglobalu i wzorzec z .* nic nie potwierdzają', async () => {
    const f = await rce(`<?php
function a() {
	$page = $_GET['page'];
	$other = 'x';
	if ( in_array( $other, array( 'x' ), true ) ) { include $page . '.php'; }
	if ( isset( $_GET[ $page ] ) ) { include $page . '.php'; }
	if ( preg_match( '/^.*$/', $page ) ) { include $page . '.php'; }
	if ( isset( $page ) ) { include $page . '.php'; }
}`);
    expect(f).toHaveLength(4);
  });

  it('sprawdzenie w innej funkcji nie obejmuje zakresu funkcji zagnieżdżonej', async () => {
    const f = await rce(`<?php
function a() {
	$page = $_GET['page'];
	if ( in_array( $page, array( 'one' ), true ) ) {
		$cb = function () use ( $page ) {
			$page = $_GET['page'];
			include $page . '.php';
		};
	}
}`);
    expect(f).toHaveLength(1);
  });
});

async function byRule(code: string, ruleId: string): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-guard-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === ruleId);
}

describe('sprawdzenie elementu tablicy i warunek trójargumentowy', () => {
  const SQLI = 'wp.sqli.unprepared';

  it('bez sprawdzenia superglobal w zapytaniu jest zgłaszany', async () => {
    const f = await byRule(
      `<?php
function a() {
	global $wpdb;
	$wpdb->query( "DELETE FROM {$wpdb->prefix}t WHERE id = " . $_GET['id'] );
}`,
      SQLI,
    );
    expect(f).toHaveLength(1);
  });

  it('is_numeric na elemencie superglobala w if uspokaja ciało', async () => {
    const f = await byRule(
      `<?php
function a() {
	global $wpdb;
	if ( is_numeric( $_GET['id'] ) ) {
		$wpdb->query( "DELETE FROM {$wpdb->prefix}t WHERE id = " . $_GET['id'] );
	}
}`,
      SQLI,
    );
    expect(f).toHaveLength(0);
  });

  it('sprawdzenie innego klucza nie uspokaja', async () => {
    const f = await byRule(
      `<?php
function a() {
	global $wpdb;
	if ( is_numeric( $_GET['a'] ) ) {
		$wpdb->query( "DELETE FROM {$wpdb->prefix}t WHERE id = " . $_GET['b'] );
	}
}`,
      SQLI,
    );
    expect(f).toHaveLength(1);
  });

  it('in_array na elemencie dopuszcza tylko wartości z listy', async () => {
    const f = await byRule(
      `<?php
function a() {
	global $wpdb;
	if ( in_array( $_GET['order'], array( 'asc', 'desc' ), true ) ) {
		return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t ORDER BY id " . $_GET['order'] );
	}
}`,
      SQLI,
    );
    expect(f).toHaveLength(0);
  });

  it('warunek trójargumentowy z is_numeric zdejmuje skażenie z gałęzi prawdy', async () => {
    const f = await byRule(
      `<?php
function a() {
	global $wpdb;
	$id = is_numeric( $_GET['id'] ) ? $_GET['id'] : 0;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE id = " . $id );
}`,
      SQLI,
    );
    expect(f).toHaveLength(0);
  });

  it('gałąź fałszu warunku ze sprawdzeniem nadal niesie skażenie', async () => {
    const f = await byRule(
      `<?php
function a() {
	global $wpdb;
	$id = is_numeric( $_GET['id'] ) ? 0 : $_GET['id'];
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE id = " . $id );
}`,
      SQLI,
    );
    expect(f).toHaveLength(1);
  });

  it('negacja w warunku zdejmuje skażenie z gałęzi fałszu', async () => {
    const f = await byRule(
      `<?php
function a() {
	global $wpdb;
	$id = ! is_numeric( $_GET['id'] ) ? 0 : $_GET['id'];
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE id = " . $id );
}`,
      SQLI,
    );
    expect(f).toHaveLength(0);
  });

  it('atrybut shortcode sprawdzony is_numeric w warunku nie daje zapisanego XSS', async () => {
    const f = await byRule(
      `<?php
function gmap_sc( $atts = null ) {
	$atts = shortcode_atts( array( 'zoom' => 0 ), $atts );
	$atts['zoom'] = is_numeric( $atts['zoom'] ) && $atts['zoom'] > 0 ? '&z=' . $atts['zoom'] : '';
	return sprintf( '<iframe src="//maps.example/?q=1%s"></iframe>', $atts['zoom'] );
}`,
      'wp.xss.echo_superglobal',
    );
    expect(f).toHaveLength(0);
  });
});

describe('sprawdzony element tablicy z kilkoma kluczami', () => {
  const SQLI = 'wp.sqli.unprepared';
  const run = (guard: string, use: string) =>
    byRule(
      `<?php
function rows() {
	global $wpdb;
	$dir = 'DESC';
	${guard}
		$dir = ${use};
	}
	$sql = "SELECT * FROM t ORDER BY id $dir LIMIT %d";
	return $wpdb->get_results( $wpdb->prepare( $sql, 5 ) );
}`,
      SQLI,
    );
  const ONE = "if ( in_array( strtoupper( $_POST['order'][0]['dir'] ), array( 'ASC', 'DESC' ), true ) ) {";

  it('bez sprawdzenia element o trzech kluczach jest zgłaszany', async () => {
    expect(await run('if ( true ) {', "strtoupper( $_POST['order'][0]['dir'] )")).toHaveLength(1);
  });

  it('in_array na tym samym elemencie uspokaja jego użycie w ciele', async () => {
    expect(await run(ONE, "strtoupper( $_POST['order'][0]['dir'] )")).toHaveLength(0);
  });

  it('sprawdzenie jednego elementu nie obejmuje sąsiedniego', async () => {
    expect(await run(ONE, "strtoupper( $_POST['order'][1]['dir'] )")).toHaveLength(1);
    expect(await run(ONE, "strtoupper( $_POST['order'][0]['col'] )")).toHaveLength(1);
  });
});

describe('walidator wołany po nazwie i wzorzec odrzucający obce znaki', () => {
  const SQLI = 'wp.sqli.unprepared';
  const run = (guard: string) =>
    byRule(
      `<?php
class Repo {
	private function is_valid_table( $t ) { return in_array( $t, array( 'a', 'b' ), true ); }
	function rows() {
		global $wpdb;
		$t = $_GET['table'];
		${guard}
		return $wpdb->get_results( "SELECT * FROM {$t}" );
	}
}`,
      SQLI,
    );

  it('bez żadnego sprawdzenia nazwa tabeli z żądania jest zgłaszana', async () => {
    expect(await run('')).toHaveLength(1);
  });

  it('wczesne wyjście po nieudanym is_valid_* uspokaja dalszy kod', async () => {
    expect(await run('if ( ! $this->is_valid_table( $t ) ) { return array(); }')).toHaveLength(0);
  });

  it('metoda statyczna i funkcja o nazwie walidatora też się liczą', async () => {
    expect(await run('if ( ! self::is_valid_table( $t ) ) { return array(); }')).toHaveLength(0);
    expect(await run('if ( ! validate_table_name( $t ) ) { wp_die(); }')).toHaveLength(0);
  });

  it('walidator adresu e-mail albo URL niczego nie potwierdza', async () => {
    expect(await run('if ( ! is_valid_email( $t ) ) { return array(); }')).toHaveLength(1);
    expect(await run('if ( ! $this->is_safe_url( $t ) ) { return array(); }')).toHaveLength(1);
  });

  it('wzorzec odrzucający znaki spoza zbioru z wyjściem uspokaja dalszy kod', async () => {
    expect(await run("if ( preg_match( '/[^a-z0-9_]/i', $t ) ) { wp_die( 'bad' ); }")).toHaveLength(0);
    expect(await run("if ( preg_match( '/\\W/', $t ) ) { return array(); }")).toHaveLength(0);
  });

  it('wzorzec, który tylko szuka dozwolonego znaku, nic nie potwierdza', async () => {
    expect(await run("if ( preg_match( '/[a-z]/', $t ) ) { return array(); }")).toHaveLength(1);
  });
});
