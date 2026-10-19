// Przypisania w gałęziach warunków i pętli. Zapis, który wykonuje się tylko w części przebiegów, nie zdejmuje
// skażenia z reszty, chyba że sam warunek sprawdza tę zmienną. Każdy przypadek ujemny ma dodatni odpowiednik,
// żeby poprawka nie zamieniła się w ślepotę.
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

async function run(code: string, ruleId: string, extended = false): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-branch-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir, extended });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === ruleId);
}

const XSS = 'wp.xss.echo_superglobal';
const SQLI = 'wp.sqli.unprepared';

describe('przepływ liniowy bez zmian', () => {
  it('zwykłe przypisanie czyste zdejmuje skażenie', async () => {
    const f = await run(`<?php
function show() {
	$name = $_GET['name'];
	$name = esc_html( $name );
	echo $name;
}`, XSS);
    expect(f).toHaveLength(0);
  });

  it('skażona zmienna bez nadpisania jest zgłaszana', async () => {
    const f = await run(`<?php
function show() {
	$name = $_GET['name'];
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('dopisanie czystego tekstu nie zdejmuje skażenia', async () => {
    const f = await run(`<?php
function show() {
	$html = $_GET['name'];
	$html .= '<br>';
	echo $html;
}`, XSS);
    expect(f).toHaveLength(1);
  });
});

describe('zapis w gałęzi warunku', () => {
  it('oczyszczenie pod warunkiem niezwiązanym ze zmienną nie zdejmuje skażenia', async () => {
    const f = await run(`<?php
function show( $flag ) {
	$name = $_GET['name'];
	if ( $flag ) {
		$name = esc_html( $name );
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('oczyszczenie pod warunkiem, który sprawdza zmienną, zdejmuje skażenie', async () => {
    const f = await run(`<?php
function show() {
	$name = $_GET['name'];
	if ( ! empty( $name ) ) {
		$name = esc_html( $name );
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(0);
  });

  it('ujście w tej samej gałęzi widzi oczyszczenie', async () => {
    const f = await run(`<?php
function show( $flag ) {
	$name = $_GET['name'];
	if ( $flag ) {
		$name = esc_html( $name );
		echo $name;
	}
}`, XSS);
    expect(f).toHaveLength(0);
  });

  it('ujście w drugiej gałęzi nie widzi zapisu z pierwszej', async () => {
    const f = await run(`<?php
function show( $flag ) {
	$name = 'domyślna';
	if ( $flag ) {
		$name = $_GET['name'];
	} else {
		echo $name;
	}
}`, XSS);
    expect(f).toHaveLength(0);
  });

  it('skażenie przypisane w gałęzi dociera do ujścia po warunku', async () => {
    const f = await run(`<?php
function show( $flag ) {
	$name = 'domyślna';
	if ( $flag ) {
		$name = $_GET['name'];
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('skażenie przypisane w else dociera do ujścia po warunku', async () => {
    const f = await run(`<?php
function show( $flag ) {
	if ( $flag ) {
		$name = 'domyślna';
	} else {
		$name = $_GET['name'];
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('oczyszczenie w elseif nie zdejmuje skażenia z reszty', async () => {
    const f = await run(`<?php
function show( $a, $b ) {
	$name = $_GET['name'];
	if ( $a ) {
		echo 'a';
	} elseif ( $b ) {
		$name = esc_html( $name );
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('składnia z dwukropkiem działa tak samo', async () => {
    const f = await run(`<?php
function show( $flag ) {
	$name = $_GET['name'];
	if ( $flag ):
		$name = esc_html( $name );
	endif;
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('warunek bez nawiasów klamrowych też jest gałęzią', async () => {
    const f = await run(`<?php
function show( $flag ) {
	$name = $_GET['name'];
	if ( $flag ) $name = esc_html( $name );
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('zagnieżdżone warunki: oczyszczenie w wewnętrznym nie zdejmuje skażenia', async () => {
    const f = await run(`<?php
function show( $a, $b ) {
	$name = $_GET['name'];
	if ( $a ) {
		if ( $b ) {
			$name = esc_html( $name );
		}
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('zagnieżdżone warunki: oczyszczenie w obu poziomach, gdy oba sprawdzają zmienną, zdejmuje skażenie', async () => {
    const f = await run(`<?php
function show() {
	$name = $_GET['name'];
	if ( isset( $name ) ) {
		if ( strlen( $name ) > 0 ) {
			$name = esc_html( $name );
		}
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(0);
  });
});

describe('zapis w pętli i w try', () => {
  it('oczyszczenie w pętli, która może się nie wykonać, nie zdejmuje skażenia', async () => {
    const f = await run(`<?php
function show( $items ) {
	$name = $_GET['name'];
	foreach ( $items as $item ) {
		$name = esc_html( $name );
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('oczyszczenie w pętli widoczne w tej pętli', async () => {
    const f = await run(`<?php
function show( $items ) {
	foreach ( $items as $item ) {
		$name = $_GET['name'];
		$name = esc_html( $name );
		echo $name;
	}
}`, XSS);
    expect(f).toHaveLength(0);
  });

  it('oczyszczenie w treści try zdejmuje skażenie', async () => {
    const f = await run(`<?php
function show() {
	$name = $_GET['name'];
	try {
		$name = esc_html( $name );
	} catch ( Exception $e ) {
		return;
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(0);
  });

  it('oczyszczenie tylko w catch nie zdejmuje skażenia', async () => {
    const f = await run(`<?php
function show() {
	$name = $_GET['name'];
	try {
		do_something();
	} catch ( Exception $e ) {
		$name = esc_html( $name );
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });
});

describe('inne klasy ujść', () => {
  it('SQL: zapytanie złożone przed warunkiem, w którym wywołano prepare, nadal jest podatne', async () => {
    const f = await run(`<?php
function rows( $flag ) {
	global $wpdb;
	$sql = "SELECT * FROM {$wpdb->posts} WHERE ID = " . $_GET['id'];
	if ( $flag ) {
		$sql = $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID = %d", 1 );
	}
	return $wpdb->get_results( $sql );
}`, SQLI);
    expect(f).toHaveLength(1);
  });

  it('SQL: prepare bez warunku zdejmuje skażenie', async () => {
    const f = await run(`<?php
function rows() {
	global $wpdb;
	$sql = "SELECT * FROM {$wpdb->posts} WHERE ID = " . $_GET['id'];
	$sql = $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE ID = %d", 1 );
	return $wpdb->get_results( $sql );
}`, SQLI);
    expect(f).toHaveLength(0);
  });
});

describe('nadpisanie w tej samej gałęzi', () => {
  it('późniejszy czysty zapis w gałęzi zdejmuje skażenie zapisane w niej wcześniej', async () => {
    const f = await run(`<?php
function show() {
	$name = 'domyślna';
	if ( isset( $_POST['go'] ) ) {
		$name = $_POST['name'];
		$name = get_option( 'saved' );
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(0);
  });

  it('to samo, gdy skażenie powstało w pętli wewnątrz gałęzi', async () => {
    const f = await run(`<?php
function show() {
	$opts = get_option( 'a' );
	if ( isset( $_POST['go'] ) ) {
		foreach ( $_POST as $value ) {
			$opts = $value;
		}
		$opts = get_option( 'a' );
	}
	echo $opts;
}`, XSS);
    expect(f).toHaveLength(0);
  });

  it('dopisywanie przed nadpisaniem też nie dociera do ujścia', async () => {
    const f = await run(`<?php
function show( $flag ) {
	if ( $flag ) {
		$html = '';
		$html .= $_POST['x'];
		$html = '<b>ok</b>';
	}
	echo $html;
}`, XSS);
    expect(f).toHaveLength(0);
  });

  it('czysty zapis przed skażonym w tej samej gałęzi nie pomaga', async () => {
    const f = await run(`<?php
function show() {
	if ( isset( $_POST['go'] ) ) {
		$name = get_option( 'saved' );
		$name = $_POST['name'];
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('czysty zapis w gałęzi zagnieżdżonej nie zdejmuje skażenia z gałęzi zewnętrznej', async () => {
    const f = await run(`<?php
function show( $a, $b ) {
	if ( $a ) {
		$name = $_POST['name'];
		if ( $b ) {
			$name = get_option( 'saved' );
		}
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('czysty zapis w innej gałęzi niż skażony nie zdejmuje skażenia', async () => {
    const f = await run(`<?php
function show( $a ) {
	$name = $_POST['name'];
	if ( $a ) {
		$name = get_option( 'saved' );
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('oczyszczenie w gałęzi po pobraniu danych w tej samej gałęzi', async () => {
    const f = await run(`<?php
function show( $a ) {
	if ( $a ) {
		$name = $_POST['name'];
		$name = esc_html( $name );
	}
	echo $name;
}`, XSS);
    expect(f).toHaveLength(0);
  });
});
