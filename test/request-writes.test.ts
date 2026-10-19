// Zapisy do superglobali. Wartość domyślna wpisana w jednej gałęzi nie czyści elementu dla reszty kodu,
// a zapis, który sam sięga po superglobal i go oczyszcza, nadal czyści. Każdy przypadek ujemny ma
// dodatni odpowiednik, żeby poprawka nie zamieniła się w ślepotę.
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
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-reqw-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir, extended });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === ruleId);
}

const SQLI = 'wp.sqli.unprepared';
const XSS = 'wp.xss.echo_superglobal';

describe('wartość domyślna wpisana do superglobala', () => {
  it('esc_sql poza cudzysłowem po domyślnej wartości nadal jest SQL injection', async () => {
    const f = await run(`<?php
function list_rows() {
	global $wpdb;
	if ( empty( $_REQUEST['orderby'] ) ) {
		$_REQUEST['orderby'] = 'id';
	}
	$orderby = ' ORDER BY ' . esc_sql( $_REQUEST['orderby'] );
	$query = $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}rows" . $orderby . " LIMIT %d", 10 );
	return $wpdb->get_results( $query );
}`, SQLI);
    expect(f).toHaveLength(1);
  });

  it('echo elementu po domyślnej wartości nadal jest XSS', async () => {
    const f = await run(`<?php
function tab() {
	if ( empty( $_GET['tab'] ) ) {
		$_GET['tab'] = 'general';
	}
	echo $_GET['tab'];
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('zmienna przepisana z elementu po domyślnej wartości też jest skażona', async () => {
    const f = await run(`<?php
function tab() {
	if ( ! isset( $_GET['tab'] ) ) {
		$_GET['tab'] = 'general';
	}
	$name = $_GET['tab'];
	echo $name;
}`, XSS);
    expect(f).toHaveLength(1);
  });
});

describe('zapis do superglobala, który sam go oczyszcza', () => {
  it('sanitize_text_field na tym samym elemencie czyści go', async () => {
    const f = await run(`<?php
function tab() {
	$_GET['tab'] = sanitize_text_field( $_GET['tab'] );
	echo $_GET['tab'];
}`, XSS);
    expect(f).toHaveLength(0);
  });

  it('rzutowanie na liczbę czyści element przed zapytaniem', async () => {
    const f = await run(`<?php
function load() {
	global $wpdb;
	$_GET['id'] = (int) $_GET['id'];
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}rows WHERE id = " . $_GET['id'] );
}`, SQLI);
    expect(f).toHaveLength(0);
  });

  it('bez zapisu ten sam kod z echo jest XSS', async () => {
    const f = await run(`<?php
function tab() {
	echo $_GET['tab'];
}`, XSS);
    expect(f).toHaveLength(1);
  });
});
