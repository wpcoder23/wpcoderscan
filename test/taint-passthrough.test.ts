// Funkcje, które zwracają fragment albo kopię argumentu, przenoszą skażenie. Funkcje budujące adres witryny
// przenoszą je tylko do XSS, bo host takiego adresu zawsze jest naszą witryną. Każdy przypadek ujemny ma
// dodatni odpowiednik, żeby zmiana nie zamieniła się w ślepotę.
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
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-pass-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir, extended });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === ruleId);
}

const XSS = 'wp.xss.echo_superglobal';
const SQLI = 'wp.sqli.unprepared';
const SSRF = 'wp.http.ssrf';

describe('przekształcenia tekstu i tablic', () => {
  it('strtr zwraca skażony tekst', async () => {
    const f = await run(`<?php
function show() {
	echo strtr( $_GET['q'], 'ab', 'cd' );
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('element tablicy z explode zostaje skażony', async () => {
    const f = await run(`<?php
function show() {
	$parts = explode( ',', $_GET['ids'] );
	$first = array_shift( $parts );
	echo $first;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('fragment tekstu po strstr trafia do zapytania', async () => {
    const f = await run(`<?php
function remove() {
	global $wpdb;
	$id = strstr( $_GET['id'], ',' );
	$wpdb->query( "DELETE FROM {$wpdb->posts} WHERE ID = $id" );
}`, SQLI);
    expect(f).toHaveLength(1);
  });

  it('liczba z intval po strstr jest czysta', async () => {
    const f = await run(`<?php
function remove() {
	global $wpdb;
	$id = intval( strstr( $_GET['id'], ',' ) );
	$wpdb->query( "DELETE FROM {$wpdb->posts} WHERE ID = $id" );
}`, SQLI);
    expect(f).toHaveLength(0);
  });
});

describe('funkcje budujące adres witryny', () => {
  it('adres z fragmentem z żądania wypisany bez esc_url to XSS', async () => {
    const f = await run(`<?php
function show() {
	$url = admin_url( 'admin.php?page=x&id=' . $_GET['id'] );
	echo $url;
}`, XSS);
    expect(f).toHaveLength(1);
  });

  it('ten sam adres po esc_url jest czysty', async () => {
    const f = await run(`<?php
function show() {
	echo esc_url( admin_url( 'admin.php?page=x&id=' . $_GET['id'] ) );
}`, XSS);
    expect(f).toHaveLength(0);
  });

  it('żądanie do adresu zbudowanego z home_url ma ustalony host, więc to nie SSRF', async () => {
    const f = await run(`<?php
function ping() {
	wp_remote_get( home_url( '/feed?tag=' . $_GET['tag'] ) );
}`, SSRF, true);
    expect(f).toHaveLength(0);
  });

  it('żądanie pod adres z żądania to SSRF', async () => {
    const f = await run(`<?php
function ping() {
	wp_remote_get( strtolower( $_GET['url'] ) );
}`, SSRF, true);
    expect(f).toHaveLength(1);
  });
});
