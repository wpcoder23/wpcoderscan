// esc_sql i addslashes chronią wartość w cudzysłowie zapytania. Liczba, kolumna i ORDER BY zostają podatne.
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

async function sqli(code: string): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-esc-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === 'wp.sqli.unprepared');
}

describe('ucieczka cudzysłowów a miejsce wartości w zapytaniu', () => {
  it('esc_sql na superglobalu poza cudzysłowem to wykrycie pewne', async () => {
    const f = await sqli(`<?php
function rows() {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t ORDER BY " . esc_sql( $_GET['orderby'] ) );
}`);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('firm');
    expect(f[0].severity).toBe('high');
    expect(f[0].message).toMatch(/outside quotes/);
  });

  it('jedna wartość w cudzysłowie i jedna poza nim: zgłaszana jest ta poza cudzysłowem', async () => {
    const f = await sqli(`<?php
function rows() {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE a = '" . esc_sql( $_GET['a'] ) . "' AND b = " . esc_sql( $_GET['b'] ) );
}`);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].message).toMatch(/outside quotes/);
  });

  it('wartość po esc_sql obok zwykłego skażenia nie zmienia werdyktu o zwykłym skażeniu', async () => {
    const f = await sqli(`<?php
function rows() {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE a = '" . esc_sql( $_GET['a'] ) . "' AND b = '" . $_GET['b'] . "'" );
}`);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
  });

  it('wartość w cudzysłowie wewnątrz warunku trójargumentowego nie jest oceniana drugi raz', async () => {
    const f = await sqli(`<?php
function rows() {
	global $wpdb;
	$search = isset( $_GET['s'] ) ? $_GET['s'] : '';
	return $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE post_type = '" . esc_sql( $_GET['t'] ) . "'
		AND meta_key = 'panels_data'
		" . ( ! empty( $search ) ? 'AND post_title LIKE "%' . esc_sql( $search ) . '%"' : '' ) . "
		ORDER BY post_date DESC" );
}`);
    expect(f).toHaveLength(0);
  });

  it('wartość po esc_sql w gałęzi warunku, wklejona poza cudzysłowem, nadal jest zgłaszana', async () => {
    const f = await sqli(`<?php
function rows() {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE post_type = 'page' AND " . ( ! empty( $_GET['id'] ) ? 'ID = ' . esc_sql( $_GET['id'] ) : '1 = 1' ) );
}`);
    expect(f).toHaveLength(1);
  });

  it('liczba po znaku równości bez cudzysłowu też jest zgłaszana', async () => {
    const f = await sqli(`<?php
function one() {
	global $wpdb;
	return $wpdb->get_row( "SELECT * FROM {$wpdb->prefix}t WHERE id = " . addslashes( $_POST['id'] ) );
}`);
    expect(f).toHaveLength(1);
  });

  it('wartość w cudzysłowie po esc_sql jest czysta', async () => {
    const f = await sqli(`<?php
function rows() {
	global $wpdb;
	$a = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE name = '" . esc_sql( $_GET['n'] ) . "'" );
	$b = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE name LIKE '%" . esc_sql( $_GET['n'] ) . "%'" );
	return array( $a, $b );
}`);
    expect(f).toHaveLength(0);
  });

  it('zmienna z wartością po esc_sql wstawiona w cudzysłów jest czysta, a bez cudzysłowu zgłaszana', async () => {
    const quoted = await sqli(`<?php
function rows() {
	global $wpdb;
	$name = esc_sql( $_GET['n'] );
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE name = '$name'" );
}`);
    expect(quoted).toHaveLength(0);

    const bare = await sqli(`<?php
function rows() {
	global $wpdb;
	$orderby = esc_sql( $_GET['orderby'] );
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t ORDER BY $orderby" );
}`);
    expect(bare).toHaveLength(1);
    expect(bare[0].confidence).toBe('heuristic');
    expect(bare[0].message).toMatch(/variable \$orderby/);
  });

  it('lista identyfikatorów po array_map esc_sql: w cudzysłowach czysta, bez cudzysłowów zgłaszana', async () => {
    const quoted = await sqli(`<?php
function rows() {
	global $wpdb;
	$ids = $_POST['ids'];
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE slug IN ('" . implode( "','", array_map( 'esc_sql', $ids ) ) . "')" );
}`);
    expect(quoted).toHaveLength(0);

    const bare = await sqli(`<?php
function rows() {
	global $wpdb;
	$ids = $_POST['ids'];
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE id IN (" . implode( ',', array_map( 'esc_sql', $ids ) ) . ")" );
}`);
    expect(bare).toHaveLength(1);
  });

  it('nazwa w odwrotnych apostrofach nie jest chroniona przez esc_sql', async () => {
    const f = await sqli(`<?php
function rows() {
	global $wpdb;
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t ORDER BY \`" . esc_sql( $_GET['col'] ) . "\`" );
}`);
    expect(f).toHaveLength(1);
  });

  it('metody $wpdb->_escape i escape działają jak esc_sql', async () => {
    const f = await sqli(`<?php
function rows() {
	global $wpdb;
	$a = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE id = " . $wpdb->_escape( $_GET['id'] ) );
	$b = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE n = '" . $wpdb->_escape( $_GET['n'] ) . "'" );
	return array( $a, $b );
}`);
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(4);
  });

  it('rzutowanie na liczbę i absint zdejmują skażenie także po esc_sql', async () => {
    const f = await sqli(`<?php
function rows() {
	global $wpdb;
	$a = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE id = " . (int) esc_sql( $_GET['id'] ) );
	$b = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t WHERE id = " . absint( esc_sql( $_GET['id'] ) ) );
	return array( $a, $b );
}`);
    expect(f).toHaveLength(0);
  });

  it('całe zapytanie po esc_sql bez kontekstu cudzysłowów zostaje uznane za czyste', async () => {
    const f = await sqli(`<?php
function rows() {
	global $wpdb;
	return $wpdb->get_results( esc_sql( $_GET['q'] ) );
}`);
    expect(f).toHaveLength(0);
  });

  it('dopisanie wartości po esc_sql do zapytania nie zdejmuje wcześniejszego skażenia', async () => {
    const f = await sqli(`<?php
function rows() {
	global $wpdb;
	$where = ' WHERE 1=1';
	$where .= ' AND a = ' . $_GET['a'];
	$where .= " AND b = '" . esc_sql( $_GET['b'] ) . "'";
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t" . $where );
}`);
    expect(f).toHaveLength(1);
  });

  it('wartość po esc_sql sprawdzona wcześniej listą dozwolonych wartości jest czysta', async () => {
    const f = await sqli(`<?php
function rows() {
	global $wpdb;
	$orderby = in_array( $_GET['orderby'], array( 'id', 'name' ), true ) ? $_GET['orderby'] : 'id';
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t ORDER BY " . esc_sql( $orderby ) );
}`);
    expect(f).toHaveLength(0);
  });
});
