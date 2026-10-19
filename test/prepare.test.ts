// Dane użytkownika wklejone w tekst zapytania podany do $wpdb->prepare (prepare chroni tylko argumenty).
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
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-prep-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings;
}

const sqli = (f: Finding[]) => f.filter((x) => x.ruleId === 'wp.sqli.unprepared');

describe('prepare z danymi w tekście zapytania', () => {
  it('kolumna ORDER BY ze zmiennej z żądania w tekście prepare', async () => {
    const f = sqli(
      await findingsFor(`<?php
function rows() {
	global $wpdb;
	$orderby = $_GET['orderby'];
	return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}items ORDER BY $orderby LIMIT %d", 10 ) );
}`),
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
  });

  it('superglobal wklejony wprost w tekst prepare to wykrycie pewne', async () => {
    const f = sqli(
      await findingsFor(`<?php
function rows() {
	global $wpdb;
	return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}items WHERE name = '" . $_GET['name'] . "'" ) );
}`),
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('firm');
  });

  it('zapytanie zapisane w zmiennej przez prepare i podane dalej', async () => {
    const f = sqli(
      await findingsFor(`<?php
function rows() {
	global $wpdb;
	$col = $_GET['col'];
	$sql = $wpdb->prepare( "SELECT $col FROM {$wpdb->prefix}items WHERE id = %d", 1 );
	return $wpdb->get_results( $sql );
}`),
    );
    expect(f).toHaveLength(1);
  });

  it('wartości podane jako argumenty prepare nie są zgłaszane', async () => {
    const f = sqli(
      await findingsFor(`<?php
function rows() {
	global $wpdb;
	return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}items WHERE name = %s AND id = %d", $_GET['name'], $_GET['id'] ) );
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('kolumna sprawdzona listą dozwolonych wartości albo sanitize_sql_orderby nie jest zgłaszana', async () => {
    const f = sqli(
      await findingsFor(`<?php
function a() {
	global $wpdb;
	$orderby = isset( $_GET['orderby'] ) && in_array( $_GET['orderby'], array( 'id', 'name' ), true ) ? $_GET['orderby'] : 'id';
	return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}items ORDER BY $orderby LIMIT %d", 10 ) );
}
function b() {
	global $wpdb;
	$orderby = sanitize_sql_orderby( $_GET['orderby'] );
	return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}items ORDER BY $orderby LIMIT %d", 10 ) );
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('fragment zapytania przygotowany wcześniej przez prepare nie skaża kolejnego', async () => {
    const f = sqli(
      await findingsFor(`<?php
function rows() {
	global $wpdb;
	$where = $wpdb->prepare( ' AND name = %s', $_GET['name'] );
	return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}items WHERE 1=1 $where" );
}`),
    );
    expect(f).toHaveLength(0);
  });
});
