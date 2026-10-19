// Reguła wp.sqli.unprepared: fragmenty zapytania zwracane z filtrów WP_Query (posts_where, posts_orderby i inne)
// i zapisywane we właściwościach obiektów zapytań (query_orderby w pre_user_query).
// Każdy przypadek ujemny ma dodatni odpowiednik, żeby poprawka nie zamieniła się w ślepotę.
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
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-sqlclause-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === 'wp.sqli.unprepared');
}

describe('filtry fragmentów zapytania', () => {
  it('posts_where z danymi z żądania wklejonymi do zapytania', async () => {
    const f = await sqli(`<?php
add_filter( 'posts_where', 'filter_where' );
function filter_where( $where ) {
	return $where . " AND post_title = '" . $_GET['t'] . "'";
}`);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
    expect(f[0].message).toContain('posts_where');
  });

  it('esc_sql w cudzysłowie jest czysty', async () => {
    const f = await sqli(`<?php
add_filter( 'posts_where', 'filter_where' );
function filter_where( $where ) {
	return $where . " AND post_title = '" . esc_sql( $_GET['t'] ) . "'";
}`);
    expect(f).toHaveLength(0);
  });

  it('esc_sql poza cudzysłowem nadal jest SQL injection', async () => {
    const f = await sqli(`<?php
add_filter( 'posts_orderby', 'filter_orderby' );
function filter_orderby( $orderby ) {
	return 'ORDER BY ' . esc_sql( $_GET['orderby'] );
}`);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
  });

  it('domknięcie i metoda klasy też są rozwiązywane', async () => {
    const f = await sqli(`<?php
class Search {
	public function __construct() {
		add_filter( 'posts_join', array( $this, 'join' ) );
		add_filter( 'posts_search', function ( $search ) {
			return $search . " OR ID = " . $_POST['id'];
		} );
	}
	public function join( $join ) {
		return $join . " JOIN x ON x.id = " . $_GET['x'];
	}
}`);
    expect(f).toHaveLength(2);
  });

  it('funkcja strzałkowa', async () => {
    const f = await sqli(`<?php
add_filter( 'posts_groupby', fn( $g ) => $g . ', ' . $_GET['g'] );`);
    expect(f).toHaveLength(1);
  });

  it('wartość przez zmienną i rzutowanie na liczbę', async () => {
    const f = await sqli(`<?php
add_filter( 'posts_where', 'filter_where' );
function filter_where( $where ) {
	$id = (int) $_GET['id'];
	return $where . ' AND ID = ' . $id;
}`);
    expect(f).toHaveLength(0);
  });

  it('wartość przez zmienną bez rzutowania jest heurystyką', async () => {
    const f = await sqli(`<?php
add_filter( 'posts_where', 'filter_where' );
function filter_where( $where ) {
	$id = $_GET['id'];
	return $where . ' AND ID = ' . $id;
}`);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
  });

  it('funkcja niezarejestrowana na haku fragmentu zapytania nie jest sprawdzana', async () => {
    const f = await sqli(`<?php
add_filter( 'the_title', 'filter_title' );
function filter_title( $title ) {
	return $title . $_GET['suffix'];
}`);
    expect(f).toHaveLength(0);
  });
});

describe('właściwości obiektów zapytań', () => {
  it('query_orderby w pre_user_query', async () => {
    const f = await sqli(`<?php
add_action( 'pre_user_query', function ( $query ) {
	$query->query_orderby = ' ORDER BY ' . esc_sql( $_GET['sort'] ) . ' ASC';
} );`);
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('query_orderby');
  });

  it('query_where z wartością w cudzysłowie po esc_sql jest czyste', async () => {
    const f = await sqli(`<?php
add_action( 'pre_user_query', function ( $query ) {
	$query->query_where .= " AND user_login = '" . esc_sql( $_GET['login'] ) . "'";
} );`);
    expect(f).toHaveLength(0);
  });
});
