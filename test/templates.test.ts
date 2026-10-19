// Funkcje ładujące szablon po nazwie z danych użytkownika (local file inclusion przez get_template_part i podobne).
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
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-tpl-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings;
}

const rce = (f: Finding[]) => f.filter((x) => x.ruleId === 'wp.rce.dynamic');

describe('szablon ładowany po nazwie z danych użytkownika', () => {
  it('get_template_part z superglobala to wykrycie pewne', async () => {
    const f = rce(
      await findingsFor(`<?php
function show() {
	get_template_part( $_GET['part'] );
}`),
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('firm');
    expect(f[0].line).toBe(3);
    expect(f[0].message).toMatch(/get_template_part\(\) loads a template/);
  });

  it('nazwa sklejona z dwóch argumentów get_template_part też jest sprawdzana', async () => {
    const f = rce(
      await findingsFor(`<?php
function show() {
	get_template_part( 'parts/block', $_POST['name'] );
}`),
    );
    expect(f).toHaveLength(1);
  });

  it('metoda na obiekcie o nazwie ładującej szablon daje heurystykę, także przy superglobalu', async () => {
    const f = rce(
      await findingsFor(`<?php
function ajax_tab() {
	$tab = isset( $_POST['tabname'] ) ? wc_clean( $_POST['tabname'] ) : '';
	$MVX->template->get_template( 'vendor/' . str_replace( '_', '-', $tab ) . '.php' );
	die;
}`),
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
    expect(f[0].severity).toBe('high');
  });

  it('nazwa zapisana camelCase i statyczna metoda są rozpoznawane', async () => {
    const f = rce(
      await findingsFor(`<?php
function a() {
	Functions::getTemplatePart( 'layout-' . $_GET['layout'] );
}`),
    );
    expect(f).toHaveLength(1);
  });

  it('nazwa oczyszczona sanitize_key albo basename nie jest zgłaszana', async () => {
    const f = rce(
      await findingsFor(`<?php
function a() {
	get_template_part( 'parts/' . sanitize_key( $_GET['part'] ) );
	locate_template( basename( $_GET['file'] ) );
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('stała nazwa albo nazwa z funkcji niczego nie zgłasza', async () => {
    const f = rce(
      await findingsFor(`<?php
function a() {
	get_template_part( 'parts/header', get_post_type() );
	load_template( __DIR__ . '/x.php' );
	wc_get_template( 'cart.php', array( 'item' => $_GET['item'] ) );
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('funkcje o podobnych nazwach, które niczego nie ładują, są pomijane', async () => {
    const f = rce(
      await findingsFor(`<?php
function a() {
	$slug = get_page_template_slug( $_GET['id'] );
	$dir  = get_template_directory() . '/' . $_GET['x'];
	is_page_template( $_GET['tpl'] );
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('funkcja ładująca zdefiniowana w tym samym pliku nie daje duplikatu przy wywołaniu', async () => {
    const f = rce(
      await findingsFor(`<?php
function lae_get_template_part( $name ) {
	include __DIR__ . '/tpl/' . $name . '.php';
}
function show() {
	lae_get_template_part( $_GET['tpl'] );
}`),
    );
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(3);
  });

  it('tablica danych przekazana szablonowi nie jest jego nazwą', async () => {
    const f = rce(
      await findingsFor(`<?php
function show() {
	$search = $_GET['search'];
	learndash_get_template_part( 'shortcodes/search.php', array( 'search' => $search ), true );
	$post = WPCF7_ContactForm::get_template( array( 'locale' => $_GET['locale'] ) );
}`),
    );
    expect(f).toHaveLength(0);
  });

  it('nazwa szablonu obok tablicy danych nadal jest oceniana', async () => {
    const f = rce(
      await findingsFor(`<?php
function show() {
	learndash_get_template_part( $_GET['tpl'], array( 'a' => 1 ), true );
}`),
    );
    expect(f).toHaveLength(1);
  });

  it('zmienna zasilona z żądania jest śledzona do argumentu', async () => {
    const f = rce(
      await findingsFor(`<?php
function show() {
	$layout = $_GET['layout'];
	$layout = trim( $layout );
	return $this->load_template( $layout, array() );
}`),
    );
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
    expect(f[0].message).toMatch(/variable \$layout/);
  });
});
