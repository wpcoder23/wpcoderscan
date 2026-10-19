// Reguła wp.xss.echo_superglobal: HTML składany w kodzie i zwracany, zapisany we właściwości albo wklejony
// do do_shortcode. Każdy przypadek ujemny ma dodatni odpowiednik, żeby poprawka nie zamieniła się w ślepotę.
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

async function xss(code: string): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-xsshtml-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === 'wp.xss.echo_superglobal');
}

describe('HTML zwracany przez funkcję', () => {
  it('return z tagiem i adresem żądania bez ucieczki', async () => {
    const f = await xss(`<?php
function form_action() {
	return '<form action="' . $_SERVER['PHP_SELF'] . '" method="post"></form>';
}`);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('medium');
    expect(f[0].message).toContain('HTML text');
  });

  it('esc_url zdejmuje skażenie', async () => {
    const f = await xss(`<?php
function form_action() {
	return '<form action="' . esc_url( $_SERVER['PHP_SELF'] ) . '" method="post"></form>';
}`);
    expect(f).toHaveLength(0);
  });

  it('zmienna zbudowana przez .= i zwrócona', async () => {
    const f = await xss(`<?php
function render_box( $content ) {
	$out = $content;
	$out .= '<div class="box">' . $_GET['q'] . '</div>';
	return $out;
}`);
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('Variable $out');
  });

  it('esc_html w składanym HTML', async () => {
    const f = await xss(`<?php
function render_box( $content ) {
	$out = $content;
	$out .= '<div class="box">' . esc_html( $_GET['q'] ) . '</div>';
	return $out;
}`);
    expect(f).toHaveLength(0);
  });

  it('tablica linków zbudowana z add_query_arg i zwrócona', async () => {
    const f = await xss(`<?php
function get_views( $views ) {
	$url = add_query_arg( 'code', $_GET['code'] );
	$views['all'] = "<a href='{$url}'>All</a>";
	return $views;
}`);
    expect(f).toHaveLength(1);
  });

  it('ten sam kod z esc_url jest czysty', async () => {
    const f = await xss(`<?php
function get_views( $views ) {
	$url = esc_url( add_query_arg( 'code', $_GET['code'] ) );
	$views['all'] = "<a href='{$url}'>All</a>";
	return $views;
}`);
    expect(f).toHaveLength(0);
  });

  it('zwrócenie samych danych bez HTML nie jest zgłaszane', async () => {
    const f = await xss(`<?php
function get_id() {
	return $_GET['id'];
}
function get_label() {
	return 'a < b ' . $_GET['id'];
}`);
    expect(f).toHaveLength(0);
  });

  it('zwrot shortcode nie jest zgłaszany dwa razy', async () => {
    const f = await xss(`<?php
add_shortcode( 'box', 'box_shortcode' );
function box_shortcode( $atts ) {
	$a = shortcode_atts( array( 'title' => '' ), $atts );
	return '<div>' . $a['title'] . '</div>';
}`);
    expect(f).toHaveLength(1);
  });
});

describe('HTML zapisany we właściwości', () => {
  it('właściwość obiektu dostaje HTML z danymi żądania', async () => {
    const f = await xss(`<?php
function fill( $template ) {
	$template->content = '<div class="notice"><p>' . $_SERVER['PHP_SELF'] . '</p></div>';
}`);
    expect(f).toHaveLength(1);
  });

  it('właściwość z danymi bez HTML nie jest zgłaszana', async () => {
    const f = await xss(`<?php
function fill( $template ) {
	$template->content = $_GET['q'];
}`);
    expect(f).toHaveLength(0);
  });
});

describe('do_shortcode', () => {
  it('atrybut z żądania wklejony do kodu krótkiego', async () => {
    const f = await xss(`<?php
function show() {
	echo do_shortcode( '[gallery ids="' . $_GET['ids'] . '"]' );
}`);
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('do_shortcode');
  });

  it('atrybut rzutowany na liczbę jest czysty', async () => {
    const f = await xss(`<?php
function show() {
	echo do_shortcode( '[gallery ids="' . absint( $_GET['ids'] ) . '"]' );
}`);
    expect(f).toHaveLength(0);
  });

  it('stały kod krótki jest czysty', async () => {
    const f = await xss(`<?php
function show() {
	echo do_shortcode( '[gallery ids="1,2,3"]' );
}`);
    expect(f).toHaveLength(0);
  });
});
