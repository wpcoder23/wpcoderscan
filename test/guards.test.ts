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
