// Reguła wp.auth.unprotected_action: uchwyty zapisane jako metody klasy z tego samego pliku.
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

async function auth(code: string): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-auth-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === 'wp.auth.unprotected_action');
}

describe('uchwyty będące metodami klasy', () => {
  it('[ $this, metoda ] bez nonce i uprawnień jest zgłaszane dwa razy', async () => {
    const f = await auth(`<?php
class Ajax {
	public function __construct() {
		add_action( 'wp_ajax_demo_save', array( $this, 'save' ) );
	}
	public function save() {
		update_option( 'demo', $_POST['v'] );
		wp_send_json_success();
	}
}`);
    expect(f).toHaveLength(2);
    expect(f.map((x) => x.message).join(' ')).toContain('nonce');
    expect(f.map((x) => x.message).join(' ')).toContain('capabilities');
  });

  it('wariant [ self::class, metoda ] i tekst Klasa::metoda', async () => {
    const f = await auth(`<?php
class A {
	public static function init() {
		add_action( 'wp_ajax_a', [ self::class, 'one' ] );
		add_action( 'wp_ajax_b', 'A::two' );
	}
	public static function one() { delete_option( 'x' ); }
	public static function two() { delete_option( 'y' ); }
}`);
    expect(f).toHaveLength(4);
  });

  it('metoda z nonce i current_user_can jest czysta', async () => {
    const f = await auth(`<?php
class Ajax {
	public function __construct() {
		add_action( 'wp_ajax_demo_save', array( $this, 'save' ) );
	}
	public function save() {
		check_ajax_referer( 'demo' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		update_option( 'demo', 1 );
	}
}`);
    expect(f).toHaveLength(0);
  });

  it('pomocnik o nazwie kontrolnej w metodzie uspokaja regułę', async () => {
    const f = await auth(`<?php
class Ajax {
	public function __construct() {
		add_action( 'wp_ajax_demo', array( $this, 'save' ) );
	}
	public function save() {
		$this->verify_request();
		update_option( 'demo', 1 );
	}
}`);
    expect(f).toHaveLength(0);
  });

  it('metoda niezmieniająca stanu i obcy obiekt nie są zgłaszane', async () => {
    const f = await auth(`<?php
class Ajax {
	public function __construct() {
		add_action( 'wp_ajax_read', array( $this, 'read' ) );
		add_action( 'wp_ajax_other', array( $this->helper, 'write' ) );
		add_action( 'wp_ajax_missing', array( $this, 'nope' ) );
	}
	public function read() { wp_send_json( get_option( 'demo' ) ); }
}`);
    expect(f).toHaveLength(0);
  });

  it('nopriv wymaga tylko nonce', async () => {
    const f = await auth(`<?php
class Ajax {
	public function __construct() {
		add_action( 'wp_ajax_nopriv_demo', array( $this, 'save' ) );
	}
	public function save() { update_option( 'demo', 1 ); }
}`);
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('nonce');
  });
});
