// Reguła wp.auth.unprotected_action: cztery przypadki, w których uchwyt jest bezpieczny, choć nie woła nonce
// ani current_user_can. Pomocnik o nazwie legit, token jednorazowy z opcji, callback z wymaganym parametrem
// i samo czyszczenie transientu. Każdy przypadek ujemny ma dodatni odpowiednik, żeby poprawka nie zamieniła się w ślepotę.
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
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-authprec-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === 'wp.auth.unprotected_action');
}

describe('pomocnik o nazwie legit', () => {
  it('is_legit_ajax_call w innej klasie uspokaja regułę', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_opt_out', 'acme_opt_out' );
function acme_opt_out() {
	if ( ! \\Acme\\Utils::is_legit_ajax_call( 'acme_opt_out' ) ) {
		wp_send_json_error( 'Permission denied' );
	}
	update_option( 'acme_opt_out', gmdate( 'Y-m-d' ) );
}`);
    expect(f).toHaveLength(0);
  });

  it('pomocnik o neutralnej nazwie nie uspokaja reguły', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_opt_out', 'acme_opt_out' );
function acme_opt_out() {
	if ( ! \\Acme\\Utils::is_ready( 'acme_opt_out' ) ) {
		wp_send_json_error( 'Not ready' );
	}
	update_option( 'acme_opt_out', gmdate( 'Y-m-d' ) );
}`);
    expect(f).toHaveLength(2);
  });
});

describe('token jednorazowy zamiast nonce', () => {
  it('skrót tokenu z opcji porównany z wartością z żądania', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_nopriv_acme_connect', 'acme_connect' );
function acme_connect() {
	$given = ! empty( $_REQUEST['oth'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['oth'] ) ) : '';
	$oth   = get_option( 'acme_connect_token' );
	if ( empty( $oth ) ) {
		wp_send_json_error( 'x' );
	}
	if ( hash_hmac( 'sha512', $oth, wp_salt() ) !== $given ) {
		wp_send_json_error( 'x' );
	}
	delete_option( 'acme_connect_token' );
	activate_plugin( 'acme-pro/acme.php' );
}`);
    expect(f).toHaveLength(0);
  });

  it('hash_equals z transientem i wartością z żądania', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_state', 'acme_state' );
function acme_state() {
	if ( ! hash_equals( get_transient( 'acme_state' ), $_POST['state'] ) ) {
		wp_die( 'x' );
	}
	update_option( 'acme_linked', 1 );
}`);
    expect(f).toHaveLength(0);
  });

  it('dwie wartości z żądania nie są sekretem', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_save', 'acme_save' );
function acme_save() {
	if ( $_POST['a'] !== $_POST['b'] ) {
		wp_die( 'x' );
	}
	update_option( 'acme', $_POST['a'] );
}`);
    expect(f).toHaveLength(2);
  });

  it('opcja porównana ze stałą nie jest sekretem', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_save', 'acme_save' );
function acme_save() {
	if ( get_option( 'acme_mode' ) === 'live' ) {
		update_option( 'acme', $_POST['v'] );
	}
}`);
    expect(f).toHaveLength(2);
  });

  it('wartość z żądania porównana ze stałą nie jest sekretem', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_save', 'acme_save' );
function acme_save() {
	if ( $_POST['mode'] === 'live' ) {
		update_option( 'acme', $_POST['v'] );
	}
}`);
    expect(f).toHaveLength(2);
  });

  it('opcja wybrana przez żądanie nie jest sekretem', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_save', 'acme_save' );
function acme_save() {
	if ( get_option( 'acme_' . $_POST['k'] ) === $_POST['v'] ) {
		update_option( 'acme', 1 );
	}
}`);
    expect(f).toHaveLength(2);
  });
});

describe('callback z wymaganym parametrem', () => {
  it('metoda z dwoma wymaganymi parametrami na haku admin_post', async () => {
    const f = await auth(`<?php
class Slider {
	public function __construct() {
		add_action( 'admin_post_acme_delete_slide', array( $this, 'delete_slide' ) );
	}
	public function delete_slide( $slide_id, $slideshow_id ) {
		wp_update_post( array( 'ID' => $slideshow_id ) );
	}
}`);
    expect(f).toHaveLength(0);
  });

  it('domknięcie z wymaganym parametrem na haku wp_ajax', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_clear', function ( $id ) {
	update_option( 'acme_cleared', $id );
} );`);
    expect(f).toHaveLength(0);
  });

  it('parametry z wartościami domyślnymi nie chronią', async () => {
    const f = await auth(`<?php
class Slider {
	public function __construct() {
		add_action( 'admin_post_acme_delete_slide', array( $this, 'delete_slide' ) );
	}
	public function delete_slide( $slide_id = 0, $slideshow_id = 0 ) {
		wp_update_post( array( 'ID' => $_GET['id'] ) );
	}
}`);
    expect(f).toHaveLength(2);
  });

  it('parametr wariadyczny i brak parametrów nie chronią', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_a', function ( ...$args ) {
	update_option( 'acme_a', $_POST['v'] );
} );
add_action( 'wp_ajax_acme_b', function () {
	update_option( 'acme_b', $_POST['v'] );
} );`);
    expect(f).toHaveLength(4);
  });
});

describe('samo czyszczenie transientu', () => {
  it('usunięcie transientu pod stałą klasy', async () => {
    const f = await auth(`<?php
class Shipping {
	const COUNT_TRANSIENT = 'acme_zone_count';
	public static function init() {
		add_action( 'wp_ajax_acme_zones_save', array( __CLASS__, 'delete_count_transient' ) );
	}
	public static function delete_count_transient() {
		delete_transient( self::COUNT_TRANSIENT );
	}
}`);
    expect(f).toHaveLength(0);
  });

  it('transient o nazwie z żądania nadal jest zgłaszany', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_clear', 'acme_clear' );
function acme_clear() {
	delete_transient( 'acme_' . $_POST['id'] );
}`);
    expect(f).toHaveLength(2);
  });

  it('usunięcie transientu razem z zapisem opcji nadal jest zgłaszane', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_clear', 'acme_clear' );
function acme_clear() {
	delete_transient( 'acme_count' );
	update_option( 'acme_mode', $_POST['mode'] );
}`);
    expect(f).toHaveLength(2);
  });

  it('zapis transientu nadal jest zgłaszany', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_remember', 'acme_remember' );
function acme_remember() {
	set_transient( 'acme_value', $_POST['v'] );
}`);
    expect(f).toHaveLength(2);
  });
});
