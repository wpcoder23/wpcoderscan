// Reguły ujść: ścieżki plików, adresy HTTP, wysyłanie plików, role i nazwy opcji.
// Każda ma przypadki dodatnie (wykrycie pewne i heurystyczne) oraz ujemne (sprawdzenia, stałe przedrostki,
// ustalony host, bramka na uprawnienie administratora).
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

async function run(code: string, ruleId: string, extended = true): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-sink-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir, extended });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === ruleId);
}

const FILE = 'wp.file.path_traversal';
const SSRF = 'wp.http.ssrf';
const UPLOAD = 'wp.upload.unrestricted';
const PRIV = 'wp.privilege.escalation';
const OPTION = 'wp.option.arbitrary_update';

describe('ścieżka pliku od użytkownika (wp.file.path_traversal)', () => {
  it('unlink na superglobalu to wykrycie pewne', async () => {
    const f = await run(`<?php
function a() {
	unlink( $_POST['file'] );
}`, FILE);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('firm');
    expect(f[0].severity).toBe('high');
    expect(f[0].cwe).toContain('CWE-22');
  });

  it('odczyt przez file_get_contents i readfile', async () => {
    const f = await run(`<?php
function a() {
	echo file_get_contents( $_GET['path'] );
	readfile( $_GET['other'] );
}`, FILE);
    expect(f).toHaveLength(2);
    expect(f.every((x) => x.severity === 'high')).toBe(true);
  });

  it('zapis przez file_put_contents jest krytyczny i ma CWE-73', async () => {
    const f = await run(`<?php
function a() {
	file_put_contents( $_POST['target'], $_POST['data'] );
}`, FILE);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
    expect(f[0].cwe).toContain('CWE-73');
  });

  it('fopen w trybie zapisu liczy się jak zapis', async () => {
    const f = await run(`<?php
function a() {
	$h = fopen( $_GET['p'], 'w' );
}`, FILE);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
  });

  it('zmienna zasilona danymi użytkownika to heurystyka', async () => {
    const f = await run(`<?php
function a() {
	$f = $_REQUEST['f'];
	readfile( $f );
}`, FILE);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
    expect(f[0].severity).toBe('medium');
  });

  it('stały katalog z doklejoną nazwą od użytkownika nadal jest zgłaszany', async () => {
    const f = await run(`<?php
function a() {
	unlink( WP_CONTENT_DIR . '/uploads/' . $_POST['name'] );
}`, FILE);
    expect(f).toHaveLength(1);
  });

  it('metoda $wp_filesystem->delete', async () => {
    const f = await run(`<?php
function a() {
	global $wp_filesystem;
	$wp_filesystem->delete( $_POST['file'] );
}`, FILE);
    expect(f).toHaveLength(1);
  });

  it('copy zgłasza stronę źródłową i docelową jako jedno wywołanie', async () => {
    const f = await run(`<?php
function a() {
	copy( $_POST['src'], $_POST['dst'] );
}`, FILE);
    expect(f).toHaveLength(1);
  });

  it('basename oczyszcza ścieżkę', async () => {
    const f = await run(`<?php
function a() {
	unlink( basename( $_POST['file'] ) );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('adres z ustalonym hostem nie jest odczytem lokalnego pliku', async () => {
    const f = await run(`<?php
function a() {
	return file_get_contents( 'https://api.example.com/v1?q=' . $_GET['q'] );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('validate_file na zmiennej uspokaja', async () => {
    const f = await run(`<?php
function a() {
	$f = $_GET['f'];
	if ( validate_file( $f ) !== 0 ) {
		wp_die( 'x' );
	}
	unlink( $f );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('realpath na zmiennej uspokaja', async () => {
    const f = await run(`<?php
function a() {
	$f = realpath( $_GET['f'] );
	if ( strpos( $f, WP_CONTENT_DIR ) !== 0 ) {
		return;
	}
	unlink( $f );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('szukanie ".." w zmiennej uspokaja', async () => {
    const f = await run(`<?php
function a() {
	$f = $_GET['f'];
	if ( strpos( $f, '..' ) !== false ) {
		return;
	}
	readfile( $f );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('tmp_name z $_FILES jest ścieżką serwera, nie użytkownika', async () => {
    const f = await run(`<?php
function a() {
	$data = file_get_contents( $_FILES['upload']['tmp_name'] );
	unlink( $_FILES['upload']['tmp_name'] );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('stała ścieżka we wtyczce nie jest zgłaszana', async () => {
    const f = await run(`<?php
function a() {
	$path = plugin_dir_path( __FILE__ ) . 'templates/header.php';
	return file_get_contents( $path );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('reguła jest rozszerzona i nie działa bez --extended', async () => {
    const f = await run(`<?php
function a() {
	unlink( $_POST['file'] );
}`, FILE, false);
    expect(f).toHaveLength(0);
  });
});

describe('adres HTTP od użytkownika (wp.http.ssrf)', () => {
  it('wp_remote_get z adresem z superglobala', async () => {
    const f = await run(`<?php
function a() {
	return wp_remote_get( $_GET['url'] );
}`, SSRF);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('firm');
    expect(f[0].severity).toBe('high');
    expect(f[0].cwe).toContain('CWE-918');
  });

  it('adres w zmiennej to heurystyka', async () => {
    const f = await run(`<?php
function a() {
	$u = $_POST['endpoint'];
	return wp_remote_post( $u, array( 'body' => array() ) );
}`, SSRF);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
    expect(f[0].severity).toBe('medium');
  });

  it('curl_setopt z CURLOPT_URL', async () => {
    const f = await run(`<?php
function a() {
	$ch = curl_init();
	curl_setopt( $ch, CURLOPT_URL, $_GET['u'] );
	curl_exec( $ch );
}`, SSRF);
    expect(f).toHaveLength(1);
  });

  it('host zbudowany z danych użytkownika', async () => {
    const f = await run(`<?php
function a() {
	return wp_remote_get( 'http://' . $_GET['host'] . '/api' );
}`, SSRF);
    expect(f).toHaveLength(1);
  });

  it('add_query_arg ocenia adres, a nie klucz', async () => {
    const f = await run(`<?php
function a() {
	return wp_remote_get( add_query_arg( 'x', '1', $_GET['url'] ) );
}`, SSRF);
    expect(f).toHaveLength(1);
  });

  it('dane użytkownika za ustalonym hostem nie zmieniają celu', async () => {
    const f = await run(`<?php
function a() {
	$one = wp_remote_get( 'https://api.example.com/v1?q=' . urlencode( $_GET['q'] ) );
	$two = wp_remote_get( 'https://api.example.com/' . $_GET['path'] );
	$three = wp_remote_get( sprintf( 'https://api.example.com/%s', $_GET['id'] ) );
	return array( $one, $two, $three );
}`, SSRF);
    expect(f).toHaveLength(0);
  });

  it('wp_safe_remote_get odrzuca adresy wewnętrzne, więc nie jest ujściem', async () => {
    const f = await run(`<?php
function a() {
	return wp_safe_remote_get( $_GET['url'] );
}`, SSRF);
    expect(f).toHaveLength(0);
  });

  it('wp_http_validate_url na zmiennej uspokaja', async () => {
    const f = await run(`<?php
function a() {
	$u = $_GET['url'];
	if ( ! wp_http_validate_url( $u ) ) {
		return;
	}
	return wp_remote_get( $u );
}`, SSRF);
    expect(f).toHaveLength(0);
  });

  it('porównanie hosta z wp_parse_url uspokaja', async () => {
    const f = await run(`<?php
function a() {
	$url = esc_url_raw( $_GET['url'] );
	$parts = wp_parse_url( $url );
	if ( 'example.com' !== $parts['host'] ) {
		return;
	}
	return wp_remote_get( $url );
}`, SSRF);
    expect(f).toHaveLength(0);
  });

  it('stały adres witryny nie jest zgłaszany', async () => {
    const f = await run(`<?php
function a() {
	return wp_remote_get( home_url( '/wp-json/x' ) );
}`, SSRF);
    expect(f).toHaveLength(0);
  });
});

describe('wysyłanie pliku bez sprawdzenia typu (wp.upload.unrestricted)', () => {
  it('move_uploaded_file pod nazwą od klienta', async () => {
    const f = await run(`<?php
function a( $dir ) {
	move_uploaded_file( $_FILES['f']['tmp_name'], $dir . '/' . $_FILES['f']['name'] );
}`, UPLOAD);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
    expect(f[0].confidence).toBe('firm');
    expect(f[0].cwe).toContain('CWE-434');
  });

  it('nazwa w zmiennej to heurystyka', async () => {
    const f = await run(`<?php
function a( $dir ) {
	$name = $_FILES['f']['name'];
	move_uploaded_file( $_FILES['f']['tmp_name'], $dir . '/' . $name );
}`, UPLOAD);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
    expect(f[0].severity).toBe('high');
  });

  it('basename i wp_unique_filename zostawiają rozszerzenie, więc nie oczyszczają', async () => {
    const f = await run(`<?php
function a( $dir ) {
	move_uploaded_file( $_FILES['f']['tmp_name'], $dir . '/' . basename( $_FILES['f']['name'] ) );
}`, UPLOAD);
    expect(f).toHaveLength(1);
  });

  it('wp_handle_upload z wyłączonym sprawdzaniem typu', async () => {
    const f = await run(`<?php
function a() {
	return wp_handle_upload( $_FILES['f'], array( 'test_form' => false, 'test_type' => false ) );
}`, UPLOAD);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
  });

  it('wp_handle_upload bez wyłączenia typu jest w porządku', async () => {
    const f = await run(`<?php
function a() {
	return wp_handle_upload( $_FILES['f'], array( 'test_form' => false ) );
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });

  it('wp_check_filetype w tej funkcji uspokaja', async () => {
    const f = await run(`<?php
function a( $dir ) {
	$type = wp_check_filetype( $_FILES['f']['name'] );
	if ( empty( $type['ext'] ) ) {
		return;
	}
	move_uploaded_file( $_FILES['f']['tmp_name'], $dir . '/' . $_FILES['f']['name'] );
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });

  it('odczyt rozszerzenia razem z in_array uspokaja', async () => {
    const f = await run(`<?php
function a( $dir ) {
	$name = $_FILES['f']['name'];
	$ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
	if ( ! in_array( $ext, array( 'jpg', 'png' ), true ) ) {
		return;
	}
	move_uploaded_file( $_FILES['f']['tmp_name'], $dir . '/' . $name );
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });

  it('sanitize_file_name też zostawia rozszerzenie', async () => {
    const f = await run(`<?php
function a( $dir ) {
	$name = sanitize_file_name( $_FILES['f']['name'] );
	move_uploaded_file( $_FILES['f']['tmp_name'], $dir . '/' . $name );
}`, UPLOAD);
    expect(f).toHaveLength(1);
  });

  it('rozszerzenie dopisane na stałe odbiera klientowi wybór typu', async () => {
    const f = await run(`<?php
function a( $dir ) {
	move_uploaded_file( $_FILES['f']['tmp_name'], $dir . '/' . md5( $_FILES['f']['name'] ) . '.jpg' );
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });

  it('stała nazwa docelowa nie jest zgłaszana', async () => {
    const f = await run(`<?php
function a( $dir ) {
	move_uploaded_file( $_FILES['f']['tmp_name'], $dir . '/avatar.bin' );
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });
});

describe('rola, logowanie i uprawnienia sterowane przez żądanie (wp.privilege.escalation)', () => {
  it('rola z żądania w tablicy dla wp_insert_user', async () => {
    const f = await run(`<?php
function a() {
	wp_insert_user( array(
		'user_login' => $_POST['u'],
		'user_pass'  => $_POST['p'],
		'role'       => $_POST['role'],
	) );
}`, PRIV);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
    expect(f[0].confidence).toBe('firm');
    expect(f[0].cwe).toContain('CWE-269');
  });

  it('rola we zmiennej to heurystyka', async () => {
    const f = await run(`<?php
function a() {
	$role = $_POST['role'];
	wp_insert_user( array( 'user_login' => 'x', 'role' => $role ) );
}`, PRIV);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
  });

  it('set_role z wartością z żądania', async () => {
    const f = await run(`<?php
function a( $id ) {
	$user = new WP_User( $id );
	$user->set_role( $_POST['role'] );
}`, PRIV);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
  });

  it('wp_insert_user z całym żądaniem', async () => {
    const f = await run(`<?php
function a() {
	wp_insert_user( $_POST );
}`, PRIV);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
  });

  it('klucz meta użytkownika z żądania', async () => {
    const f = await run(`<?php
function a( $uid ) {
	update_user_meta( $uid, $_POST['key'], $_POST['value'] );
}`, PRIV);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
  });

  it('uprawnienia zapisywane wartością z żądania', async () => {
    const f = await run(`<?php
function a( $uid ) {
	global $wpdb;
	update_user_meta( $uid, $wpdb->prefix . 'capabilities', $_POST['caps'] );
}`, PRIV);
    expect(f).toHaveLength(1);
  });

  it('logowanie jako użytkownik wskazany w żądaniu', async () => {
    const f = await run(`<?php
function a() {
	wp_set_auth_cookie( $_POST['user_id'] );
}`, PRIV);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
  });

  it('rzutowanie na liczbę nie zmienia tego, kto się loguje', async () => {
    const f = await run(`<?php
function a() {
	$id = intval( $_GET['uid'] );
	wp_set_current_user( $id );
}`, PRIV);
    expect(f).toHaveLength(1);
  });

  it('bramka na uprawnienie administratora uspokaja', async () => {
    const f = await run(`<?php
function a( $id ) {
	if ( ! current_user_can( 'promote_users' ) ) {
		return;
	}
	$user = new WP_User( $id );
	$user->set_role( $_POST['role'] );
}`, PRIV);
    expect(f).toHaveLength(0);
  });

  it('stała rola nie jest zgłaszana', async () => {
    const f = await run(`<?php
function a() {
	wp_insert_user( array( 'user_login' => $_POST['u'], 'role' => 'subscriber' ) );
}`, PRIV);
    expect(f).toHaveLength(0);
  });

  it('rola sprawdzona listą dozwolonych wartości', async () => {
    const f = await run(`<?php
function a() {
	$role = $_POST['role'];
	if ( ! in_array( $role, array( 'subscriber', 'customer' ), true ) ) {
		return;
	}
	wp_insert_user( array( 'user_login' => 'x', 'role' => $role ) );
}`, PRIV);
    expect(f).toHaveLength(0);
  });

  it('klucz role w funkcji bez zapisu konta nie jest zgłaszany', async () => {
    const f = await run(`<?php
function a() {
	return get_users( array( 'role' => $_GET['role'] ) );
}`, PRIV);
    expect(f).toHaveLength(0);
  });

  it('stały przedrostek klucza meta ogranicza zakres', async () => {
    const f = await run(`<?php
function a( $uid ) {
	update_user_meta( $uid, 'myplugin_' . $_POST['key'], $_POST['value'] );
}`, PRIV);
    expect(f).toHaveLength(0);
  });

  it('logowanie po sprawdzeniu hasła', async () => {
    const f = await run(`<?php
function a() {
	$user = get_user_by( 'login', $_POST['u'] );
	if ( $user && wp_check_password( $_POST['p'], $user->user_pass, $user->ID ) ) {
		wp_set_auth_cookie( $user->ID );
	}
}`, PRIV);
    expect(f).toHaveLength(0);
  });

  it('logowanie konta utworzonego w tej samej funkcji', async () => {
    const f = await run(`<?php
function a() {
	$id = wp_create_user( 'x', 'y', 'z@example.com' );
	wp_set_auth_cookie( $id );
}`, PRIV);
    expect(f).toHaveLength(0);
  });
});

describe('nazwa opcji od użytkownika (wp.option.arbitrary_update)', () => {
  it('update_option z nazwą i wartością z żądania', async () => {
    const f = await run(`<?php
function a() {
	update_option( $_POST['name'], $_POST['value'] );
}`, OPTION);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
    expect(f[0].confidence).toBe('firm');
    expect(f[0].cwe).toContain('CWE-915');
  });

  it('nazwa we zmiennej to heurystyka', async () => {
    const f = await run(`<?php
function a() {
	$k = $_POST['k'];
	update_option( $k, $_POST['v'] );
}`, OPTION);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
    expect(f[0].severity).toBe('high');
  });

  it('wartość podana na stałe obniża wagę o stopień', async () => {
    const f = await run(`<?php
function a() {
	update_option( $_POST['name'], true );
}`, OPTION);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('firm');
    expect(f[0].severity).toBe('high');
  });

  it('delete_option ma niższą wagę', async () => {
    const f = await run(`<?php
function a() {
	delete_option( $_GET['opt'] );
}`, OPTION);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
  });

  it('dane użytkownika na początku nazwy są zgłaszane mimo stałego sufiksu', async () => {
    const f = await run(`<?php
function a() {
	update_option( $_POST['name'] . '_x', 1 );
}`, OPTION);
    expect(f).toHaveLength(1);
  });

  it('stały przedrostek ogranicza zakres do opcji wtyczki', async () => {
    const f = await run(`<?php
function a() {
	update_option( 'myplugin_' . $_POST['k'], 1 );
}`, OPTION);
    expect(f).toHaveLength(0);
  });

  it('stała nazwa z wartością od użytkownika nie jest zgłaszana', async () => {
    const f = await run(`<?php
function a() {
	update_option( 'myplugin_settings', $_POST['v'] );
}`, OPTION);
    expect(f).toHaveLength(0);
  });

  it('bramka na uprawnienie administratora uspokaja', async () => {
    const f = await run(`<?php
function a() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	update_option( $_POST['name'], 1 );
}`, OPTION);
    expect(f).toHaveLength(0);
  });
});
