// Precyzja reguł ujść: rozwijanie zmiennych, bramki administratora, sprawdzenia nazwane po funkcji,
// klucze tablic o literalnych kluczach i wpisy $_FILES. Każdy przypadek ujemny ma dodatni odpowiednik,
// żeby poprawka nie zamieniła się w ślepotę.
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
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-prec-'));
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

describe('host i przedrostek ustalone w zmiennej', () => {
  it('adres ze stałym hostem zbudowany w zmiennej nie jest SSRF', async () => {
    const f = await run(`<?php
function a() {
	$url = 'https://api.example.com/v1/' . $_GET['q'];
	wp_remote_get( $url );
}`, SSRF);
    expect(f).toHaveLength(0);
  });

  it('host z danych użytkownika zbudowany w zmiennej nadal jest SSRF', async () => {
    const f = await run(`<?php
function a() {
	$url = 'https://' . $_GET['h'] . '/v1/';
	wp_remote_get( $url );
}`, SSRF);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
  });

  it('alias zmiennej z ustalonym hostem', async () => {
    const f = await run(`<?php
function a() {
	$base = 'https://api.example.com/';
	$url = $base . $_GET['p'];
	wp_remote_get( $url );
}`, SSRF);
    expect(f).toHaveLength(0);
  });

  it('doklejanie .= do ustalonego hosta', async () => {
    const f = await run(`<?php
function a() {
	$url = 'https://api.example.com/';
	$url .= $_GET['p'];
	wp_remote_get( $url );
}`, SSRF);
    expect(f).toHaveLength(0);
  });

  it('host bez ukośnika po nazwie domeny nie jest ustalony', async () => {
    const f = await run(`<?php
function a() {
	$url = 'https://api.example.com' . $_GET['p'];
	wp_remote_get( $url );
}`, SSRF);
    expect(f).toHaveLength(1);
  });

  it('sprintf z hostem w formacie', async () => {
    const fixed = await run(`<?php
function a() {
	$url = sprintf( 'https://api.example.com/%s/list', $_GET['p'] );
	wp_remote_get( $url );
}`, SSRF);
    expect(fixed).toHaveLength(0);
    const open = await run(`<?php
function a() {
	$url = sprintf( 'https://%s/list', $_GET['h'] );
	wp_remote_get( $url );
}`, SSRF);
    expect(open).toHaveLength(1);
  });

  it('zmienna nadpisana w pętli nie jest rozwijana', async () => {
    const f = await run(`<?php
function a() {
	$url = 'https://api.example.com/';
	foreach ( $_POST['urls'] as $url ) {
		wp_remote_get( $url );
	}
}`, SSRF);
    expect(f).toHaveLength(1);
  });

  it('przedrostek opcji ustalony w zmiennej', async () => {
    const fixed = await run(`<?php
function a() {
	$prefix = 'myplugin_';
	update_option( $prefix . $_POST['k'], $_POST['v'] );
}`, OPTION);
    expect(fixed).toHaveLength(0);
    const open = await run(`<?php
function a() {
	$prefix = $_POST['p'];
	update_option( $prefix . '_x', $_POST['v'] );
}`, OPTION);
    expect(open).toHaveLength(1);
  });
});

describe('dane tylko w nazwie pliku', () => {
  it('fragment nazwy przed danymi nie pozwala wyjść z katalogu', async () => {
    const f = await run(`<?php
function a( $dir ) {
	unlink( $dir . '/img-' . $_POST['id'] );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('dane tuż za separatorem katalogu nadal są zgłaszane', async () => {
    const f = await run(`<?php
function a( $dir ) {
	unlink( $dir . '/' . $_POST['id'] );
}`, FILE);
    expect(f).toHaveLength(1);
  });

  it('dane za fragmentem nazwy w zmiennej', async () => {
    const f = await run(`<?php
function a( $dir ) {
	$name = 'cache-' . $_POST['id'];
	unlink( $dir . $name );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('dwie części danych, jedna za katalogiem, nadal są zgłaszane', async () => {
    const f = await run(`<?php
function a( $dir ) {
	unlink( $dir . $_POST['sub'] . '/x-' . $_POST['id'] );
}`, FILE);
    expect(f).toHaveLength(1);
  });
});

describe('niegroźne rozszerzenie dopisane na stałe', () => {
  it('odczyt i usunięcie pliku .jpg nie są zgłaszane', async () => {
    const f = await run(`<?php
function a( $dir ) {
	unlink( $dir . $_POST['f'] . '.jpg' );
	echo file_get_contents( $dir . $_GET['g'] . '.png' );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('zapis pliku .txt jest zgłaszany jako słaba wskazówka', async () => {
    const f = await run(`<?php
function a( $dir ) {
	file_put_contents( $dir . $_POST['f'] . '.txt', 'x' );
}`, FILE);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('low');
    expect(f[0].confidence).toBe('heuristic');
  });

  it('rozszerzenie .php nie jest niegroźne', async () => {
    const f = await run(`<?php
function a( $dir ) {
	unlink( $dir . $_POST['f'] . '.php' );
}`, FILE);
    expect(f).toHaveLength(1);
  });

  it('rozszerzenie dopisane w zmiennej', async () => {
    const f = await run(`<?php
function a( $dir ) {
	$path = $dir . $_POST['f'] . '.pdf';
	unlink( $path );
}`, FILE);
    expect(f).toHaveLength(0);
  });
});

describe('rmdir i sprawdzenia separatora', () => {
  it('rmdir usuwa tylko pusty katalog i nie jest ujściem', async () => {
    const f = await run(`<?php
function a() {
	rmdir( $_POST['d'] );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('strpos na separator uspokaja', async () => {
    const f = await run(`<?php
function a( $dir ) {
	$f = $_POST['f'];
	if ( strpos( $f, '/' ) !== false ) {
		return;
	}
	unlink( $dir . $f );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('wynik str_replace na ".." przypisany do nowej zmiennej uspokaja', async () => {
    const f = await run(`<?php
function a( $dir ) {
	$f = str_replace( '../', '', $_POST['f'] );
	unlink( $dir . $f );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('preg_replace z klasą bez ukośnika oczyszcza nazwę', async () => {
    const clean = await run(`<?php
function a( $dir ) {
	$f = preg_replace( '/[^a-z0-9_-]/i', '', $_POST['f'] );
	unlink( $dir . $f );
}`, FILE);
    expect(clean).toHaveLength(0);
    const slash = await run(`<?php
function a( $dir ) {
	$f = preg_replace( '/[^a-z0-9\\/_-]/i', '', $_POST['f'] );
	unlink( $dir . $f );
}`, FILE);
    expect(slash).toHaveLength(1);
  });
});

describe('klucze tablic o literalnych kluczach i wpisy $_FILES', () => {
  it('foreach po tablicy o literalnych kluczach nie skaża zmiennej klucza', async () => {
    const f = await run(`<?php
function a( $dir ) {
	$files = array( 'a.txt' => $_POST['x'], 'b.txt' => $_POST['y'] );
	foreach ( $files as $name => $content ) {
		file_put_contents( $dir . '/' . $name, $content );
	}
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('foreach po danych z żądania skaża klucz', async () => {
    const f = await run(`<?php
function a( $dir ) {
	foreach ( $_POST['files'] as $name => $content ) {
		file_put_contents( $dir . '/' . $name, $content );
	}
}`, FILE);
    expect(f).toHaveLength(1);
  });

  it('tmp_name we wpisie pliku w zmiennej to ścieżka serwera', async () => {
    const f = await run(`<?php
function a() {
	$upload = $_FILES['f'];
	echo file_get_contents( $upload['tmp_name'] );
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('nazwa pliku z komputera użytkownika we wpisie pozostaje skażona', async () => {
    const f = await run(`<?php
function a() {
	$upload = $_FILES['f'];
	echo file_get_contents( $upload['name'] );
}`, FILE);
    expect(f).toHaveLength(1);
  });

  it('tmp_name w tablicy z żądania nie jest ścieżką serwera', async () => {
    const f = await run(`<?php
function a() {
	echo file_get_contents( $_POST['tmp_name'] );
}`, FILE);
    expect(f).toHaveLength(1);
  });
});

describe('bramka administratora obniża wagę zamiast usuwać wynik', () => {
  it('ścieżka za current_user_can( manage_options )', async () => {
    const f = await run(`<?php
function a() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	unlink( $_POST['f'] );
}`, FILE);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('low');
    expect(f[0].confidence).toBe('heuristic');
  });

  it('adres za sprawdzeniem roli administratora', async () => {
    const f = await run(`<?php
function a() {
	$user = wp_get_current_user();
	if ( ! in_array( 'administrator', (array) $user->roles, true ) ) {
		return;
	}
	wp_remote_get( $_POST['u'] );
}`, SSRF);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('low');
  });

  it('bramka w funkcji wywołującej obniża wagę parametru', async () => {
    const f = await run(`<?php
function helper( $p ) {
	unlink( $p );
}
function a() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	helper( $_POST['p'] );
}`, FILE);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('low');
  });

  it('upload za bramką administratora', async () => {
    const f = await run(`<?php
function a() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	move_uploaded_file( $_FILES['f']['tmp_name'], '/var/www/' . $_FILES['f']['name'] );
}`, UPLOAD);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('low');
  });

  it('opcja za bramką administratora w funkcji wywołującej jest pomijana', async () => {
    const f = await run(`<?php
function save( $name ) {
	update_option( $name, $_POST['v'] );
}
function a() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	save( $_POST['n'] );
}`, OPTION);
    expect(f).toHaveLength(0);
  });

  it('metoda sprawdzająca administratora po nazwie', async () => {
    const f = await run(`<?php
class A {
	function save() {
		if ( ! $this->userIsAdmin() ) {
			return;
		}
		update_option( $_POST['n'], $_POST['v'] );
	}
}`, OPTION);
    expect(f).toHaveLength(0);
  });

  it('has_cap z uprawnieniem administratora', async () => {
    const f = await run(`<?php
function a() {
	$u = wp_get_current_user();
	if ( ! $u->has_cap( 'manage_options' ) ) {
		return;
	}
	update_option( $_POST['n'], $_POST['v'] );
}`, OPTION);
    expect(f).toHaveLength(0);
  });

  it('uprawnienie zwykłego użytkownika niczego nie uspokaja', async () => {
    const f = await run(`<?php
function a() {
	if ( ! current_user_can( 'edit_posts' ) ) {
		return;
	}
	update_option( $_POST['n'], $_POST['v'] );
}`, OPTION);
    expect(f).toHaveLength(1);
  });
});

describe('dane z wywołania w tym samym pliku to słabszy dowód', () => {
  it('parametr zasilony przez wywołanie jest o stopień niżej', async () => {
    const f = await run(`<?php
function helper( $p ) {
	file_put_contents( $p, 'x' );
}
function a() {
	helper( $_POST['p'] );
}`, FILE);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('heuristic');
    expect(f[0].severity).toBe('medium');
  });
});

describe('logowanie: tożsamość potwierdzona po nazwie albo w wywołującym', () => {
  it('metoda verifyToken przed logowaniem', async () => {
    const f = await run(`<?php
class A {
	function login() {
		$id = (int) $_POST['id'];
		if ( ! $this->verifyToken( $_POST['t'] ) ) {
			return;
		}
		wp_set_auth_cookie( $id );
	}
}`, PRIV);
    expect(f).toHaveLength(0);
  });

  it('samo wp_set_auth_cookie nie jest sprawdzeniem tożsamości', async () => {
    const f = await run(`<?php
function login() {
	wp_set_auth_cookie( (int) $_POST['id'] );
}`, PRIV);
    expect(f).toHaveLength(1);
  });

  it('nonce nie potwierdza tożsamości', async () => {
    const f = await run(`<?php
function login() {
	check_ajax_referer( 'x' );
	wp_verify_nonce( $_POST['n'], 'y' );
	wp_set_auth_cookie( (int) $_POST['id'] );
}`, PRIV);
    expect(f).toHaveLength(1);
  });

  it('sprawdzenie hasła w funkcji, która woła logowanie', async () => {
    const f = await run(`<?php
function do_login( $id ) {
	wp_set_auth_cookie( $id );
}
function handle() {
	if ( ! wp_check_password( $_POST['p'], $hash ) ) {
		return;
	}
	do_login( $_POST['id'] );
}`, PRIV);
    expect(f).toHaveLength(0);
  });

  it('pasek logowania dla developera za kontrolą środowiska', async () => {
    const f = await run(`<?php
function dev_login() {
	if ( wp_get_environment_type() !== 'local' ) {
		return;
	}
	wp_set_auth_cookie( (int) $_POST['user'] );
}`, PRIV);
    expect(f).toHaveLength(0);
  });

  it('rola z żądania za bramką administratora w funkcji wywołującej', async () => {
    const f = await run(`<?php
function create( $role ) {
	wp_insert_user( array( 'user_login' => 'x', 'role' => $role ) );
}
function a() {
	if ( ! current_user_can( 'promote_users' ) ) {
		return;
	}
	create( $_POST['role'] );
}`, PRIV);
    expect(f).toHaveLength(0);
  });
});

describe('wysyłanie pliku: rozszerzenie i walidacja po nazwie', () => {
  it('rozszerzenie .jpg dopisane w zmiennej odbiera wybór typu', async () => {
    const f = await run(`<?php
function a() {
	$target = '/var/www/up/' . $_FILES['f']['name'] . '.jpg';
	move_uploaded_file( $_FILES['f']['tmp_name'], $target );
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });

  it('stałe rozszerzenie .php nie chroni, bo treść wybiera klient', async () => {
    const f = await run(`<?php
function a() {
	move_uploaded_file( $_FILES['f']['tmp_name'], '/var/www/up/' . $_POST['n'] . '.php' );
}`, UPLOAD);
    expect(f).toHaveLength(1);
  });

  it('własna funkcja walidująca typ pliku', async () => {
    const f = await run(`<?php
class A {
	function save() {
		if ( ! $this->isAllowedFileType( $_FILES['f'] ) ) {
			return;
		}
		move_uploaded_file( $_FILES['f']['tmp_name'], '/var/www/up/' . $_FILES['f']['name'] );
	}
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });

  it('porównanie pola type z listą dozwolonych', async () => {
    const f = await run(`<?php
function a() {
	if ( ! in_array( $_FILES['f']['type'], array( 'image/png' ), true ) ) {
		return;
	}
	move_uploaded_file( $_FILES['f']['tmp_name'], '/var/www/up/' . $_FILES['f']['name'] );
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });

  it('wp_handle_upload z plikiem z żądania to wykrycie pewne', async () => {
    const f = await run(`<?php
function a() {
	wp_handle_upload( $_FILES['f'], array( 'test_form' => false, 'test_type' => false ) );
}`, UPLOAD);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].confidence).toBe('firm');
  });

  it('wp_handle_sideload na pliku o nieznanym pochodzeniu to słaba wskazówka', async () => {
    const f = await run(`<?php
function a( $file ) {
	wp_handle_sideload( $file, array( 'test_form' => false, 'test_type' => false ) );
}`, UPLOAD);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('low');
    expect(f[0].confidence).toBe('heuristic');
  });

  it('wp_handle_upload na pliku o nieznanym pochodzeniu jest średni', async () => {
    const f = await run(`<?php
function a( $file ) {
	wp_handle_upload( $file, array( 'test_form' => false, 'test_type' => false ) );
}`, UPLOAD);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('medium');
    expect(f[0].confidence).toBe('heuristic');
  });

  it('wp_check_filetype po zapisie służy do odczytu typu, a nie do jego egzekwowania', async () => {
    const f = await run(`<?php
function a( array $file ) {
	$r = wp_handle_upload( $file, array( 'test_form' => false, 'test_type' => false ) );
	$type = wp_check_filetype( $r['file'] );
}`, UPLOAD);
    expect(f).toHaveLength(1);
  });

  it('wp_check_filetype przed zapisem to sprawdzenie', async () => {
    const f = await run(`<?php
function a( array $file ) {
	$t = wp_check_filetype( $file['name'] );
	if ( ! $t['type'] ) {
		return;
	}
	wp_handle_upload( $file, array( 'test_form' => false, 'test_type' => false ) );
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });

  it('sprawdzenie po zapisie liczy się, gdy funkcja usuwa odrzucony plik', async () => {
    const f = await run(`<?php
function a() {
	$target = '/var/www/up/' . $_FILES['f']['name'];
	move_uploaded_file( $_FILES['f']['tmp_name'], $target );
	$t = wp_check_filetype( $target );
	if ( ! $t['type'] ) {
		unlink( $target );
	}
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });

  it('funkcja pytająca o uprawnienia (is_allowed) nie sprawdza typu pliku', async () => {
    const f = await run(`<?php
function a() {
	if ( ! et_pb_is_allowed( 'theme_builder' ) ) {
		return;
	}
	wp_handle_upload( $_FILES['f'], array( 'test_form' => false, 'test_type' => false ) );
}`, UPLOAD);
    expect(f).toHaveLength(1);
  });

  it('funkcja o nazwie is_allowed_file_type to sprawdzenie typu', async () => {
    const f = await run(`<?php
function a() {
	if ( ! is_allowed_file_type( $_FILES['f'] ) ) {
		return;
	}
	wp_handle_upload( $_FILES['f'], array( 'test_form' => false, 'test_type' => false ) );
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });

  it('sprawdzenie końcówki nazwy przez ends_with( $nazwa, ".json" )', async () => {
    const f = await run(`<?php
function a() {
	if ( ! str_ends_with( sanitize_file_name( $_FILES['f']['name'] ), '.json' ) ) {
		return;
	}
	wp_handle_upload( $_FILES['f'], array( 'test_form' => false, 'test_type' => false ) );
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });

  it('sprawdzenie końcówki nazwy metodą endsWith', async () => {
    const f = await run(`<?php
class A {
	function save() {
		if ( ! $this->str->endsWith( $_FILES['f']['name'], '.csv' ) ) {
			return;
		}
		wp_handle_upload( $_FILES['f'], array( 'test_form' => false, 'test_type' => false ) );
	}
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });

  it('wzorzec preg_match kończący się rozszerzeniem', async () => {
    const f = await run(`<?php
function a() {
	if ( ! preg_match( '/\\.(jpe?g|png)$/i', $_FILES['f']['name'] ) ) {
		return;
	}
	move_uploaded_file( $_FILES['f']['tmp_name'], '/var/www/up/' . $_FILES['f']['name'] );
}`, UPLOAD);
    expect(f).toHaveLength(0);
  });

  it('ends_with z dowolnym drugim argumentem nie jest sprawdzeniem rozszerzenia', async () => {
    const f = await run(`<?php
function a( $suffix ) {
	if ( ! str_ends_with( $_FILES['f']['name'], $suffix ) ) {
		return;
	}
	wp_handle_upload( $_FILES['f'], array( 'test_form' => false, 'test_type' => false ) );
}`, UPLOAD);
    expect(f).toHaveLength(1);
  });
});

describe('nazwa opcji: stały koniec i uprawnienie podane zmienną', () => {
  it('stały koniec nazwy obniża wynik do słabej wskazówki', async () => {
    const f = await run(`<?php
function a() {
	update_option( $_POST['addon'] . '_notice_ignore', $_POST['v'] );
}`, OPTION);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('low');
    expect(f[0].confidence).toBe('heuristic');
  });

  it('koniec user_roles nie obniża wyniku, bo prefiks tabeli jest znany', async () => {
    const f = await run(`<?php
function a() {
	update_option( $_POST['x'] . '_user_roles', $_POST['v'] );
}`, OPTION);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
  });

  it('krótki koniec nazwy nie obniża wyniku', async () => {
    const f = await run(`<?php
function a() {
	update_option( $_POST['x'] . '_a', $_POST['v'] );
}`, OPTION);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
  });

  it('uprawnienie administratora podane zmienną z apply_filters', async () => {
    const f = await run(`<?php
function a() {
	$cap = apply_filters( 'toolkit_cap', 'manage_options' );
	if ( ! current_user_can( $cap ) ) {
		return;
	}
	update_option( $_POST['k'], $_POST['v'] );
}`, OPTION);
    expect(f).toHaveLength(0);
  });

  it('uprawnienie podane zmienną z literału', async () => {
    const f = await run(`<?php
function a() {
	$cap = 'manage_options';
	if ( ! current_user_can( $cap ) ) {
		return;
	}
	update_option( $_POST['k'], $_POST['v'] );
}`, OPTION);
    expect(f).toHaveLength(0);
  });

  it('uprawnienie ze zmiennej o nieznanej wartości niczego nie potwierdza', async () => {
    const f = await run(`<?php
function a() {
	$cap = get_option( 'cap' );
	if ( ! current_user_can( $cap ) ) {
		return;
	}
	update_option( $_POST['k'], $_POST['v'] );
}`, OPTION);
    expect(f).toHaveLength(1);
  });

  it('zmienna z uprawnieniem przypisana także niskim uprawnieniem nie wystarcza', async () => {
    const f = await run(`<?php
function a( $mode ) {
	$cap = 'manage_options';
	if ( $mode ) {
		$cap = 'read';
	}
	if ( ! current_user_can( $cap ) ) {
		return;
	}
	update_option( $_POST['k'], $_POST['v'] );
}`, OPTION);
    expect(f).toHaveLength(1);
  });
});

describe('bramka z rejestracji: strona menu i trasa REST', () => {
  it('callback trasy REST z permission_callback wymagającym manage_options', async () => {
    const f = await run(`<?php
add_action( 'rest_api_init', function () {
	register_rest_route( 'x/v1', '/set', array(
		'methods' => 'POST',
		'permission_callback' => function () {
			return current_user_can( 'manage_options' );
		},
		'callback' => function ( $request ) {
			update_option( $request->get_param( 'key' ), $request->get_param( 'value' ) );
		},
	) );
} );`, OPTION);
    expect(f).toHaveLength(0);
  });

  it('ta sama trasa z permission_callback __return_true jest zgłaszana', async () => {
    const f = await run(`<?php
add_action( 'rest_api_init', function () {
	register_rest_route( 'x/v1', '/set', array(
		'methods' => 'POST',
		'permission_callback' => '__return_true',
		'callback' => function ( $request ) {
			update_option( $request->get_param( 'key' ), $request->get_param( 'value' ) );
		},
	) );
} );`, OPTION);
    expect(f).toHaveLength(1);
  });

  it('permission_callback z uprawnieniem edit_posts nie jest bramką administratora', async () => {
    const f = await run(`<?php
add_action( 'rest_api_init', function () {
	register_rest_route( 'x/v1', '/set', array(
		'methods' => 'POST',
		'permission_callback' => function () {
			return current_user_can( 'edit_posts' );
		},
		'callback' => function ( $request ) {
			update_option( $request->get_param( 'key' ), $request->get_param( 'value' ) );
		},
	) );
} );`, OPTION);
    expect(f).toHaveLength(1);
  });

  it('callback i permission_callback jako metody klasy', async () => {
    const f = await run(`<?php
class Api {
	function __construct() {
		add_action( 'rest_api_init', array( $this, 'routes' ) );
	}
	function routes() {
		register_rest_route( 'x/v1', '/set', array(
			'methods' => 'POST',
			'callback' => array( $this, 'save' ),
			'permission_callback' => array( $this, 'can_manage' ),
		) );
	}
	function can_manage() {
		return current_user_can( 'manage_options' );
	}
	function save( $request ) {
		update_option( $request->get_param( 'key' ), $request->get_param( 'value' ) );
	}
}`, OPTION);
    expect(f).toHaveLength(0);
  });

  it('lista tras w jednym wywołaniu register_rest_route', async () => {
    const f = await run(`<?php
add_action( 'rest_api_init', function () {
	register_rest_route( 'x/v1', '/set', array(
		array(
			'methods' => 'POST',
			'permission_callback' => function () {
				return current_user_can( 'manage_options' );
			},
			'callback' => function ( $request ) {
				update_option( $request->get_param( 'key' ), $request->get_param( 'value' ) );
			},
		),
	) );
} );`, OPTION);
    expect(f).toHaveLength(0);
  });

  it('strona menu z uprawnieniem manage_options', async () => {
    const f = await run(`<?php
class Page {
	function __construct() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
	}
	function menu() {
		add_menu_page( 'T', 'T', 'manage_options', 'slug', array( $this, 'render' ) );
	}
	function render() {
		if ( isset( $_POST['f'] ) ) {
			update_option( $_POST['f'], $_POST['v'] );
		}
	}
}`, OPTION);
    expect(f).toHaveLength(0);
  });

  it('strona menu z niskim uprawnieniem jest zgłaszana', async () => {
    const f = await run(`<?php
class Page {
	function __construct() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
	}
	function menu() {
		add_menu_page( 'T', 'T', 'read', 'slug', array( $this, 'render' ) );
	}
	function render() {
		if ( isset( $_POST['f'] ) ) {
			update_option( $_POST['f'], $_POST['v'] );
		}
	}
}`, OPTION);
    expect(f).toHaveLength(1);
  });

  it('podstrona z uprawnieniem na czwartym miejscu i funkcją strony jako nazwą', async () => {
    const f = await run(`<?php
add_action( 'admin_menu', function () {
	add_submenu_page( 'tools.php', 'T', 'T', 'manage_options', 'slug', 'render_page' );
} );
function render_page() {
	unlink( ABSPATH . $_POST['f'] );
}`, FILE);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('low');
  });
});

describe('sprawdzenie członkostwa przez empty( $lista[ $klucz ] )', () => {
  it('! empty( $lista[ $klucz ] ) zdejmuje skażenie klucza w gałęzi', async () => {
    const f = await run(`<?php
function a( $dir ) {
	$allowed = array( 'a' => 'a.txt', 'b' => 'b.txt' );
	$k = $_GET['k'];
	if ( ! empty( $allowed[ $k ] ) ) {
		unlink( $dir . '/' . $k );
	}
}`, FILE);
    expect(f).toHaveLength(0);
  });

  it('bez sprawdzenia ten sam kod jest zgłaszany', async () => {
    const f = await run(`<?php
function a( $dir ) {
	$k = $_GET['k'];
	unlink( $dir . '/' . $k );
}`, FILE);
    expect(f).toHaveLength(1);
  });
});
