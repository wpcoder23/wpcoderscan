// Bramka administratora poza własną funkcją: pomocnik wołany wyłącznie zza bramki, funkcja uprawnień znana tylko
// z nazwy, opakowanie sprawdzenia ze stałym uprawnieniem i przedrostek nazwy opcji. Każdy przypadek ujemny
// ma dodatni odpowiednik, żeby poprawka nie zamieniła się w ślepotę.
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

async function run(code: string, ruleId: string): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-gate-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir, extended: true });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === ruleId);
}

const FILE = 'wp.file.path_traversal';
const OPTION = 'wp.option.arbitrary_update';

// Klasa ze stroną menu za manage_options. Handler strony woła pomocnika, który zawiera ujście.
function adminPage(extra: string, body: string): string {
  return `<?php
class Page {
	function __construct() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
${extra}
	}
	function menu() {
		add_menu_page( 'T', 'T', 'manage_options', 'slug', array( $this, 'render' ) );
	}
${body}
}`;
}

describe('pomocnik wołany wyłącznie zza bramki administratora', () => {
  it('łańcuch prywatnych metod od strony menu obniża wagę ścieżki', async () => {
    const f = await run(
      adminPage(
        '',
        `	function render() { $this->handle(); }
	private function handle() { $this->store(); }
	private function store() { file_put_contents( ABSPATH . $_POST['f'], 'x' ); }`,
      ),
      FILE,
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('low');
  });

  it('opcja zapisywana przez pomocnika zza bramki nie jest zgłaszana', async () => {
    const f = await run(
      adminPage(
        '',
        `	function render() { $this->save(); }
	private function save() { update_option( $_POST['n'], $_POST['v'] ); }`,
      ),
      OPTION,
    );
    expect(f).toHaveLength(0);
  });

  it('ten sam pomocnik wołany także z handlera bez bramki jest zgłaszany', async () => {
    const f = await run(
      adminPage(
        `		add_action( 'wp_ajax_nopriv_x', array( $this, 'open' ) );`,
        `	function render() { $this->store(); }
	function open() { $this->store(); }
	private function store() { file_put_contents( ABSPATH . $_POST['f'], 'x' ); }`,
      ),
      FILE,
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).not.toBe('low');
  });

  it('pomocnik zarejestrowany jako callback hooka ma własne wejście', async () => {
    const f = await run(
      adminPage(
        `		add_action( 'wp_ajax_nopriv_x', array( $this, 'store' ) );`,
        `	function render() { $this->store(); }
	function store() { file_put_contents( ABSPATH . $_POST['f'], 'x' ); }`,
      ),
      FILE,
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).not.toBe('low');
  });

  it('wywołanie na obcym obiekcie to wejście, którego nie widzimy', async () => {
    const f = await run(
      `<?php
class Page {
	function __construct() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
	}
	function menu() {
		add_menu_page( 'T', 'T', 'manage_options', 'slug', array( $this, 'render' ) );
	}
	function render() { $this->store(); }
	function store() { file_put_contents( ABSPATH . $_POST['f'], 'x' ); }
}
function other( $page ) {
	$page->store();
}`,
      FILE,
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).not.toBe('low');
  });

  it('nazwa pomocnika użyta jako indeks tablicy nie jest callbackiem', async () => {
    const f = await run(
      `<?php
class Page {
	function __construct() {
		if ( current_user_can( 'manage_options' ) ) { add_action( 'admin_init', array( $this, 'run' ) ); }
	}
	function run() { if ( ! empty( $_POST['save'] ) ) { $this->save(); } }
	function save() { update_option( $_POST['n'], $_POST['v'] ); }
}`,
      OPTION,
    );
    expect(f).toHaveLength(0);
  });

  it('nazwa pomocnika zapisana jako tekst wywołania zwrotnego blokuje wniosek', async () => {
    const f = await run(
      `<?php
class Page {
	function __construct() {
		if ( current_user_can( 'manage_options' ) ) { add_action( 'admin_init', array( $this, 'run' ) ); }
		add_action( 'wp_ajax_nopriv_save', array( $this, 'save' ) );
	}
	function run() { $this->save(); }
	function save() { update_option( $_POST['n'], $_POST['v'] ); }
}`,
      OPTION,
    );
    expect(f).toHaveLength(1);
  });

  it('pomocnik bez żadnego wywołania w pliku nie jest za bramką', async () => {
    const f = await run(
      adminPage('', `	function render() {}
	function store() { update_option( $_POST['n'], $_POST['v'] ); }`),
      OPTION,
    );
    expect(f).toHaveLength(1);
  });

  it('wywołanie spoza funkcji nie potwierdza bramki', async () => {
    const f = await run(
      `<?php
function store() { update_option( $_POST['n'], $_POST['v'] ); }
store();`,
      OPTION,
    );
    expect(f).toHaveLength(1);
  });

  it('rekurencja nie zapętla analizy', async () => {
    const f = await run(
      adminPage(
        '',
        `	function render() { $this->walk( 3 ); }
	private function walk( $n ) { if ( $n > 0 ) { $this->walk( $n - 1 ); } update_option( $_POST['n'], $_POST['v'] ); }`,
      ),
      OPTION,
    );
    expect(f).toHaveLength(0);
  });
});

describe('hook zarejestrowany tylko dla administratora', () => {
  const hooked = (register: string): string => `<?php
class Page {
	function __construct() {
${register}
	}
	function boot() {
${register}
	}
	function save() { update_option( $_POST['n'], $_POST['v'] ); }
}`;
  const reg = "add_action( 'admin_init', array( $this, 'save' ) );";

  it('rejestracja w if ze sprawdzeniem uprawnienia', async () => {
    expect(await run(hooked(`if ( current_user_can( 'manage_options' ) ) { ${reg} }`), OPTION)).toHaveLength(0);
  });

  it('rejestracja w if z metodą o nazwie sprawdzenia administratora', async () => {
    expect(await run(hooked(`if ( $this->user_can_manage_settings() ) { ${reg} }`), OPTION)).toHaveLength(0);
  });

  it('koniunkcja z is_admin() i sprawdzeniem uprawnienia', async () => {
    const code = hooked(`if ( is_admin() && current_user_can( 'manage_options' ) ) { ${reg} }`);
    expect(await run(code, OPTION)).toHaveLength(0);
  });

  it('wczesne wyjście dla pozostałych przed rejestracją', async () => {
    const code = hooked(`if ( ! current_user_can( 'manage_options' ) ) { return; }\n${reg}`);
    expect(await run(code, OPTION)).toHaveLength(0);
  });

  it('gałąź else po zaprzeczonym sprawdzeniu', async () => {
    const code = hooked(`if ( ! current_user_can( 'manage_options' ) ) { $x = 1; } else { ${reg} }`);
    expect(await run(code, OPTION)).toHaveLength(0);
  });

  it('closure zarejestrowana w if ze sprawdzeniem', async () => {
    const f = await run(
      `<?php
if ( current_user_can( 'manage_options' ) ) {
	add_action( 'admin_init', function () { update_option( $_POST['n'], $_POST['v'] ); } );
}`,
      OPTION,
    );
    expect(f).toHaveLength(0);
  });

  it('samo is_admin() nie jest bramką', async () => {
    expect(await run(hooked(`if ( is_admin() ) { ${reg} }`), OPTION)).toHaveLength(1);
  });

  it('alternatywa ze składnikiem bez sprawdzenia nie jest bramką', async () => {
    const code = hooked(`if ( current_user_can( 'manage_options' ) || $this->debug ) { ${reg} }`);
    expect(await run(code, OPTION)).toHaveLength(1);
  });

  it('rejestracja w gałęzi else zwykłego sprawdzenia jest otwarta', async () => {
    const code = hooked(`if ( current_user_can( 'manage_options' ) ) { $x = 1; } else { ${reg} }`);
    expect(await run(code, OPTION)).toHaveLength(1);
  });

  it('wyjście dla administratora nie jest bramką dla administratora', async () => {
    const code = hooked(`if ( current_user_can( 'manage_options' ) ) { return; }\n${reg}`);
    expect(await run(code, OPTION)).toHaveLength(1);
  });

  it('uprawnienie zwykłego użytkownika nie jest bramką', async () => {
    expect(await run(hooked(`if ( current_user_can( 'edit_posts' ) ) { ${reg} }`), OPTION)).toHaveLength(1);
  });

  it('ta sama funkcja zarejestrowana także poza bramką jest otwarta', async () => {
    const code = `<?php
class Page {
	function __construct() {
		if ( current_user_can( 'manage_options' ) ) { add_action( 'admin_init', array( $this, 'save' ) ); }
		add_action( 'wp_ajax_nopriv_save', array( $this, 'save' ) );
	}
	function save() { update_option( $_POST['n'], $_POST['v'] ); }
}`;
    expect(await run(code, OPTION)).toHaveLength(1);
  });

  it('wczesne wyjście w gałęzi warunkowej nie obejmuje rejestracji poza nią', async () => {
    const code = hooked(`if ( $this->flag ) { if ( ! current_user_can( 'manage_options' ) ) { return; } }\n${reg}`);
    expect(await run(code, OPTION)).toHaveLength(1);
  });

  it('ścieżka pliku w funkcji zarejestrowanej za bramką ma niską wagę', async () => {
    const f = await run(
      `<?php
class Page {
	function __construct() {
		if ( current_user_can( 'manage_options' ) ) { add_action( 'admin_init', array( $this, 'save' ) ); }
	}
	function save() { file_put_contents( ABSPATH . $_POST['f'], 'x' ); }
}`,
      FILE,
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('low');
  });
});

describe('funkcja uprawnień znana tylko z nazwy', () => {
  const route = (permission: string): string => `<?php
add_action( 'rest_api_init', function () {
	register_rest_route( 'x/v1', '/opt', array(
		'methods' => 'POST',
		'callback' => 'save_opt',
		'permission_callback' => ${permission},
	) );
} );
function save_opt( $request ) {
	update_option( $request->get_param( 'name' ), $request->get_param( 'value' ) );
}`;

  it('nazwa z przedrostkiem wtyczki i check_admin na końcu', async () => {
    expect(await run(route("'jkit_permission_check_admin'"), OPTION)).toHaveLength(0);
  });

  it('metoda checkAdmin zapisana camelCase w tablicy', async () => {
    expect(await run(route("array( 'Auth', 'checkAdmin' )"), OPTION)).toHaveLength(0);
  });

  it('nazwa bez słowa o administratorze nie jest bramką', async () => {
    expect(await run(route("'plugin_check_access'"), OPTION)).toHaveLength(1);
  });

  it('nazwa z check_admin_notices nie jest bramką', async () => {
    expect(await run(route("'check_admin_notices'"), OPTION)).toHaveLength(1);
  });

  it('__return_true nadal nie jest bramką', async () => {
    expect(await run(route("'__return_true'"), OPTION)).toHaveLength(1);
  });
});

describe('sprawdzenie uprawnienia przez własną funkcję', () => {
  it('opakowanie ze stałym manage_options', async () => {
    const f = await run(
      `<?php
class A {
	function save() {
		$this->check_permission( 'manage_options' );
		update_option( $_POST['n'], $_POST['v'] );
	}
}`,
      OPTION,
    );
    expect(f).toHaveLength(0);
  });

  it('opakowanie ze zwykłym uprawnieniem niczego nie uspokaja', async () => {
    const f = await run(
      `<?php
class A {
	function save() {
		$this->check_permission( 'edit_posts' );
		update_option( $_POST['n'], $_POST['v'] );
	}
}`,
      OPTION,
    );
    expect(f).toHaveLength(1);
  });

  it('add_cap( manage_options ) nadaje uprawnienie, a nie sprawdza', async () => {
    const f = await run(
      `<?php
function a() {
	$role = get_role( 'subscriber' );
	$role->add_cap( 'manage_options' );
	update_option( $_POST['n'], $_POST['v'] );
}`,
      OPTION,
    );
    expect(f).toHaveLength(1);
  });

  it('check_admin_referer sprawdza nonce, a nie uprawnienie', async () => {
    const f = await run(
      `<?php
function a() {
	check_admin_referer( 'x' );
	update_option( $_POST['n'], $_POST['v'] );
}`,
      OPTION,
    );
    expect(f).toHaveLength(1);
  });

  it('metoda o nazwie z nonce nie jest bramką', async () => {
    const f = await run(
      `<?php
class A {
	function save() {
		$this->verify_admin_nonce();
		update_option( $_POST['n'], $_POST['v'] );
	}
}`,
      OPTION,
    );
    expect(f).toHaveLength(1);
  });
});

describe('przedrostek w nazwie opcji', () => {
  it('strpos !== 0 z wyjątkiem przed zapisem', async () => {
    const f = await run(
      `<?php
function a( $request ) {
	foreach ( $request->get_params() as $key => $values ) {
		if ( strpos( $key, 'myplugin_' ) !== 0 ) {
			throw new Exception( 'no' );
		}
		update_option( $key, $values );
	}
}`,
      OPTION,
    );
    expect(f).toHaveLength(0);
  });

  it('bez sprawdzenia przedrostka ta sama pętla jest zgłaszana', async () => {
    const f = await run(
      `<?php
function a( $request ) {
	foreach ( $request->get_params() as $key => $values ) {
		update_option( $key, $values );
	}
}`,
      OPTION,
    );
    expect(f).toHaveLength(1);
  });

  it('str_starts_with w warunku zapisu', async () => {
    const f = await run(
      `<?php
function a() {
	$name = $_POST['n'];
	if ( str_starts_with( $name, 'myplugin_' ) ) {
		update_option( $name, 1 );
	}
}`,
      OPTION,
    );
    expect(f).toHaveLength(0);
  });

  it('negacja str_starts_with z wyjściem', async () => {
    const f = await run(
      `<?php
function a() {
	$name = $_POST['n'];
	if ( ! str_starts_with( $name, 'myplugin_' ) ) {
		return;
	}
	update_option( $name, 1 );
}`,
      OPTION,
    );
    expect(f).toHaveLength(0);
  });

  it('luźne porównanie strpos != 0 nie jest sprawdzeniem, bo false == 0', async () => {
    const f = await run(
      `<?php
function a() {
	$name = $_POST['n'];
	if ( strpos( $name, 'myplugin_' ) != 0 ) {
		return;
	}
	update_option( $name, 1 );
}`,
      OPTION,
    );
    expect(f).toHaveLength(1);
  });

  it('przedrostek krótszy niż cztery znaki nie zawęża', async () => {
    const f = await run(
      `<?php
function a() {
	$name = $_POST['n'];
	if ( strpos( $name, 'wp_' ) !== 0 ) {
		return;
	}
	update_option( $name, 1 );
}`,
      OPTION,
    );
    expect(f).toHaveLength(1);
  });

  it('przedrostek nie czyści ścieżki pliku', async () => {
    const f = await run(
      `<?php
function a() {
	$file = $_GET['f'];
	if ( strpos( $file, 'uploads/' ) !== 0 ) {
		return;
	}
	unlink( ABSPATH . $file );
}`,
      FILE,
    );
    expect(f).toHaveLength(1);
  });
});
