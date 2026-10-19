// Reguła wp.auth.unprotected_action: callbacki z przestrzenią nazw, funkcje i metody wołane z uchwytu,
// zmiana stanu w pomocniku, uchwyty zamykające powiadomienia i nazwy, które tylko brzmią jak sprawdzenie uprawnień.
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

async function auth(code: string): Promise<Finding[]> {
  const dir = mkdtempSync(join(tmpdir(), 'wpcs-reach-'));
  dirs.push(dir);
  writeFileSync(join(dir, 'sample.php'), code, 'utf8');
  const result = await scan(dir, { cwd: dir });
  expect(result.errors).toHaveLength(0);
  return result.findings.filter((f) => f.ruleId === 'wp.auth.unprotected_action');
}

describe('callback z przestrzenią nazw', () => {
  it('tekst \\Ns\\Klasa::metoda jest rozwiązywany po krótkiej nazwie klasy', async () => {
    const f = await auth(`<?php
namespace Acme\\Admin;
class Ajax {
	public function save() { update_option( 'acme', $_POST['v'] ); }
}
add_action( 'wp_ajax_acme_save', '\\\\Acme\\\\Admin\\\\Ajax::save' );`);
    expect(f).toHaveLength(2);
  });

  it('tablica [ \\Ns\\Klasa::class, metoda ] też', async () => {
    const f = await auth(`<?php
namespace Acme\\Admin;
class Ajax {
	public function save() { delete_option( 'acme' ); }
}
add_action( 'wp_ajax_acme_save', [ \\Acme\\Admin\\Ajax::class, 'save' ] );`);
    expect(f).toHaveLength(2);
  });
});

describe('zmiany konta użytkownika', () => {
  it('add_role i add_cap na obiekcie użytkownika zmieniają stan', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_grant', 'grant_role' );
function grant_role() {
	$user = get_user_by( 'id', (int) $_POST['id'] );
	$user->add_role( 'administrator' );
	$user->add_cap( 'manage_options' );
}`);
    expect(f).toHaveLength(2);
  });
});

describe('funkcje i metody wołane z uchwytu', () => {
  it('uchwyt, który tylko woła metodę zmieniającą bazę, jest zgłaszany', async () => {
    const f = await auth(`<?php
class Wishlist {
	public function __construct() {
		add_action( 'admin_post_wishlist_delete', array( $this, 'delete_wishlist' ) );
	}
	public function delete_wishlist() {
		$this->delete( array( $_GET['wishlist'] ) );
		wp_redirect( admin_url() );
	}
	private function delete( $ids ) {
		global $wpdb;
		$wpdb->delete( $wpdb->prefix . 'wishlist', array( 'id' => $ids[0] ) );
	}
}`);
    expect(f).toHaveLength(2);
  });

  it('nonce i uprawnienia sprawdzone w metodzie wołanej z uchwytu uspokajają regułę', async () => {
    const f = await auth(`<?php
class Wishlist {
	public function __construct() {
		add_action( 'admin_post_wishlist_delete', array( $this, 'delete_wishlist' ) );
	}
	public function delete_wishlist() {
		$this->run( $_GET['wishlist'] );
	}
	private function run( $id ) {
		check_admin_referer( 'wishlist' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'no' );
		}
		update_option( 'wishlist_deleted', $id );
	}
}`);
    expect(f).toHaveLength(0);
  });

  it('funkcja pomocnicza z tego samego pliku zmienia stan', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_nopriv_track', 'track' );
function track() {
	save_hit( $_POST['page'] );
}
function save_hit( $page ) {
	update_option( 'last_hit', $page );
}`);
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain('nonce');
  });

  it('pomocnik o nazwie kontrolnej w wołanej metodzie uspokaja regułę', async () => {
    const f = await auth(`<?php
class A {
	public function __construct() {
		add_action( 'wp_ajax_a', array( $this, 'handle' ) );
	}
	public function handle() { $this->process(); }
	private function process() {
		$this->check_permissions();
		update_option( 'a', $_POST['v'] );
	}
}`);
    expect(f).toHaveLength(0);
  });
});

describe('zapis do konta zalogowanego użytkownika', () => {
  it('update_user_meta z get_current_user_id nie wymaga uprawnień', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_dismiss_notice', 'dismiss_notice' );
function dismiss_notice() {
	update_user_meta( get_current_user_id(), 'notice_dismissed', 1 );
	wp_send_json_success();
}`);
    expect(f).toHaveLength(0);
  });

  it('identyfikator przepisany do zmiennej też', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_dismiss_notice', 'dismiss_notice' );
function dismiss_notice() {
	$uid = get_current_user_id();
	update_user_meta( $uid, 'notice_dismissed', 1 );
}`);
    expect(f).toHaveLength(0);
  });

  it('zapis do konta wskazanego w żądaniu nadal jest zgłaszany', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_set_meta', 'set_meta' );
function set_meta() {
	update_user_meta( (int) $_POST['uid'], 'level', $_POST['level'] );
}`);
    expect(f).toHaveLength(2);
  });

  it('opcja użytkownika zapisana pod ID z wp_get_current_user nie wymaga uprawnień', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_hide_columns', 'hide_columns' );
function hide_columns() {
	$user = wp_get_current_user();
	update_user_option( $user->ID, 'hidden_columns', explode( ',', $_POST['hidden'] ), true );
	die();
}`);
    expect(f).toHaveLength(0);
  });

  it('opcja użytkownika wskazanego w żądaniu nadal jest zgłaszana', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_hide_columns', 'hide_columns' );
function hide_columns() {
	update_user_option( (int) $_POST['uid'], 'hidden_columns', $_POST['hidden'], true );
}`);
    expect(f).toHaveLength(2);
  });

  it('obiekt użytkownika pobrany po ID z żądania nie jest kontem zalogowanego', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_set_level', 'set_level' );
function set_level() {
	$user = get_user_by( 'id', (int) $_POST['uid'] );
	update_user_meta( $user->ID, 'level', $_POST['level'] );
}`);
    expect(f).toHaveLength(2);
  });
});

describe('nazwy, które tylko brzmią jak sprawdzenie', () => {
  it('wp_get_current_user nie jest sprawdzeniem uprawnień', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_feedback', 'feedback' );
function feedback() {
	$user = wp_get_current_user();
	update_option( 'feedback_' . $user->ID, $_POST['text'] );
}`);
    expect(f).toHaveLength(2);
  });

  it('is_admin() pyta o obszar administracyjny, nie o prawa', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_conf', 'conf' );
function conf() {
	if ( ! is_admin() ) {
		return;
	}
	update_option( 'conf', $_POST['v'] );
}`);
    expect(f).toHaveLength(2);
  });

  it('metoda is_admin własnej klasy uspokaja regułę', async () => {
    const f = await auth(`<?php
class C {
	public function __construct() {
		add_action( 'wp_ajax_conf', array( $this, 'conf' ) );
	}
	public function conf() {
		if ( ! $this->is_admin() ) {
			return;
		}
		update_option( 'conf', $_POST['v'] );
	}
}`);
    expect(f).toHaveLength(0);
  });

  it('wp_get_referer nie jest sprawdzeniem nonce', async () => {
    const f = await auth(`<?php
add_action( 'admin_post_reset', 'reset_conf' );
function reset_conf() {
	delete_option( 'conf' );
	wp_safe_redirect( wp_get_referer() );
}`);
    expect(f).toHaveLength(2);
  });

  it('autor wpisu nie jest sprawdzeniem uprawnień', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_rename', 'rename_post' );
function rename_post() {
	$author = get_the_author_meta( 'ID' );
	wp_update_post( array( 'ID' => $_POST['id'], 'post_title' => $_POST['t'], 'post_author' => $author ) );
}`);
    expect(f).toHaveLength(2);
  });

  it('ręczne sprawdzenie ról użytkownika uspokaja regułę', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_conf', 'conf' );
function conf() {
	$user = wp_get_current_user();
	if ( ! in_array( 'administrator', $user->roles, true ) ) {
		wp_die( 'no' );
	}
	update_option( 'conf', $_POST['v'] );
}`);
    expect(f).toHaveLength(0);
  });

  it('metoda w camelCase o nazwie sprawdzającej prawa uspokaja regułę', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_save_map', 'save_map' );
function save_map() {
	global $plugin;
	if ( ! $plugin->isUserAllowedToEdit() ) {
		wp_die( 'no' );
	}
	update_option( 'map', $_POST['v'] );
}`);
    expect(f).toHaveLength(0);
  });

  it('funkcja userCanManage też', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_save_map', 'save_map' );
function save_map() {
	if ( ! userCanManage() ) {
		wp_die( 'no' );
	}
	update_option( 'map', $_POST['v'] );
}`);
    expect(f).toHaveLength(0);
  });

  it('getAccessToken w camelCase nie jest sprawdzeniem', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_save_map', 'save_map' );
function save_map() {
	$token = getAccessToken();
	update_option( 'map', $_POST['v'] . $token );
}`);
    expect(f).toHaveLength(2);
  });

  it('pomocnik walidujący żądanie AJAX uspokaja regułę', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_save_preset', 'save_preset' );
function save_preset() {
	acme_validate_ajax( 'acme_preset', false, 'acme-settings' );
	update_option( 'preset', $_POST['v'] );
}`);
    expect(f).toHaveLength(0);
  });

  it('pomocnik walidujący dane nie uspokaja reguły', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_save_preset', 'save_preset' );
function save_preset() {
	acme_validate_input( $_POST['v'] );
	update_option( 'preset', $_POST['v'] );
}`);
    expect(f).toHaveLength(2);
  });
});

describe('haki wykonywane przy każdym żądaniu', () => {
  it('admin_init nie jest oceniany przez tę regułę', async () => {
    const f = await auth(`<?php
add_action( 'admin_init', 'save_settings' );
function save_settings() {
	if ( isset( $_POST['plugin_save'] ) ) {
		update_option( 'plugin_settings', $_POST['plugin_settings'] );
	}
}`);
    expect(f).toHaveLength(0);
  });
});

describe('zmiana stanu w pomocniku', () => {
  it('pomocnik dostaje dane z żądania w argumencie', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_remove_item', 'remove_item' );
function remove_item() {
	purge_item( $_POST['id'] );
}
function purge_item( $id ) {
	delete_option( 'item_' . $id );
}`);
    expect(f).toHaveLength(2);
  });

  it('zmienna przypisana z żądania i podana pomocnikowi', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_remove_item', 'remove_item' );
function remove_item() {
	$id = (int) $_POST['id'];
	purge_item( $id );
}
function purge_item( $id ) {
	delete_option( 'item_' . $id );
}`);
    expect(f).toHaveLength(2);
  });

  it('pomocnik sam czyta żądanie', async () => {
    const f = await auth(`<?php
class Saver {
	public function __construct() {
		add_action( 'wp_ajax_save_prefs', array( $this, 'handle' ) );
	}
	public function handle() { $this->store(); }
	private function store() {
		update_option( 'prefs', $_POST['prefs'] );
	}
}`);
    expect(f).toHaveLength(2);
  });

  it('dane z żądania przechodzą przez dwa pomocniki', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_remove_item', 'remove_item' );
function remove_item() {
	prepare_removal( $_POST['id'] );
}
function prepare_removal( $id ) {
	purge_item( $id );
}
function purge_item( $id ) {
	delete_option( 'item_' . $id );
}`);
    expect(f).toHaveLength(2);
  });

  it('zmiana stanu na trzecim poziomie nie liczy się', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_remove_item', 'remove_item' );
function remove_item() {
	first_step( $_POST['id'] );
}
function first_step( $id ) { second_step( $id ); }
function second_step( $id ) { third_step( $id ); }
function third_step( $id ) {
	delete_option( 'item_' . $id );
}`);
    expect(f).toHaveLength(0);
  });

  it('pomocnik, który nie dostaje danych z żądania i ich nie czyta, nie liczy się', async () => {
    const f = await auth(`<?php
class Cache {
	public function __construct() {
		add_action( 'wp_ajax_refresh_view', array( $this, 'handle' ) );
	}
	public function handle() {
		$this->clear_cache();
		wp_send_json_success();
	}
	private function clear_cache() {
		update_option( 'view_cache_ttl', 5 );
	}
}`);
    expect(f).toHaveLength(0);
  });

  it('ta sama zmiana wprost w uchwycie jest zgłaszana', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_refresh_view', 'refresh_view' );
function refresh_view() {
	update_option( 'view_cache_ttl', 5 );
	wp_send_json_success();
}`);
    expect(f).toHaveLength(2);
  });
});

describe('uchwyty zamykające powiadomienie', () => {
  it('zapis opcji pod stałym kluczem w uchwycie dismiss nie jest zgłaszany', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_dismiss_notice', 'acme_dismiss_notice' );
function acme_dismiss_notice() {
	update_option( 'acme_notice_dismissed', 1 );
	wp_die();
}`);
    expect(f).toHaveLength(0);
  });

  it('baner i wskazówka też', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_hide_banner', 'acme_hide_banner' );
add_action( 'wp_ajax_nopriv_acme_close_tooltip', 'acme_hide_banner' );
function acme_hide_banner() {
	set_transient( 'acme_banner_hidden', 1, DAY_IN_SECONDS );
}`);
    expect(f).toHaveLength(0);
  });

  it('klucz opcji z żądania w uchwycie dismiss nadal jest zgłaszany', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_dismiss_notice', 'acme_dismiss_notice' );
function acme_dismiss_notice() {
	update_option( 'acme_' . $_POST['key'], 1 );
}`);
    expect(f).toHaveLength(2);
  });

  it('zapis do bazy w uchwycie dismiss nadal jest zgłaszany', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_dismiss_notice', 'acme_dismiss_notice' );
function acme_dismiss_notice() {
	global $wpdb;
	$wpdb->delete( $wpdb->prefix . 'acme_items', array( 'id' => (int) $_POST['id'] ) );
}`);
    expect(f).toHaveLength(2);
  });

  it('ten sam zapis opcji w uchwycie o innej nazwie jest zgłaszany', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_acme_save_settings', 'acme_save_settings' );
function acme_save_settings() {
	update_option( 'acme_notice_dismissed', 1 );
}`);
    expect(f).toHaveLength(2);
  });
});

describe('uchwyty publiczne z założenia', () => {
  it('ten sam callback pod hakiem nopriv nie dostaje zgłoszenia o uprawnieniach', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_subscribe', 'subscribe' );
add_action( 'wp_ajax_nopriv_subscribe', 'subscribe' );
function subscribe() {
	global $wpdb;
	check_ajax_referer( 'subscribe' );
	$wpdb->insert( $wpdb->prefix . 'subscribers', array( 'email' => sanitize_email( $_POST['email'] ) ) );
}`);
    expect(f).toHaveLength(0);
  });

  it('brak nonce jest zgłaszany pod obydwoma hakami, bez zgłoszenia o uprawnieniach', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_subscribe', 'subscribe' );
add_action( 'wp_ajax_nopriv_subscribe', 'subscribe' );
function subscribe() {
	global $wpdb;
	$wpdb->insert( $wpdb->prefix . 'subscribers', array( 'email' => sanitize_email( $_POST['email'] ) ) );
}`);
    expect(f).toHaveLength(2);
    expect(f.every((x) => /nonce/.test(x.message))).toBe(true);
  });

  it('metoda tej samej klasy pod obydwoma hakami też', async () => {
    const f = await auth(`<?php
class Subscribe {
	public function __construct() {
		add_action( 'wp_ajax_subscribe', array( $this, 'handle' ) );
		add_action( 'wp_ajax_nopriv_subscribe', array( $this, 'handle' ) );
	}
	public function handle() {
		global $wpdb;
		check_ajax_referer( 'subscribe' );
		$wpdb->insert( $wpdb->prefix . 'subscribers', array( 'email' => sanitize_email( $_POST['email'] ) ) );
	}
}`);
    expect(f).toHaveLength(0);
  });

  it('publiczny uchwyt, który zmienia opcję serwisu, nadal dostaje zgłoszenie o uprawnieniach', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_subscribe', 'subscribe' );
add_action( 'wp_ajax_nopriv_subscribe', 'subscribe' );
function subscribe() {
	check_ajax_referer( 'subscribe' );
	update_option( 'subscribers', $_POST['email'] );
}`);
    expect(f).toHaveLength(1);
    expect(f[0].message).toMatch(/capabilities/);
  });

  it('publiczny uchwyt, który nadaje rolę albo uprawnienie, nadal dostaje zgłoszenie o uprawnieniach', async () => {
    const f = await auth(`<?php
class Team {
	public function __construct() {
		add_action( 'wp_ajax_team_add', array( $this, 'add' ) );
		add_action( 'wp_ajax_nopriv_team_add', array( $this, 'add' ) );
	}
	public function add() {
		check_ajax_referer( 'team' );
		$user = get_user_by( 'id', absint( $_POST['id'] ) );
		$user->add_cap( 'manage_options' );
	}
}`);
    expect(f).toHaveLength(1);
    expect(f[0].message).toMatch(/capabilities/);
  });

  it('publiczny uchwyt, który ustawia hasło innego konta, nadal dostaje zgłoszenie o uprawnieniach', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_reset_new_pass', 'reset_new_pass' );
add_action( 'wp_ajax_nopriv_reset_new_pass', 'reset_new_pass' );
function reset_new_pass() {
	check_ajax_referer( 'reset' );
	$user = get_user_by( 'email', sanitize_email( $_POST['user_email'] ) );
	wp_set_password( sanitize_text_field( $_POST['new_pass'] ), $user->ID );
}`);
    expect(f).toHaveLength(1);
    expect(f[0].message).toMatch(/capabilities/);
  });

  it('inny callback pod hakiem nopriv nie zwalnia uchwytu dla zalogowanych', async () => {
    const f = await auth(`<?php
add_action( 'wp_ajax_save', 'save_private' );
add_action( 'wp_ajax_nopriv_save', 'save_public' );
function save_private() {
	check_ajax_referer( 'save' );
	update_option( 'conf', $_POST['v'] );
}
function save_public() {
	wp_send_json_error();
}`);
    expect(f).toHaveLength(1);
    expect(f[0].message).toMatch(/capabilities/);
  });
});
