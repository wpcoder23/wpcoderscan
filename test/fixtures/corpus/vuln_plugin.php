<?php
/**
 * Plugin Name: Przykładowa Wtyczka Rezerwacji
 * Description: Fikcyjna wtyczka do testów skanera, wzorowana na typowych CVE WordPressa. Nie używać na produkcji.
 * Version: 1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Nieuwierzytelniony AJAX z SQL injection przez sklejanie. Brak nonce.
add_action( 'wp_ajax_nopriv_bq_search', 'bq_search' );
function bq_search() {
	global $wpdb;
	$term = $_POST['term'];
	$rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}bookings WHERE name LIKE '%" . $term . "%'" );
	echo wp_json_encode( $rows );
	wp_die();
}

// Akcja administratora kasująca rekord bez sprawdzenia uprawnień i nonce.
add_action( 'admin_post_bq_delete', 'bq_delete' );
function bq_delete() {
	global $wpdb;
	$id = (int) $_GET['id'];
	$wpdb->query( "DELETE FROM {$wpdb->prefix}bookings WHERE id = " . $id );
	wp_redirect( admin_url( 'admin.php?page=bq' ) );
	exit;
}

// Odbicie parametru z adresu w panelu bez ucieczki.
add_action( 'admin_notices', 'bq_notice' );
function bq_notice() {
	echo '<div class="notice notice-info">Filtr: ' . $_GET['filter'] . '</div>';
}

// Trasa REST bez permission_callback.
add_action( 'rest_api_init', function () {
	register_rest_route( 'bq/v1', '/bookings', array(
		'methods'  => 'GET',
		'callback' => 'bq_rest_list',
	) );
} );
function bq_rest_list() {
	return array( 'ok' => true );
}

// Opcja bez sanitize_callback.
add_action( 'admin_init', function () {
	register_setting( 'bq_options', 'bq_booking_limit' );
} );

// Deserializacja ciasteczka od użytkownika.
function bq_prefs() {
	return unserialize( $_COOKIE['bq_prefs'] );
}
