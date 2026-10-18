<?php
/**
 * Plugin Name: Przykładowa Wtyczka Rezerwacji (bezpieczna)
 * Description: Ta sama wtyczka napisana poprawnie. Skaner nie powinien nic zgłosić.
 * Version: 1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// AJAX tylko dla zalogowanych, z nonce, uprawnieniami i prepare.
add_action( 'wp_ajax_bq_search', 'bq_search' );
function bq_search() {
	global $wpdb;
	check_ajax_referer( 'bq_search' );
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_send_json_error();
	}
	$term = sanitize_text_field( wp_unslash( $_POST['term'] ) );
	$rows = $wpdb->get_results(
		$wpdb->prepare( "SELECT * FROM {$wpdb->prefix}bookings WHERE name LIKE %s", '%' . $wpdb->esc_like( $term ) . '%' )
	);
	wp_send_json_success( $rows );
}

// Akcja administratora z nonce, uprawnieniami i prepare.
add_action( 'admin_post_bq_delete', 'bq_delete' );
function bq_delete() {
	global $wpdb;
	check_admin_referer( 'bq_delete' );
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die();
	}
	$id = (int) $_GET['id'];
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}bookings WHERE id = %d", $id ) );
	wp_safe_redirect( admin_url( 'admin.php?page=bq' ) );
	exit;
}

// Odbicie parametru z ucieczką.
add_action( 'admin_notices', 'bq_notice' );
function bq_notice() {
	echo '<div class="notice notice-info">Filtr: ' . esc_html( $_GET['filter'] ) . '</div>';
}

// Trasa REST z permission_callback.
add_action( 'rest_api_init', function () {
	register_rest_route( 'bq/v1', '/bookings', array(
		'methods'             => 'GET',
		'callback'            => 'bq_rest_list',
		'permission_callback' => function () {
			return current_user_can( 'manage_options' );
		},
	) );
} );
function bq_rest_list() {
	return array( 'ok' => true );
}

// Opcja z sanitize_callback.
add_action( 'admin_init', function () {
	register_setting( 'bq_options', 'bq_booking_limit', array(
		'type'              => 'integer',
		'sanitize_callback' => 'absint',
	) );
} );
