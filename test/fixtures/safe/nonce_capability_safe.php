<?php
// Uchwyt z nonce i sprawdzeniem uprawnień.
add_action( 'admin_post_safe_save', 'safe_save_handler' );
function safe_save_handler() {
	check_admin_referer( 'safe_save' );
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die();
	}
	update_option( 'safe', $_POST['v'] );
}

// Domknięcie AJAX z obiema kontrolami.
add_action( 'wp_ajax_safe_ajax', function () {
	check_ajax_referer( 'safe_ajax' );
	if ( ! current_user_can( 'edit_posts' ) ) {
		return;
	}
	wp_send_json_success();
} );

// Hak nopriv dla niezalogowanych, wymagany tylko nonce.
add_action( 'wp_ajax_nopriv_public_ping', 'public_ping_handler' );
function public_ping_handler() {
	check_ajax_referer( 'public_ping' );
	wp_send_json_success();
}

// Callback metody obiektu, którego nie rozwiązujemy.
add_action( 'admin_post_obj_handler', array( $this, 'handle' ) );

// Uchwyt tylko czyta dane, nie zmienia stanu. Brak nonce nie jest tu błędem.
add_action( 'wp_ajax_nopriv_search_posts', 'search_posts_handler' );
function search_posts_handler() {
	$posts = get_posts( array( 's' => sanitize_text_field( $_GET['s'] ) ) );
	wp_send_json_success( $posts );
}

// Weryfikację robi pomocnik z nazwą wskazującą na kontrolę dostępu.
add_action( 'admin_post_guarded_save', 'guarded_save_handler' );
function guarded_save_handler() {
	myplugin_verify_request();
	update_option( 'guarded', $_POST['v'] );
}
