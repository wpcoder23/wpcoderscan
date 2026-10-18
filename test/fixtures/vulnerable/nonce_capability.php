<?php
// Uchwyt admin-post bez nonce i bez sprawdzenia uprawnień.
add_action( 'admin_post_delete_item', 'delete_item_handler' );
function delete_item_handler() {
	$id = (int) $_POST['id'];
	delete_option( 'item_' . $id );
}

// Uchwyt AJAX w domknięciu, brak obu kontroli.
add_action( 'wp_ajax_save_config', function () {
	update_option( 'config', $_POST['config'] );
} );

// Uchwyt z nonce, ale bez sprawdzenia uprawnień.
add_action( 'admin_post_update_role', 'update_role_handler' );
function update_role_handler() {
	check_admin_referer( 'update_role' );
	update_option( 'role', $_POST['role'] );
}
