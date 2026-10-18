<?php
global $wpdb;

$id = absint( $_GET['id'] );
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->posts} WHERE ID = %d", $id ) );

$count = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->users}" );

// Rzutowanie na liczbę zdejmuje skażenie.
$post_id = (int) $_GET['post'];
$wpdb->query( "DELETE FROM {$wpdb->postmeta} WHERE post_id = $post_id" );

// Zmienna ponownie przypisana wartością bezpieczną.
$mode = $_GET['mode'];
$mode = absint( $mode );
$wpdb->get_results( "SELECT * FROM {$wpdb->posts} LIMIT $mode" );

// Lista identyfikatorów oczyszczona absint.
$ids = implode( ',', array_map( 'absint', $_POST['ids'] ) );
$wpdb->query( "DELETE FROM {$wpdb->posts} WHERE ID IN ($ids)" );

// Nazwa tabeli ze zmiennej i parametr funkcji. Nie pochodzą z superglobala.
$table = $wpdb->prefix . 'bookings';
$wpdb->get_results( "SELECT * FROM $table" );
function bq_run( $sql ) {
	global $wpdb;
	return $wpdb->get_results( $sql );
}

// esc_sql i prepare ze skażonym argumentem.
$name = esc_sql( $_POST['name'] );
$wpdb->get_var( "SELECT ID FROM {$wpdb->users} WHERE user_login = '$name'" );
$term = $_GET['term'];
$wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->posts} WHERE post_title = %s", $term ) );
