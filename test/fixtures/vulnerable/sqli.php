<?php
global $wpdb;

$id = $_GET['id'];
$wpdb->query("DELETE FROM {$wpdb->posts} WHERE ID = $id");

$name = $_POST['name'];
$wpdb->get_results("SELECT * FROM users WHERE name = '" . $name . "'");

$wpdb->query("SELECT * FROM t WHERE id = " . $_GET['id']);

// Pętla po danych użytkownika, każdy element trafia do zapytania.
foreach ( $_POST['ids'] as $item ) {
	$wpdb->query( "DELETE FROM {$wpdb->postmeta} WHERE meta_id = $item" );
}

// Skażenie przez sklejanie w osobną zmienną z zapytaniem.
$search = trim( wp_unslash( $_GET['s'] ) );
$sql    = "SELECT ID FROM {$wpdb->posts} WHERE post_title LIKE '%" . $search . "%'";
$wpdb->get_col( $sql );
