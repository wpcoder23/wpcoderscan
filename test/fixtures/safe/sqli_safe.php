<?php
global $wpdb;

$id = absint( $_GET['id'] );
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->posts} WHERE ID = %d", $id ) );

$count = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->users}" );
