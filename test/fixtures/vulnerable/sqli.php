<?php
global $wpdb;

$id = $_GET['id'];
$wpdb->query("DELETE FROM {$wpdb->posts} WHERE ID = $id");

$name = $_POST['name'];
$wpdb->get_results("SELECT * FROM users WHERE name = '" . $name . "'");

$wpdb->query("SELECT * FROM t WHERE id = " . $_GET['id']);
