<?php
// include ze ścieżką z samych stałych i literałów.
require_once ABSPATH . 'wp-admin/includes/plugin.php';
include plugin_dir_path( __FILE__ ) . 'includes/helpers.php';

// polecenie systemowe z samym literałem.
$uptime = shell_exec( 'uptime' );

// Szablon ze zmiennej, która nie pochodzi od użytkownika.
$template = locate_template( 'parts/box.php' );
include $template;
function bq_render( $view ) {
	include plugin_dir_path( __FILE__ ) . 'views/' . $view . '.php';
}

// Ścieżka z superglobala po basename, polecenie po escapeshellarg.
include plugin_dir_path( __FILE__ ) . 'pages/' . basename( $_GET['page'] ) . '.php';
$out = shell_exec( 'ls ' . escapeshellarg( $_POST['dir'] ) );

// Komunikat budowany z liczby.
$count = (int) $_GET['n'];
system( 'sleep ' . $count );
