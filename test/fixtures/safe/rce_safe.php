<?php
// include ze ścieżką z samych stałych i literałów.
require_once ABSPATH . 'wp-admin/includes/plugin.php';
include plugin_dir_path( __FILE__ ) . 'includes/helpers.php';

// polecenie systemowe z samym literałem.
$uptime = shell_exec( 'uptime' );
