<?php
// eval na danych dynamicznych (heurystyka, nieznane pochodzenie).
eval( $user_code );

// eval z superglobala (pewne).
eval( $_POST['code'] );

// require_once ze ścieżką z superglobala (pewne).
require_once ABSPATH . $_GET['file'];

// shell_exec z superglobalem (pewne).
$out = shell_exec( 'ls ' . $_POST['dir'] );

// polecenie w backtickach z interpolacją superglobala (pewne).
$list = `cat {$_GET['path']}`;

// Zmienna zasilona superglobalem trafia do include i exec (heurystyka).
$page = $_GET['page'];
include __DIR__ . '/pages/' . $page . '.php';
$host = $_POST['host'];
exec( 'ping ' . $host );
