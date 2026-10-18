<?php
// eval na danych dynamicznych.
eval( $user_code );

// include ze ścieżką ze zmiennej.
include $template;

// require_once ze ścieżką z superglobala.
require_once ABSPATH . $_GET['file'];

// polecenie systemowe ze zmiennej.
system( $cmd );

// shell_exec z superglobalem.
$out = shell_exec( 'ls ' . $_POST['dir'] );

// polecenie w backtickach z interpolacją.
$list = `cat $path`;
