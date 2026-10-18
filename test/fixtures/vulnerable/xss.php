<?php
// Bezpośredni superglobal w echo.
echo $_GET['name'];

// Superglobal w print.
print $_POST['message'];

// Superglobal w konkatenacji.
echo 'Witaj ' . $_REQUEST['user'];

// Superglobal w interpolacji łańcucha.
echo "Szukasz: {$_GET['q']}";

// Zmienna zasilona superglobalem trafia do echo (heurystyka średnia).
$query = trim( $_GET['query'] );
echo '<h2>' . $query . '</h2>';
