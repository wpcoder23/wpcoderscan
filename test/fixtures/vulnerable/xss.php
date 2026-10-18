<?php
// Bezpośredni superglobal w echo.
echo $_GET['name'];

// Superglobal w print.
print $_POST['message'];

// Superglobal w konkatenacji.
echo 'Witaj ' . $_REQUEST['user'];

// Superglobal w interpolacji łańcucha.
echo "Szukasz: {$_GET['q']}";
