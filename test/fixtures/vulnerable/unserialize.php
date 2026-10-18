<?php
$a = unserialize( $_POST['payload'] );
$b = maybe_unserialize( $_COOKIE['data'] );
$c = unserialize( base64_decode( $_GET['x'] ) );
