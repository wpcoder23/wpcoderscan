<?php
// maybe_unserialize na danych z bazy, nie od użytkownika.
$data = get_option( 'my_option' );
$a = maybe_unserialize( $data );

// JSON zamiast deserializacji obiektu.
$b = json_decode( $_POST['payload'], true );
