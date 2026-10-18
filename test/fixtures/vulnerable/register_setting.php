<?php
// Brak trzeciego argumentu, brak sanitize_callback.
register_setting( 'my_group', 'my_option_a' );

// Tablica argumentów bez sanitize_callback.
register_setting( 'my_group', 'my_option_b', array(
	'type'    => 'string',
	'default' => '',
) );
