<?php
// sanitize_callback w tablicy argumentów.
register_setting( 'my_group', 'opt_a', array(
	'type'              => 'string',
	'sanitize_callback' => 'sanitize_text_field',
) );

// Stara sygnatura, callback podany jako trzeci argument.
register_setting( 'my_group', 'opt_b', 'absint' );
