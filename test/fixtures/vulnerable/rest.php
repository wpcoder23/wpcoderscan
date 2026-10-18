<?php
// Brak permission_callback, endpoint otwarty.
register_rest_route( 'myplugin/v1', '/items', array(
	'methods'  => 'POST',
	'callback' => 'myplugin_create_item',
) );

// permission_callback ustawiony na __return_true.
register_rest_route( 'myplugin/v1', '/open', array(
	'methods'             => 'GET',
	'callback'            => 'myplugin_list',
	'permission_callback' => '__return_true',
) );

// Lista endpointów, jeden bez permission_callback.
register_rest_route( 'myplugin/v1', '/multi', array(
	array(
		'methods'             => 'GET',
		'callback'            => 'myplugin_get',
		'permission_callback' => 'myplugin_can_read',
	),
	array(
		'methods'  => 'DELETE',
		'callback' => 'myplugin_delete',
	),
) );
