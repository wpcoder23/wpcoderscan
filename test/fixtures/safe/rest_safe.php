<?php
// Endpoint z realną kontrolą uprawnień.
register_rest_route( 'myplugin/v1', '/items', array(
	'methods'             => 'POST',
	'callback'            => 'myplugin_create_item',
	'permission_callback' => function () {
		return current_user_can( 'edit_posts' );
	},
) );

// Lista endpointów, każdy z permission_callback.
register_rest_route( 'myplugin/v1', '/multi', array(
	array(
		'methods'             => 'GET',
		'callback'            => 'myplugin_get',
		'permission_callback' => 'myplugin_can_read',
	),
	array(
		'methods'             => 'DELETE',
		'callback'            => 'myplugin_delete',
		'permission_callback' => 'myplugin_can_delete',
	),
) );

// Publiczna trasa tylko do odczytu, __return_true jest tu świadomy.
register_rest_route( 'myplugin/v1', '/public', array(
	'methods'             => WP_REST_Server::READABLE,
	'callback'            => 'myplugin_public',
	'permission_callback' => '__return_true',
) );
register_rest_route( 'myplugin/v1', '/status', array(
	'callback'            => 'myplugin_status',
	'permission_callback' => '\__return_true',
) );
