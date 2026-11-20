<?php
/**
 * Plugin Name: Demo Notes Board (security review sample, fixed)
 * Description: DEMO ONLY. The corrected version of the sample plugin, with every finding in the sample report fixed.
 * Version: 1.0.1
 * Author: Bryan Byfield
 * License: GPL-2.0-or-later
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'DNB_DIR', plugin_dir_path( __FILE__ ) );

add_action( 'init', 'dnb_register_post_type' );
function dnb_register_post_type() {
	register_post_type( 'dnb_note', array(
		'label'    => 'Notes',
		'public'   => false,
		'show_ui'  => true,
		'supports' => array( 'title', 'editor' ),
	) );
}

add_shortcode( 'dnb_board', 'dnb_board_shortcode' );
function dnb_board_shortcode( $atts ) {
	$atts  = shortcode_atts( array( 'title' => 'Notes board', 'limit' => 5 ), $atts );
	$notes = get_posts( array(
		'post_type'   => 'dnb_note',
		'post_status' => 'publish',
		'numberposts' => absint( $atts['limit'] ),
	) );
	// FIX 1: escape the attribute.
	$out = '<div class="dnb-board" data-title="' . esc_attr( $atts['title'] ) . '"><ul>';
	foreach ( $notes as $note ) {
		$author = get_post_meta( $note->ID, 'dnb_author', true );
		// FIX 2b: escape the stored author name on output.
		$out .= '<li><strong>' . esc_html( $author ) . '</strong>: ' . esc_html( $note->post_title ) . '</li>';
	}
	return $out . '</ul></div>';
}

add_action( 'rest_api_init', 'dnb_register_routes' );
function dnb_register_routes() {
	register_rest_route( 'dnb/v1', '/notes', array(
		'methods'             => 'POST',
		'callback'            => 'dnb_rest_create_note',
		// FIX 2a: only users who can publish posts may create notes.
		'permission_callback' => function () {
			return current_user_can( 'publish_posts' );
		},
	) );
}
function dnb_rest_create_note( WP_REST_Request $request ) {
	$id = wp_insert_post( array(
		'post_type'   => 'dnb_note',
		'post_title'  => sanitize_text_field( $request->get_param( 'title' ) ),
		'post_status' => 'publish',
	) );
	// FIX 2c: sanitize on input as well.
	update_post_meta( $id, 'dnb_author', sanitize_text_field( $request->get_param( 'author' ) ) );
	return array( 'id' => $id );
}

add_action( 'wp_ajax_nopriv_dnb_search', 'dnb_ajax_search' );
add_action( 'wp_ajax_dnb_search', 'dnb_ajax_search' );
function dnb_ajax_search() {
	global $wpdb;
	$q = isset( $_GET['q'] ) ? sanitize_text_field( wp_unslash( $_GET['q'] ) ) : '';
	// FIX 3: prepared statement with an escaped LIKE value.
	$like = '%' . $wpdb->esc_like( $q ) . '%';
	$rows = $wpdb->get_results(
		$wpdb->prepare(
			"SELECT ID, post_title FROM {$wpdb->posts} WHERE post_type = 'dnb_note' AND post_status = 'publish' AND post_title LIKE %s",
			$like
		)
	);
	wp_send_json( $rows );
}

add_action( 'wp_ajax_dnb_delete_note', 'dnb_ajax_delete_note' );
function dnb_ajax_delete_note() {
	// FIX 4: nonce, capability, and only delete posts of the right type.
	check_ajax_referer( 'dnb_delete_note', 'nonce' );
	$id = isset( $_POST['id'] ) ? absint( $_POST['id'] ) : 0;
	if ( ! $id || 'dnb_note' !== get_post_type( $id ) || ! current_user_can( 'delete_post', $id ) ) {
		wp_send_json_error( null, 403 );
	}
	wp_delete_post( $id, true );
	wp_send_json_success();
}

add_action( 'init', 'dnb_maybe_download_export' );
function dnb_maybe_download_export() {
	if ( empty( $_GET['dnb_export'] ) ) {
		return;
	}
	// FIX 5: login and capability required, file name reduced to a base name, and the real path must stay inside the exports folder.
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Not allowed.', '', array( 'response' => 403 ) );
	}
	$base = realpath( DNB_DIR . 'exports' );
	$file = realpath( $base . '/' . basename( wp_unslash( $_GET['dnb_export'] ) ) );
	if ( $file && 0 === strpos( $file, $base . DIRECTORY_SEPARATOR ) && is_file( $file ) ) {
		header( 'Content-Type: text/plain' );
		readfile( $file );
		exit;
	}
	wp_die( 'File not found.', '', array( 'response' => 404 ) );
}

add_action( 'admin_post_dnb_upload', 'dnb_handle_upload' );
function dnb_handle_upload() {
	// FIX 6: nonce, capability, and WordPress's own upload handling with a type allow-list.
	check_admin_referer( 'dnb_upload' );
	if ( ! current_user_can( 'upload_files' ) ) {
		wp_die( 'Not allowed.', '', array( 'response' => 403 ) );
	}
	require_once ABSPATH . 'wp-admin/includes/file.php';
	$result = wp_handle_upload(
		$_FILES['attachment'],
		array(
			'test_form' => false,
			'mimes'     => array( 'jpg|jpeg' => 'image/jpeg', 'png' => 'image/png', 'pdf' => 'application/pdf' ),
		)
	);
	if ( isset( $result['error'] ) ) {
		wp_die( esc_html( $result['error'] ), '', array( 'response' => 400 ) );
	}
	wp_die( 'Uploaded.' );
}

add_action( 'admin_menu', function () {
	add_menu_page( 'Notes Board', 'Notes Board', 'manage_options', 'dnb-board', 'dnb_admin_page' );
} );
function dnb_admin_page() {
	echo '<div class="wrap"><h1>Notes Board</h1>';
	// FIX 7: escape the reflected value.
	if ( isset( $_GET['msg'] ) ) {
		echo '<div class="notice notice-info"><p>' . esc_html( sanitize_text_field( wp_unslash( $_GET['msg'] ) ) ) . '</p></div>';
	}
	echo '</div>';
}
