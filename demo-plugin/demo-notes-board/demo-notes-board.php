<?php
/**
 * Plugin Name: Demo Notes Board (security review sample)
 * Description: DEMO ONLY. A tiny plugin written for a sample security review. It contains INTENTIONALLY PLANTED vulnerabilities. Do not install it on a real site.
 * Version: 1.0.0
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

/* ---------- Front-end board: [dnb_board title="..." limit="5"] ---------- */
add_shortcode( 'dnb_board', 'dnb_board_shortcode' );
function dnb_board_shortcode( $atts ) {
	$atts  = shortcode_atts( array( 'title' => 'Notes board', 'limit' => 5 ), $atts );
	$notes = get_posts( array(
		'post_type'   => 'dnb_note',
		'post_status' => 'publish',
		'numberposts' => (int) $atts['limit'],
	) );
	// [FINDING 1] attribute value printed without escaping.
	$out = '<div class="dnb-board" data-title="' . $atts['title'] . '"><ul>';
	foreach ( $notes as $note ) {
		$author = get_post_meta( $note->ID, 'dnb_author', true );
		// [FINDING 2] stored author name printed without escaping.
		$out .= '<li><strong>' . $author . '</strong>: ' . esc_html( $note->post_title ) . '</li>';
	}
	return $out . '</ul></div>';
}

/* ---------- REST: create a note ---------- */
add_action( 'rest_api_init', 'dnb_register_routes' );
function dnb_register_routes() {
	register_rest_route( 'dnb/v1', '/notes', array(
		'methods'             => 'POST',
		'callback'            => 'dnb_rest_create_note',
		// [FINDING 2] anyone, logged in or not, can call this.
		'permission_callback' => '__return_true',
	) );
}
function dnb_rest_create_note( WP_REST_Request $request ) {
	$id = wp_insert_post( array(
		'post_type'   => 'dnb_note',
		'post_title'  => sanitize_text_field( $request->get_param( 'title' ) ),
		'post_status' => 'publish',
	) );
	update_post_meta( $id, 'dnb_author', $request->get_param( 'author' ) );
	return array( 'id' => $id );
}

/* ---------- AJAX: search and delete ---------- */
add_action( 'wp_ajax_nopriv_dnb_search', 'dnb_ajax_search' );
add_action( 'wp_ajax_dnb_search', 'dnb_ajax_search' );
function dnb_ajax_search() {
	global $wpdb;
	$q = isset( $_GET['q'] ) ? wp_unslash( $_GET['q'] ) : '';
	// [FINDING 3] user input concatenated into SQL.
	$rows = $wpdb->get_results(
		"SELECT ID, post_title FROM {$wpdb->posts} WHERE post_type = 'dnb_note' AND post_status = 'publish' AND post_title LIKE '%$q%'"
	);
	wp_send_json( $rows );
}

add_action( 'wp_ajax_dnb_delete_note', 'dnb_ajax_delete_note' );
function dnb_ajax_delete_note() {
	// [FINDING 4] no nonce, no capability check, and the ID is not limited to notes.
	$id = isset( $_POST['id'] ) ? (int) $_POST['id'] : 0;
	wp_delete_post( $id, true );
	wp_send_json_success();
}

/* ---------- Export download: ?dnb_export=file.csv ---------- */
add_action( 'init', 'dnb_maybe_download_export' );
function dnb_maybe_download_export() {
	if ( empty( $_GET['dnb_export'] ) ) {
		return;
	}
	// [FINDING 5] file name used as-is: path traversal, no login required.
	$file = DNB_DIR . 'exports/' . $_GET['dnb_export'];
	if ( file_exists( $file ) ) {
		header( 'Content-Type: text/plain' );
		readfile( $file );
		exit;
	}
}

/* ---------- Attachment upload (logged-in users) ---------- */
add_action( 'admin_post_dnb_upload', 'dnb_handle_upload' );
function dnb_handle_upload() {
	// [FINDING 6] no nonce, no capability check, no file type check.
	$dir = wp_upload_dir()['basedir'] . '/dnb';
	wp_mkdir_p( $dir );
	$name = $_FILES['attachment']['name'];
	move_uploaded_file( $_FILES['attachment']['tmp_name'], $dir . '/' . $name );
	wp_die( 'Uploaded.' );
}

/* ---------- Admin page ---------- */
add_action( 'admin_menu', function () {
	add_menu_page( 'Notes Board', 'Notes Board', 'manage_options', 'dnb-board', 'dnb_admin_page' );
} );
function dnb_admin_page() {
	echo '<div class="wrap"><h1>Notes Board</h1>';
	// [FINDING 7] reflected value printed without escaping.
	if ( isset( $_GET['msg'] ) ) {
		echo '<div class="notice notice-info"><p>' . $_GET['msg'] . '</p></div>';
	}
	echo '</div>';
}
