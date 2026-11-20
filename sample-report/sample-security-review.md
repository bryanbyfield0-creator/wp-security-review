# Sample Security Review: Demo Notes Board

**This is a sample report.** The plugin below is a demo I wrote myself for this purpose. It contains deliberately planted vulnerabilities so you can see exactly what a review from me looks like. It is not a real plugin, and no real plugin or real person's code is reviewed here. Do not install it on a live site.

| | |
|---|---|
| Plugin reviewed | Demo Notes Board (sample), version 1.0.0, one PHP file, 123 lines |
| Reviewed by | Bryan Byfield |
| Test environment | Fresh local WordPress 7.1.5 install, PHP 8.3, reachable only from my own machine |
| Test accounts | Administrator, Contributor, Subscriber, and a logged-out visitor |
| Review type | Full review (plugin under 10,000 lines) |

## 1. Summary

I read every line of the plugin and then tried each suspected problem on a real WordPress install, once per role, before writing it down. Every finding below was reproduced. Nothing is listed on a hunch.

**Result: 8 findings.** 6 High, 1 Medium and 1 Low. Four of the High findings can be used by a visitor who is not logged in.

| # | Finding | Who can trigger it | Rating |
|---|---|---|---|
| 1 | Shortcode attribute printed without escaping (stored XSS) | Contributor | Medium |
| 2a | REST route open to everyone (`permission_callback` is `__return_true`) | Anyone, no login | High |
| 2b | Stored XSS through the author field, created via 2a | Anyone, no login | High |
| 3 | SQL injection in the search endpoint | Anyone, no login | High |
| 4 | Delete endpoint has no nonce, no capability check, and accepts any post ID | Any logged-in user | High |
| 5 | Path traversal in the export download reads files outside the plugin | Anyone, no login | High |
| 6 | Upload handler accepts any file type from any logged-in user | Subscriber and up | High |
| 7 | Reflected XSS on the admin page | Needs an admin to click a link | Low |

Ratings reflect how easy the issue is to reach and how much it exposes on a typical site. They are my judgment, not a formal score.

## 2. What I checked

- **Capabilities and nonces** on every AJAX action, `admin-post` action and form handler
- **SQL**: every query, whether it goes through `$wpdb->prepare()`, and how LIKE values are escaped
- **Output escaping**: every place user or stored data is printed, including shortcode attributes and post meta
- **Input handling**: sanitizing, and whether `wp_unslash()` is used in a way that undoes WordPress's built-in slashing
- **REST routes**: every `register_rest_route()` and its `permission_callback`
- **File handling**: reads, writes and uploads, including path traversal and file type checks
- **Admin pages**: capability on the menu item, and any reflected values

## 3. Findings

### Finding 1: Shortcode attribute printed without escaping (Medium)

**Where:** `demo-notes-board.php`, line 36, `dnb_board_shortcode()`

```php
$out = '<div class="dnb-board" data-title="' . $atts['title'] . '"><ul>';
```

**Problem:** The `title` attribute of `[dnb_board]` goes straight into an HTML attribute. A Contributor can write a post that breaks out of the attribute and adds their own event handler. When an editor publishes the post, the script runs for every visitor, including admins.

**How I reproduced it:** As a Contributor, I saved a post containing a shortcode whose title value ends the attribute early and adds `onmouseover="alert(1)"`. I published it as an editor would, loaded the page, and the handler was in the page source unescaped.

**Fix:** Escape on output.

```php
$out = '<div class="dnb-board" data-title="' . esc_attr( $atts['title'] ) . '"><ul>';
```

### Finding 2a: REST route open to everyone (High)

**Where:** line 52, `dnb_register_routes()`

```php
'permission_callback' => '__return_true',
```

**Problem:** `POST /wp-json/dnb/v1/notes` creates a published note for any visitor, logged in or not. This is the doorway for Finding 2b and also lets anyone fill the site with junk.

**How I reproduced it:** A logged-out request with a title and author returned a new note ID, and the note appeared on the site.

**Fix:** Require a real capability.

```php
'permission_callback' => function () {
	return current_user_can( 'publish_posts' );
},
```

### Finding 2b: Stored XSS through the author field (High)

**Where:** line 40 (output), line 61 (input) in `dnb_rest_create_note()`

**Problem:** The REST handler saves the `author` value as-is into post meta, and the shortcode prints it without escaping. Combined with 2a, a visitor with no account can plant a script that runs on any page showing the board.

**How I reproduced it:** A logged-out request set the author to a script tag, and I loaded a page with `[dnb_board]` on it. The script tag was in the page source exactly as sent.

**Fix:** Sanitize on the way in and escape on the way out.

```php
update_post_meta( $id, 'dnb_author', sanitize_text_field( $request->get_param( 'author' ) ) );
// and on output:
$out .= '<li><strong>' . esc_html( $author ) . '</strong>: ' . esc_html( $note->post_title ) . '</li>';
```

### Finding 3: SQL injection in the search endpoint (High)

**Where:** lines 70 to 74, `dnb_ajax_search()`, reachable at `admin-ajax.php?action=dnb_search` with no login

```php
$q    = isset( $_GET['q'] ) ? wp_unslash( $_GET['q'] ) : '';
$rows = $wpdb->get_results( "... AND post_title LIKE '%$q%'" );
```

**Problem:** The search term is placed directly into the query. `wp_unslash()` removes the slashes WordPress adds to request data, so the quote characters reach the database intact. A visitor can change the query and read rows they should not see.

**How I reproduced it:** I created a private note with an obvious title. A logged-out request with a crafted search term returned that private note, which the endpoint is never supposed to show.

**Fix:** Use `$wpdb->prepare()` and escape the LIKE wildcard characters.

```php
$like = '%' . $wpdb->esc_like( $q ) . '%';
$rows = $wpdb->get_results( $wpdb->prepare(
	"SELECT ID, post_title FROM {$wpdb->posts} WHERE post_type = 'dnb_note' AND post_status = 'publish' AND post_title LIKE %s",
	$like
) );
```

### Finding 4: Delete endpoint has no checks (High)

**Where:** lines 81 and 82, `dnb_ajax_delete_note()`

```php
$id = isset( $_POST['id'] ) ? (int) $_POST['id'] : 0;
wp_delete_post( $id, true );
```

**Problem:** Three things are missing. There is no nonce, so another site can trigger the delete for a logged-in user (CSRF). There is no capability check, so any logged-in user, even a Subscriber, can call it. And the ID is never checked to be one of this plugin's notes, so it deletes any post or page, permanently.

**How I reproduced it:** As a Subscriber, I sent one request with the ID of the site's default post. The post was gone afterward.

**Fix:** Nonce, capability, and a post type check.

```php
check_ajax_referer( 'dnb_delete_note', 'nonce' );
$id = absint( $_POST['id'] ?? 0 );
if ( ! $id || 'dnb_note' !== get_post_type( $id ) || ! current_user_can( 'delete_post', $id ) ) {
	wp_send_json_error( null, 403 );
}
wp_delete_post( $id, true );
```

### Finding 5: Path traversal in the export download (High)

**Where:** line 93, `dnb_maybe_download_export()`

```php
$file = DNB_DIR . 'exports/' . $_GET['dnb_export'];
```

**Problem:** The file name from the URL is appended to the path without cleaning, so `../` sequences walk out of the exports folder. No login is needed. On a real site this can expose `wp-config.php`, which holds the database credentials and secret keys.

**How I reproduced it:** A logged-out request with `../` segments returned the contents of the test site's `wp-config.php`. (Those are throwaway credentials on my local test install.)

**Fix:** Require a capability, reduce the name to a plain file name, and confirm the resolved path stays inside the exports folder.

```php
if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'Not allowed.', '', array( 'response' => 403 ) ); }
$base = realpath( DNB_DIR . 'exports' );
$file = realpath( $base . '/' . basename( wp_unslash( $_GET['dnb_export'] ) ) );
if ( $file && 0 === strpos( $file, $base . DIRECTORY_SEPARATOR ) && is_file( $file ) ) { /* serve it */ }
```

### Finding 6: Upload handler accepts any file (High)

**Where:** lines 107 and 108, `dnb_handle_upload()`, hooked to `admin_post_dnb_upload`

```php
$name = $_FILES['attachment']['name'];
move_uploaded_file( $_FILES['attachment']['tmp_name'], $dir . '/' . $name );
```

**Problem:** Any logged-in user can upload any file type under its original name, with no nonce and no capability check. A Subscriber account (which anyone can get on a site with open registration) can upload a `.php` file into the uploads folder and run it, which means full control of the site.

**How I reproduced it:** As a Subscriber, I uploaded a one-line PHP file that only prints the word "probe-ok". Requesting it in the browser ran it and printed that word. I used a harmless probe on purpose.

**Fix:** Nonce, capability, and WordPress's own upload handler with an allowed-types list.

```php
check_admin_referer( 'dnb_upload' );
if ( ! current_user_can( 'upload_files' ) ) { wp_die( 'Not allowed.', '', array( 'response' => 403 ) ); }
require_once ABSPATH . 'wp-admin/includes/file.php';
$result = wp_handle_upload( $_FILES['attachment'], array(
	'test_form' => false,
	'mimes'     => array( 'jpg|jpeg' => 'image/jpeg', 'png' => 'image/png', 'pdf' => 'application/pdf' ),
) );
```

### Finding 7: Reflected XSS on the admin page (Low)

**Where:** line 120, `dnb_admin_page()`

```php
echo '<div class="notice notice-info"><p>' . $_GET['msg'] . '</p></div>';
```

**Problem:** The `msg` value is printed unescaped. An attacker needs to get a logged-in admin to click a crafted link, which is why I rate it Low, but a script running in an admin session can do real damage.

**How I reproduced it:** As an Administrator, I opened the admin page with a script tag in `msg`. It appeared unescaped in the page source.

**Fix:** `echo esc_html( sanitize_text_field( wp_unslash( $_GET['msg'] ) ) );`

## 4. Retest after fixes

I applied every fix above to a second copy of the plugin (version 1.0.1) and ran the same checks again on a fresh install with the same four roles. All eight checks were blocked.

| # | Version 1.0.0 | Version 1.0.1 |
|---|---|---|
| 1 | Exploitable | Blocked |
| 2a | Exploitable | Blocked |
| 2b | Exploitable | Blocked |
| 3 | Exploitable | Blocked |
| 4 | Exploitable | Blocked |
| 5 | Exploitable | Blocked |
| 6 | Exploitable | Blocked |
| 7 | Exploitable | Blocked |

The fixed version and the exact check script are in the repository next to this report, so you can run them yourself.

## 5. Limits of this review

- This is a point-in-time review of one version of the code. It is not a guarantee that a plugin has no vulnerabilities and it is not a certification.
- I tested on a local install with the roles listed above. I do not test anyone's live website.
- Third-party libraries, JavaScript build steps and anything outside the files you send me are out of scope unless we agree otherwise.
- Fixing the issues is up to you. I'm happy to recheck your fixes once, as part of the review price, if you send me the updated version within 30 days.

## 6. How a review works

1. You email me the plugin (a zip or a private repo link).
2. I confirm what is in scope and the price for your plugin's size.
3. I review it and send you a report like this one.
4. I send a PayPal invoice after you have the report. There is nothing to pay up front.

Contact: bryanbyfield0@gmail.com
