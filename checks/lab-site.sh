#!/bin/bash
# Fresh, localhost-only WP on 127.0.0.1:8099 for the demo plugin. Usage: lab-site.sh <plugin-dir-name: demo-notes-board|demo-notes-board-fixed>
set -e
LAB=/workspace/venture/lab; SR=/workspace/venture/security-reviews; export PATH=$LAB/bin:$PATH
SITE=$SR/lab-site
pkill -f "php -S 127.0.0.1:8099" 2>/dev/null || true
rm -rf $SITE; mkdir -p $SITE; cd $SITE
unzip -q $LAB/wp.zip; mv wordpress/* .; rmdir wordpress
unzip -q $LAB/sqlite.zip -d wp-content/plugins/
cp wp-content/plugins/sqlite-database-integration/db.copy wp-content/db.php
sed -i "s#{SQLITE_IMPLEMENTATION_FOLDER_PATH}#$SITE/wp-content/plugins/sqlite-database-integration#; s#{SQLITE_PLUGIN}#sqlite-database-integration/load.php#" wp-content/db.php
wp config create --dbname=wp --dbuser=x --dbpass=x --dbhost=localhost --skip-check --quiet
wp core install --url=http://127.0.0.1:8099 --title=Lab --admin_user=admin --admin_password=adminpass --admin_email=admin@lab.local --skip-email --quiet
wp user create sub sub@lab.local --role=subscriber --user_pass=subpass --quiet
wp user create contrib contrib@lab.local --role=contributor --user_pass=contribpass --quiet
cp -r $SR/demo-plugin/$1 wp-content/plugins/$1
wp plugin activate $1 --quiet
cat > router.php <<'R'
<?php $p=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH); if($p!=='/' && file_exists(__DIR__.$p) && !is_dir(__DIR__.$p)) return false; $_SERVER['SCRIPT_NAME']='/index.php'; require __DIR__.'/index.php';
R
nohup php -S 127.0.0.1:8099 router.php > $SR/lab-server.log 2>&1 &
sleep 1; echo "up: http://127.0.0.1:8099 with $1"
