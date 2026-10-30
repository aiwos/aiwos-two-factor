#!/usr/bin/env bash
# Real HTTP checks of the enforcement boundary, with curl. Runs in CI against @wordpress/env
# and locally against a DDEV copy. Creates a throwaway user and removes it afterwards.
#   BASE_URL=http://localhost:8888 WP="npx wp-env run cli wp" tests/http.sh
#   BASE_URL=https://<site>.ddev.site WP="ddev wp" tests/http.sh
set -u
BASE_URL=${BASE_URL:?set BASE_URL}
WP=${WP:-ddev wp}
# WordPress location below BASE_URL: '' (default) or e.g. /wp on Bedrock.
WP_DIR=${WP_DIR:-}
LOGIN_PATH="$WP_DIR/wp-login.php"
AJAX_PATH="$WP_DIR/wp-admin/admin-ajax.php"
ADMIN_PATH="$WP_DIR/wp-admin/"
USER=aftf_http_$RANDOM
PASS="Http-pass-$RANDOM-$RANDOM!"
JAR=$(mktemp)
failures=0
curl_() { curl -sk --max-time 30 "$@"; }
check() { if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1 -- expected $3, got $2"; failures=$((failures + 1)); fi; }
cleanup() { $WP user delete "$USER" --yes >/dev/null 2>&1; rm -f "$JAR"; }
trap cleanup EXIT

$WP user create "$USER" "$USER@example.invalid" --role=administrator --user_pass="$PASS" >/dev/null 2>&1
APP=$($WP user application-password create "$USER" http --porcelain 2>/dev/null | tail -1 | tr -d '\r')

# Controls: the site works for visitors.
check 'visitor gets the home page' "$(curl_ -o /dev/null -w '%{http_code}' "$BASE_URL/")" 200

# Application password, real REST request: our error, not a generic 401/403.
body=$(curl_ -u "$USER:$APP" "$BASE_URL/?rest_route=/wp/v2/users/me")
check 'REST with application password, user without 2FA: 2FA error' "$(printf '%s' "$body" | grep -o '"code":"[a-z_]*"' | head -1)" '"code":"aiwos_two_factor_required"'

# Cookie login with the password.
curl_ -c "$JAR" -b "$JAR" -o /dev/null "$BASE_URL$LOGIN_PATH"
curl_ -c "$JAR" -b "$JAR" -o /dev/null --data-urlencode "log=$USER" --data-urlencode "pwd=$PASS" -d 'wp-submit=Log+In&testcookie=1' "$BASE_URL$LOGIN_PATH"
check 'password login sets the logged-in cookie' "$(grep -q 'wordpress_logged_in' "$JAR" && echo yes)" yes

home=$(curl_ -b "$JAR" -o /dev/null -w '%{http_code} %{redirect_url}' "$BASE_URL/")
check 'home redirects to the setup page' "$(printf '%s' "$home" | grep -cE '^30[23] .*(2fa|aiwos-two-factor-setup)')" 1
fake=$(curl_ -b "$JAR" -o /dev/null -w '%{http_code} %{redirect_url}' "$BASE_URL/?rest_route=0")
check 'GET ?rest_route=0 (not REST) is guarded' "$(printf '%s' "$fake" | grep -cE '^30[23] .*(2fa|aiwos-two-factor-setup)')" 1
check 'POST ?rest_route=0 (not REST) is refused' "$(curl_ -b "$JAR" -o /dev/null -w '%{http_code}' -d 'gform_submit=1' "$BASE_URL/?rest_route=0")" 403
check 'POST to a page is refused' "$(curl_ -b "$JAR" -o /dev/null -w '%{http_code}' -d 'probe=1' "$BASE_URL/")" 403
check 'admin-ajax is refused' "$(curl_ -b "$JAR" -o /dev/null -w '%{http_code}' -d 'action=heartbeat' "$BASE_URL$AJAX_PATH")" 403
admin=$(curl_ -b "$JAR" -o /dev/null -w '%{http_code} %{redirect_url}' "$BASE_URL$ADMIN_PATH")
check 'wp-admin redirects to the setup page' "$(printf '%s' "$admin" | grep -cE '^30[23] .*(2fa|aiwos-two-factor-setup)')" 1
setup=$(curl_ -b "$JAR" -o /dev/null -w '%{http_code}' -L "$BASE_URL/")
check 'setup page itself loads' "$setup" 200

# A user with 2FA and a session marked as 2FA-proven (done server-side, as a 2FA login would):
# with the logged-in cookie admin-ajax works (control); with only the auth cookie it must not.
ID=$($WP user get "$USER" --field=ID 2>/dev/null | tail -1 | tr -d '\r')
$WP user meta update "$USER" _two_factor_totp_key "$($WP eval 'echo Two_Factor_Totp::generate_key();' 2>/dev/null | tail -1 | tr -d '\r')" >/dev/null 2>&1
$WP user meta update "$USER" _two_factor_enabled_providers '["Two_Factor_Totp"]' --format=json >/dev/null 2>&1
# The logged-in cookie can be set for two paths (e.g. / and /wp/ on Bedrock): same token, take one.
TOKEN=$(grep 'wordpress_logged_in' "$JAR" | head -1 | awk '{print $7}' | sed 's/%7C/|/g' | cut -d'|' -f3)
stamped=$($WP eval "\$m = WP_Session_Tokens::get_instance( $ID ); \$s = \$m->get( '$TOKEN' ); if ( \$s ) { \$s['two-factor-login'] = time(); \$m->update( '$TOKEN', \$s ); echo 'stamped'; }" 2>/dev/null | tail -1 | tr -d '\r')
check 'session marked as 2FA-proven (test setup)' "$stamped" stamped
check '2FA session with both cookies: admin-ajax works (control)' "$(curl_ -b "$JAR" -o /dev/null -w '%{http_code}' -d 'action=heartbeat' "$BASE_URL$AJAX_PATH")" 200
grep -v 'wordpress_logged_in' "$JAR" > "$JAR.auth"
check 'only the auth cookie: admin-ajax refused (fails closed)' "$(curl_ -b "$JAR.auth" -o /dev/null -w '%{http_code}' -d 'action=heartbeat' "$BASE_URL$AJAX_PATH")" 403
rm -f "$JAR.auth"

echo
echo "$failures failed"
exit $(( failures > 0 ))
