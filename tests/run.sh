#!/usr/bin/env bash
# Runs all live-WordPress tests from the host site directory, e.g.:
#   cd /www/mijn-afk-nl-e2e && web/app/plugins/aiwos-two-factor/tests/run.sh
# WP (default "ddev wp") and DIR (plugin path relative to the site) can be overridden.
set -u
WP=${WP:-ddev wp}
DIR=${DIR:-web/app/plugins/aiwos-two-factor}
OPTION=two_factor_enabled_providers
status=0
quiet() { "$@" 2>&1 | grep -vE '^(Notice|Deprecated|Warning):'; return "${PIPESTATUS[0]}"; }

saved=$($WP option get "$OPTION" --format=json 2>/dev/null || echo "")
restore() {
	if [ -n "$saved" ]; then $WP option update "$OPTION" "$saved" --format=json >/dev/null; else $WP option delete "$OPTION" >/dev/null 2>&1; fi
}
trap restore EXIT

$WP option delete "$OPTION" >/dev/null 2>&1
quiet $WP eval-file "$DIR/tests/run.php" || status=1

for providers in '["Two_Factor_Totp","Two_Factor_Email"]' '["Two_Factor_Email","Two_Factor_Backup_Codes"]'; do
	$WP option update "$OPTION" "$providers" --format=json >/dev/null
	quiet $WP eval-file "$DIR/tests/disabled-providers.php" || status=1
done

exit $status
