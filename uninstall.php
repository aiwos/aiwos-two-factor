<?php
/**
 * Remove this plugin's own data. Confirmed 2FA settings belong to Two Factor and stay, and so
 * does an open staff recovery: after a reinstall the password alone must still not be enough.
 *
 * @package Aiwos\TwoFactor
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

foreach ( array( '_aiwos_two_factor_pending', '_aiwos_two_factor_email_changed' ) as $aiwos_two_factor_meta_key ) {
	delete_metadata( 'user', 0, $aiwos_two_factor_meta_key, '', true );
}
