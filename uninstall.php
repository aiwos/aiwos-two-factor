<?php
/**
 * Remove this plugin's own data. Confirmed 2FA settings belong to Two Factor and stay.
 *
 * @package Aiwos\TwoFactor
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

foreach ( array( '_aiwos_two_factor_pending', '_aiwos_two_factor_recovery' ) as $aiwos_two_factor_meta_key ) {
	delete_metadata( 'user', 0, $aiwos_two_factor_meta_key, '', true );
}
