<?php
/**
 * Remove unconfirmed secrets. Confirmed TOTP keys belong to Two Factor and stay.
 *
 * @package Aiwos\TwoFactor
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

delete_metadata( 'user', 0, '_aiwos_two_factor_pending_key', '', true );
