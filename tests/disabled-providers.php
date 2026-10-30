<?php
/**
 * Staff reset and the setup page while a provider is switched off site-wide (P2).
 * Must run in a fresh process with the option already set; see tests/run.sh.
 *
 * @package Aiwos\TwoFactor
 */

// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI test script.

use Aiwos\TwoFactor\Recovery_Token;
use Aiwos\TwoFactor\Staff_Reset;

require __DIR__ . '/bootstrap.php';

$enabled = (array) get_option( 'two_factor_enabled_providers', array() );
echo 'site providers: ' . implode( ',', $enabled ) . "\n";

try {
	foreach ( array( 'Two_Factor_Totp', 'Two_Factor_Backup_Codes' ) as $class ) {
		if ( ! in_array( $class, $enabled, true ) ) {
			aiwos_tf_check( "$class not registered", ! isset( Two_Factor_Core::get_providers()[ $class ] ) );
		}
	}

	$target = aiwos_tf_user( 'subscriber' );
	update_user_meta( $target->ID, '_two_factor_totp_key', 'JBSWY3DPEHPK3PXP' );
	update_user_meta( $target->ID, '_two_factor_backup_codes', array( wp_hash_password( '12345678' ) ) );
	update_user_meta( $target->ID, '_two_factor_enabled_providers', array( 'Two_Factor_Totp', 'Two_Factor_Backup_Codes', 'Two_Factor_Email' ) );
	$token = WP_Session_Tokens::get_instance( $target->ID )->create( time() + HOUR_IN_SECONDS );
	WP_Application_Passwords::create_new_application_password( $target->ID, array( 'name' => 'aftf-test' ) );

	$admin = aiwos_tf_user( 'administrator' );
	update_user_meta( $admin->ID, '_two_factor_enabled_providers', array( 'Two_Factor_Email' ) );
	aiwos_tf_log_in( $admin, 'Two_Factor_Email' );

	aiwos_tf_check( 'Users row action renders', isset( Staff_Reset::add_row_action( array(), $target )['aiwos-reset-2fa'] ) );
	aiwos_tf_check( 'reset completes', 'started' === Staff_Reset::start_recovery( $target, 'Disabled provider test', false ) );
	aiwos_tf_check( 'sessions and app passwords revoked', null === WP_Session_Tokens::get_instance( $target->ID )->get( $token ) && array() === WP_Application_Passwords::get_user_application_passwords( $target->ID ) );
	aiwos_tf_check( 'secret, codes and providers cleared', '' === get_user_meta( $target->ID, '_two_factor_totp_key', true ) && '' === get_user_meta( $target->ID, '_two_factor_backup_codes', true ) && '' === get_user_meta( $target->ID, '_two_factor_enabled_providers', true ) );
	aiwos_tf_check( 'recovery pending and mailed', Recovery_Token::is_pending( $target->ID ) && 1 === count( aiwos_tf_mails_to( $target ) ) );

	aiwos_tf_log_in( $target );
	aiwos_tf_check( 'setup page renders without fatal error', is_string( do_shortcode( '[two-factor-set-totp]' ) ) );
} finally {
	aiwos_tf_finish();
}
