<?php
/**
 * Live-WordPress tests for Aiwos Two Factor.
 *
 * Run inside a host site with upstream Two Factor >= 0.17 and this plugin active:
 *   ddev wp eval-file web/app/plugins/aiwos-two-factor/tests/run.php
 * or everything (incl. disabled-provider runs): tests/run.sh.
 *
 * Creates throwaway users and removes them afterwards. Mails are captured, not sent.
 *
 * @package Aiwos\TwoFactor
 */

// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped, WordPress.WP.GlobalVariablesOverride.Prohibited, WordPress.Security.ValidatedSanitizedInput -- CLI test script.

use Aiwos\TwoFactor\Account;
use Aiwos\TwoFactor\Enforcer;
use Aiwos\TwoFactor\Enrollment;
use Aiwos\TwoFactor\Plugin;
use Aiwos\TwoFactor\Recovery_Token;
use Aiwos\TwoFactor\Setup_Page;
use Aiwos\TwoFactor\Staff_Reset;

require __DIR__ . '/bootstrap.php';

$check = 'aiwos_tf_check';

// POST payload for a form of the setup page.
$form = static function ( WP_User $user, string $action, array $extra = array() ): array {
	return array( '_aiwos_two_factor_nonce' => wp_create_nonce( 'aiwos-two-factor-' . $action . '-' . $user->ID ) ) + $extra;
};
// Code for the user's pending secret (rendering the page creates it).
$pending_code = static function ( WP_User $user ): string {
	do_shortcode( '[two-factor-set-totp]' );
	return Two_Factor_Totp::calc_totp( (string) Account::pending_secret( $user->ID ) );
};

try {
	// Bootstrap.
	$check( 'fork 0.13.0.2 and 0.16 are rejected', ! Plugin::is_supported_version( '0.13.0.2' ) && ! Plugin::is_supported_version( '0.16.0' ) );
	$check( 'running Two Factor is supported', Plugin::is_supported() );
	$check( 'shortcodes registered', shortcode_exists( Enrollment::SHORTCODE ) && shortcode_exists( Staff_Reset::SHORTCODE ) );

	// Rendering and pending secret.
	wp_set_current_user( 0 );
	$check( 'nothing rendered for visitors', '' === trim( do_shortcode( '[two-factor-set-totp]' ) ) );
	$user = aiwos_tf_user( 'subscriber' );
	aiwos_tf_log_in( $user );
	$html    = do_shortcode( '[two-factor-set-totp]' );
	$pending = (string) Account::pending_secret( $user->ID );
	$check( 'setup form posts', str_contains( $html, '<form method="post" class="aiwos-two-factor"' ) );
	$check( 'pending secret kept server-side, not as form field', '' !== $pending && ! preg_match( '/<input[^>]+value="' . preg_quote( $pending, '/' ) . '"/', $html ) );
	$check( 'secret stable across renders', str_contains( do_shortcode( '[two-factor-set-totp]' ), $pending ) );
	update_user_meta( $user->ID, Account::PENDING_META, array( 'key' => $pending, 'created' => time() - Account::PENDING_TTL - 1 ) ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound
	$check( 'pending secret expires', null === Account::pending_secret( $user->ID ) && ! str_contains( do_shortcode( '[two-factor-set-totp]' ), $pending ) );

	// P6: exactly six digits.
	$code = $pending_code( $user );
	foreach ( array(
		''                    => 'empty',
		substr( $code, 0, 1 ) => 'one digit',
		substr( $code, 0, 5 ) => 'five digits',
		$code . '0'           => 'seven digits',
		'abcdef'              => 'letters',
	) as $bad => $label ) {
		$check( "code rejected: $label", 'invalid_code' === Enrollment::process( $user, 'enroll', $form( $user, 'enroll', array( 'authcode' => (string) $bad ) ) ) );
	}
	$check( 'bad nonce rejected', 'invalid_nonce' === Enrollment::process( $user, 'enroll', array( '_aiwos_two_factor_nonce' => 'x', 'authcode' => $code ) ) ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound
	$check( 'unknown action rejected', 'invalid_nonce' === Enrollment::process( $user, 'delete', $form( $user, 'delete' ) ) );
	$check( 'rejections leave user without 2FA', ! Two_Factor_Core::is_user_using_two_factor( $user->ID ) );

	// Enrollment.
	$other_token = WP_Session_Tokens::get_instance( $user->ID )->create( time() + HOUR_IN_SECONDS );
	$pending     = (string) Account::pending_secret( $user->ID );
	$check(
		'code with spaces accepted',
		'enrolled' === Enrollment::process(
			$user,
			'enroll',
			$form(
				$user,
				'enroll',
				array(
					'authcode' => chunk_split( Two_Factor_Totp::calc_totp( $pending ), 3, ' ' ),
					'user_id'  => 1,
				)
			)
		)
	);
	$check( 'authenticator linked and primary', Account::has_authenticator( $user->ID ) && 'Two_Factor_Totp' === Two_Factor_Core::get_primary_provider_for_user( $user->ID )->get_key() );
	$check( 'enrollment code recorded as used', ! Two_Factor_Core::get_providers()['Two_Factor_Totp']->validate_code_for_user( $user, Two_Factor_Totp::calc_totp( $pending ) ) );
	$check( 'session marked two-factor, other sessions logged out', Two_Factor_Core::is_current_user_session_two_factor() && null === WP_Session_Tokens::get_instance( $user->ID )->get( $other_token ) );
	$check( 'enrollment mailed', 1 === count( aiwos_tf_mails_to( $user ) ) );
	$check( 'linked user sees no setup form', ! str_contains( do_shortcode( '[two-factor-set-totp]' ), 'name="authcode"' ) );

	// Recovery codes.
	$codes = Enrollment::process_recovery_codes( $user, $form( $user, 'recovery_codes' ) );
	$check( 'ten recovery codes', 10 === count( $codes ) && in_array( 'Two_Factor_Backup_Codes', Two_Factor_Core::get_enabled_providers_for_user( $user->ID ), true ) );
	$backup = Two_Factor_Core::get_providers()['Two_Factor_Backup_Codes'];
	$check( 'recovery code works once', $backup->validate_code( $user, $codes[0] ) && ! $backup->validate_code( $user, $codes[0] ) );
	aiwos_tf_log_in( $user );
	$check( 'recovery codes need a recent 2FA proof', array() === Enrollment::process_recovery_codes( $user, $form( $user, 'recovery_codes' ) ) );
	$gone = aiwos_tf_log_in( $user, 'Two_Factor_Totp' );
	WP_Session_Tokens::get_instance( $user->ID )->destroy( $gone );
	$check( 'recovery codes refused for a session that was logged out meanwhile', array() === Enrollment::process_recovery_codes( $user, $form( $user, 'recovery_codes' ) ) );

	// P5 / A2 / A3: replace the app after logging in with a recovery code.
	aiwos_tf_log_in( $user, 'Two_Factor_Backup_Codes' );
	$old_key = (string) get_user_meta( $user->ID, '_two_factor_totp_key', true );
	$check( 'replace starts after recovery-code login', 'replace_started' === Enrollment::process( $user, 'replace', $form( $user, 'replace' ) ) );
	$check( 'old app keeps working while replacing', Account::has_authenticator( $user->ID ) && get_user_meta( $user->ID, '_two_factor_totp_key', true ) === $old_key );
	$check( 'cancel keeps the old app', 'cancelled' === Enrollment::process( $user, 'cancel', $form( $user, 'cancel' ) ) && null === Account::pending_secret( $user->ID ) && Account::has_authenticator( $user->ID ) );
	Enrollment::process( $user, 'replace', $form( $user, 'replace' ) );
	$html = do_shortcode( '[two-factor-set-totp]' );
	$check( 'replacement shows setup form with cancel', str_contains( $html, 'name="authcode"' ) && str_contains( $html, 'aiwos-two-factor__cancel' ) );
	$new_key = (string) Account::pending_secret( $user->ID );
	$check( 'replacement with wrong code keeps old app', 'invalid_code' === Enrollment::process( $user, 'enroll', $form( $user, 'enroll', array( 'authcode' => Two_Factor_Totp::calc_totp( $old_key ) ) ) ) && get_user_meta( $user->ID, '_two_factor_totp_key', true ) === $old_key );
	$check( 'replacement with new code succeeds', 'replaced' === Enrollment::process( $user, 'enroll', $form( $user, 'enroll', array( 'authcode' => Two_Factor_Totp::calc_totp( $new_key ) ) ) ) );
	$check( 'old app replaced, old recovery codes invalid', get_user_meta( $user->ID, '_two_factor_totp_key', true ) === $new_key && ! $backup->validate_code( $user, $codes[1] ) && ! in_array( 'Two_Factor_Backup_Codes', Two_Factor_Core::get_enabled_providers_for_user( $user->ID ), true ) );
	aiwos_tf_log_in( $user );
	$check( 'replace needs a recent 2FA proof', 'revalidate' === Enrollment::process( $user, 'replace', $form( $user, 'replace' ) ) );

	// P3: a stored secret with TOTP switched off is not a linked app.
	$retained = aiwos_tf_user( 'subscriber' );
	$old      = aiwos_tf_link_app( $retained );
	update_user_meta( $retained->ID, '_two_factor_enabled_providers', array() );
	aiwos_tf_log_in( $retained );
	$check( 'retained secret: not linked, must enroll', ! Account::has_authenticator( $retained->ID ) && Enforcer::must_enroll( $retained ) );
	$check( 'retained secret: setup form shown', str_contains( do_shortcode( '[two-factor-set-totp]' ), 'name="authcode"' ) );
	$check( 'retained secret: old secret is not reactivated', 'invalid_code' === Enrollment::process( $retained, 'enroll', $form( $retained, 'enroll', array( 'authcode' => Two_Factor_Totp::calc_totp( $old ) ) ) ) );
	$check( 'retained secret: fresh enrollment replaces it', 'enrolled' === Enrollment::process( $retained, 'enroll', $form( $retained, 'enroll', array( 'authcode' => $pending_code( $retained ) ) ) ) && get_user_meta( $retained->ID, '_two_factor_totp_key', true ) !== $old );
	$email_user = aiwos_tf_user( 'subscriber' );
	aiwos_tf_link_app( $email_user );
	update_user_meta( $email_user->ID, '_two_factor_enabled_providers', array( 'Two_Factor_Email' ) );
	aiwos_tf_log_in( $email_user );
	$check( 'other method + retained secret: revalidation required', 'revalidate' === Enrollment::process( $email_user, 'enroll', $form( $email_user, 'enroll', array( 'authcode' => '123456' ) ) ) && str_contains( do_shortcode( '[two-factor-set-totp]' ), 'aiwos-two-factor__revalidate' ) );

	// P4: gates.
	$fresh = aiwos_tf_user( 'subscriber' );
	aiwos_tf_log_in( $fresh );
	$check( 'must enroll; administrators not exempt', Enforcer::must_enroll( $fresh ) && Enforcer::must_enroll( aiwos_tf_user( 'administrator' ) ) );
	$opt_out = static fn() => false;
	add_filter( Enforcer::CONDITION_FILTER, $opt_out );
	$check( 'condition filter exempts', ! Enforcer::must_enroll( $fresh ) );
	remove_filter( Enforcer::CONDITION_FILTER, $opt_out );
	$check( 'REST blocked for user without 2FA', is_wp_error( Enforcer::guard_rest( null ) ) && 403 === Enforcer::guard_rest( null )->get_error_data()['status'] );
	$check( 'REST keeps earlier errors', 'earlier' === Enforcer::guard_rest( new WP_Error( 'earlier' ) )->get_error_code() );
	aiwos_tf_link_app( $fresh );
	$check( 'password-only session of a 2FA user must revalidate', Enforcer::must_revalidate() && is_wp_error( Enforcer::guard_rest( null ) ) );
	aiwos_tf_log_in( $fresh, 'Two_Factor_Totp' );
	$check( '2FA session passes', ! Enforcer::must_revalidate() && null === Enforcer::guard_rest( null ) );
	$check(
		'XML-RPC login of user without 2FA blocked',
		( static function () {
			$u = aiwos_tf_user( 'subscriber' );
			define( 'XMLRPC_REQUEST', true );
			return is_wp_error( Enforcer::guard_xmlrpc( $u ) );
		} )()
	);

	// B1: staff reset authorisation. Like mijn-afk, the site limits which roles managers assign.
	$limit_roles = static fn( $roles ) => array_diff_key( $roles, array( 'administrator' => true ) );
	add_filter( 'editable_roles', $limit_roles );
	$manager     = aiwos_tf_user( 'subscriber', array( 'edit_users', 'list_users', Staff_Reset::CAP ) );
	$target      = aiwos_tf_user( 'subscriber' );
	aiwos_tf_link_app( $target );
	aiwos_tf_log_in( aiwos_tf_user( 'subscriber', array( 'edit_users' ) ), 'Two_Factor_Totp' );
	$check( 'edit_users without the capability: not allowed', 'not_allowed' === Staff_Reset::check( $target ) );
	aiwos_tf_log_in( $manager );
	$check( 'manager without own 2FA: told to set it up', 'own_2fa_required' === Staff_Reset::check( $target ) );
	aiwos_tf_link_app( $manager );
	aiwos_tf_log_in( $manager );
	$check( 'manager with 2FA but password-only session: revalidate', 'revalidate' === Staff_Reset::check( $target ) );
	aiwos_tf_log_in( $manager, 'Two_Factor_Totp' );
	$check( 'manager with recent 2FA: allowed for a regular user', '' === Staff_Reset::check( $target ) );
	Two_Factor_Core::update_current_user_session( array( 'two-factor-login' => time() - 11 * MINUTE_IN_SECONDS ) );
	$check( 'staff proof older than 10 minutes: revalidate', 'revalidate' === Staff_Reset::check( $target ) );
	aiwos_tf_log_in( $manager, 'Two_Factor_Totp' );
	$check( 'manager cannot reset self, administrators or other managers', 'self' === Staff_Reset::check( $manager ) && 'not_allowed' === Staff_Reset::check( aiwos_tf_user( 'administrator' ) ) && 'not_allowed' === Staff_Reset::check( aiwos_tf_user( 'subscriber', array( Staff_Reset::CAP ) ) ) );
	$deny = static fn() => false;
	add_filter( 'aiwos/two-factor/can-reset', $deny );
	$check( 'can-reset filter has the final say', 'not_allowed' === Staff_Reset::check( $target ) );
	remove_filter( 'aiwos/two-factor/can-reset', $deny );
	$admin = aiwos_tf_user( 'administrator' );
	aiwos_tf_link_app( $admin );
	aiwos_tf_log_in( $admin, 'Two_Factor_Totp' );
	$check( 'administrator gets the capability and may reset a manager', current_user_can( Staff_Reset::CAP ) && '' === Staff_Reset::check( $manager ) );

	// B3: staff reset puts the account in recovery.
	aiwos_tf_log_in( $manager, 'Two_Factor_Totp' );
	$target_token = WP_Session_Tokens::get_instance( $target->ID )->create( time() + HOUR_IN_SECONDS );
	WP_Application_Passwords::create_new_application_password( $target->ID, array( 'name' => 'aftf-test' ) );
	add_action(
		'aiwos/two-factor/recovery-started',
		static function ( $t, $a, $r ) {
			$GLOBALS['aiwos_tf_test']['actions'][] = array( $t->ID, $a->ID, $r );
		},
		10,
		3
	);
	$check( 'reason is required', 'reason_required' === Staff_Reset::start_recovery( $target, '  ', false ) );
	$mails_before = count( aiwos_tf_mails_to( $target ) );
	wp_set_password( 'Old-known-pass-1!', $target->ID );
	$check( 'recovery started', 'started' === Staff_Reset::start_recovery( $target, 'Called back on known number', true ) );
	$check( 'target logged out, app passwords revoked', null === WP_Session_Tokens::get_instance( $target->ID )->get( $target_token ) && array() === WP_Application_Passwords::get_user_application_passwords( $target->ID ) );
	$check( 'target 2FA removed', ! Two_Factor_Core::is_user_using_two_factor( $target->ID ) && '' === get_user_meta( $target->ID, '_two_factor_totp_key', true ) );
	$check( 'audit hook gets target, actor, reason', array( $target->ID, $manager->ID, 'Called back on known number' ) === end( $GLOBALS['aiwos_tf_test']['actions'] ) );
	$sent = array_slice( aiwos_tf_mails_to( $target ), $mails_before );
	$check( 'recovery link and password reset mailed', 2 === count( $sent ) && preg_match( '/' . Recovery_Token::QUERY_ARG . '=([0-9a-f]{64})/', (string) $sent[0]['message'], $m ) );
	$token = $m[1] ?? '';
	$check( 'token not stored in plain text', ! str_contains( (string) wp_json_encode( get_user_meta( $target->ID, Recovery_Token::META, true ) ), $token ) );

	// B3: the password alone cannot claim the account.
	aiwos_tf_log_in( $target );
	$check( 'password-only: must enroll but setup is locked', Enforcer::must_enroll( $target ) && ! Recovery_Token::session_may_enroll() && ! str_contains( do_shortcode( '[two-factor-set-totp]' ), 'name="authcode"' ) );
	$check( 'password-only: enrolling refused', 'recovery_required' === Enrollment::process( $target, 'enroll', $form( $target, 'enroll', array( 'authcode' => '123456' ) ) ) );
	add_filter( Enforcer::CONDITION_FILTER, $opt_out );
	$check( 'pending recovery is never exempt', Enforcer::must_enroll( $target ) );
	remove_filter( Enforcer::CONDITION_FILTER, $opt_out );
	$check( 'replace and cancel refused before the link', 'recovery_required' === Enrollment::process( $target, 'replace', $form( $target, 'replace' ) ) && 'recovery_required' === Enrollment::process( $target, 'cancel', $form( $target, 'cancel' ) ) );
	$link_page = static function () use ( $token ): string {
		$_GET[ Recovery_Token::QUERY_ARG ] = $token;
		$html                              = do_shortcode( '[two-factor-set-totp]' );
		unset( $_GET[ Recovery_Token::QUERY_ARG ] );
		return $html;
	};
	$html      = $link_page();
	$check( 'compromised password: link page asks for a new password first', str_contains( $html, esc_url( wp_lostpassword_url() ) ) && ! str_contains( $html, 'aiwos-two-factor__redeem' ) && ! str_contains( $html, 'name="authcode"' ) );
	$check( 'wrong token refused', 'recovery_invalid' === Enrollment::process( $target, 'redeem', $form( $target, 'redeem', array( 'token' => str_repeat( '0', 64 ) ) ) ) );
	$check( 'redeem needs a nonce', 'invalid_nonce' === Enrollment::process( $target, 'redeem', array( 'token' => $token ) ) );
	$check( 'compromised password: link refused and not used up until the password changed', 'password_first' === Enrollment::process( $target, 'redeem', $form( $target, 'redeem', array( 'token' => $token ) ) ) && Recovery_Token::needs_new_password( $target->ID ) );
	wp_set_password( 'Old-known-pass-1!', $target->ID );
	$check( 'a hash upgrade (same password stored again) does not count as a reset', Recovery_Token::needs_new_password( $target->ID ) );
	$_POST['pass1'] = 'Old-known-pass-1!';
	$errors         = new WP_Error();
	do_action( 'validate_password_reset', $errors, get_userdata( $target->ID ) );
	unset( $_POST['pass1'] );
	$check( 'resetting to the same password is refused', in_array( 'aiwos_two_factor_same_password', $errors->get_error_codes(), true ) );
	reset_password( get_userdata( $target->ID ), 'Unvalidated-pass-3!' . wp_generate_password( 8 ) );
	$check( 'a password write that did not go through the reset form does not count', Recovery_Token::needs_new_password( $target->ID ) );
	$new_pass       = 'New-pass-2!' . wp_generate_password( 8 );
	$_POST['pass1'] = $new_pass;
	$errors         = new WP_Error();
	do_action( 'validate_password_reset', $errors, get_userdata( $target->ID ) );
	unset( $_POST['pass1'] );
	reset_password( get_userdata( $target->ID ), $new_pass );
	$check( 'a real password reset (form + new password) meets the requirement', ! $errors->has_errors() && ! Recovery_Token::needs_new_password( $target->ID ) );
	aiwos_tf_log_in( get_userdata( $target->ID ) );
	$html = $link_page();
	$check( 'after a new password the link page shows a confirm button, not the setup form', str_contains( $html, 'aiwos-two-factor__redeem' ) && ! str_contains( $html, 'name="authcode"' ) );
	$check( 'after a new password the link works, once', 'recovery_ok' === Enrollment::process( $target, 'redeem', $form( $target, 'redeem', array( 'token' => $token ) ) ) && 'invalid' === Recovery_Token::redeem( $token ) );
	$check( 'session with the link may enroll', Recovery_Token::session_may_enroll() );
	$link_code  = $pending_code( $target );
	$link_token = wp_get_session_token();
	$sessions   = WP_Session_Tokens::get_instance( $target->ID );
	$saved      = $sessions->get( $link_token );
	$sessions->destroy( $link_token );
	$check( 'enrollment from a session that a reset logged out is refused', 'recovery_required' === Enrollment::process( $target, 'enroll', $form( $target, 'enroll', array( 'authcode' => $link_code ) ) ) );
	$sessions->update( $link_token, $saved );
	$partial_code = $pending_code( $target );
	$no_enable    = static fn( $check, $id, $key ) => '_two_factor_enabled_providers' === $key ? false : $check;
	add_filter( 'update_user_metadata', $no_enable, 10, 3 );
	$partial      = Enrollment::process( $target, 'enroll', $form( $target, 'enroll', array( 'authcode' => $partial_code ) ) );
	remove_filter( 'update_user_metadata', $no_enable, 10 );
	$check( 'partial write: error, recovery and pending secret stay', 'error' === $partial && Recovery_Token::is_pending( $target->ID ) && null !== Account::pending_secret( $target->ID ) );
	delete_user_meta( $target->ID, '_two_factor_totp_last_successful_login' );
	$check( 'enrollment completes the recovery', 'enrolled' === Enrollment::process( $target, 'enroll', $form( $target, 'enroll', array( 'authcode' => $pending_code( $target ) ) ) ) && ! Recovery_Token::is_pending( $target->ID ) );
	aiwos_tf_log_in( $manager, 'Two_Factor_Totp' );
	Staff_Reset::start_recovery( $target, 'Expiry test', false );
	$state            = get_user_meta( $target->ID, Recovery_Token::META, true );
	$state['expires'] = time() - 1;
	update_user_meta( $target->ID, Recovery_Token::META, $state );
	aiwos_tf_log_in( $target );
	$check( 'expired recovery cannot be redeemed', Recovery_Token::is_expired( $target->ID ) && ! Recovery_Token::session_may_enroll() );

	// a link of an earlier recovery never unlocks a later one; finishing never ends a newer one.
	$gen_target = aiwos_tf_user( 'subscriber' );
	aiwos_tf_log_in( $manager, 'Two_Factor_Totp' );
	Staff_Reset::start_recovery( $gen_target, 'Generation test A', false );
	$old_id = Recovery_Token::current_id( $gen_target->ID );
	aiwos_tf_log_in( $manager, 'Two_Factor_Totp' );
	Staff_Reset::start_recovery( $gen_target, 'Generation test B', false );
	$new_id = Recovery_Token::current_id( $gen_target->ID );
	aiwos_tf_log_in( $gen_target );
	Two_Factor_Core::update_current_user_session( array( 'aiwos-two-factor-recovery' => $old_id ) );
	$check( 'session bound to an older recovery may not enroll', $old_id !== $new_id && ! Recovery_Token::session_may_enroll() );
	Recovery_Token::complete( $gen_target->ID, (string) $old_id );
	$check( 'completing an older recovery leaves the newer one', $new_id === Recovery_Token::current_id( $gen_target->ID ) );

	// account managers only recover accounts whose roles they may assign.
	aiwos_tf_log_in( $manager, 'Two_Factor_Totp' );
	$plain   = aiwos_tf_user( 'subscriber' );
	$no_subs = static fn( $roles ) => array_diff_key( $roles, array( 'subscriber' => true ) );
	$allowed = Staff_Reset::check( $plain );
	add_filter( 'editable_roles', $no_subs );
	$refused = Staff_Reset::check( $plain );
	remove_filter( 'editable_roles', $no_subs );
	$check( 'manager scope follows editable_roles', '' === $allowed && 'not_allowed' === $refused );
	$unlimited = static fn() => wp_roles()->roles;
	add_filter( 'editable_roles', $unlimited, PHP_INT_MAX );
	$check( 'site that does not limit editable_roles: managers have no scope', 'not_allowed' === Staff_Reset::check( $plain ) );
	remove_filter( 'editable_roles', $unlimited, PHP_INT_MAX );
	$special = aiwos_tf_user( 'subscriber', array( 'approve_grants' ) );
	$check( 'individual capability the manager lacks blocks the reset', 'not_allowed' === Staff_Reset::check( $special ) );

	// Recovery state that cannot be stored: nothing is cleared.
	$keep     = aiwos_tf_user( 'subscriber' );
	$keep_key = aiwos_tf_link_app( $keep );
	$no_store = static fn( $check, $id, $key ) => Recovery_Token::META === $key ? false : $check;
	add_filter( 'update_user_metadata', $no_store, 10, 3 );
	$status   = Staff_Reset::start_recovery( $keep, 'Store failure test', false );
	remove_filter( 'update_user_metadata', $no_store, 10 );
	$check( 'recovery not stored: reset aborts and 2FA stays', 'error' === $status && get_user_meta( $keep->ID, '_two_factor_totp_key', true ) === $keep_key );

	// password-only help keeps 2FA.
	$pw_only = aiwos_tf_user( 'subscriber' );
	$pw_app  = aiwos_tf_link_app( $pw_only );
	$before  = count( aiwos_tf_mails_to( $pw_only ) );
	$check( 'password-only mail sent, 2FA kept', 'password_sent' === Staff_Reset::send_password_reset( $pw_only, 'Forgot password, called back' ) && Account::has_authenticator( $pw_only->ID ) && get_user_meta( $pw_only->ID, '_two_factor_totp_key', true ) === $pw_app && count( aiwos_tf_mails_to( $pw_only ) ) === $before + 1 );
	$check( 'password-only needs a reason', 'reason_required' === Staff_Reset::send_password_reset( $pw_only, '' ) );

	// upstream's own paths cannot change another user's 2FA.
	$check( 'upstream REST: other account refused, own allowed', ! Two_Factor_Core::rest_api_can_edit_user_and_update_two_factor_options( $pw_only->ID ) && Two_Factor_Core::rest_api_can_edit_user_and_update_two_factor_options( $manager->ID ) );
	aiwos_tf_log_in( $admin, 'Two_Factor_Totp' );
	$codes_request = new WP_REST_Request( 'POST', '/' . Two_Factor_Core::REST_NAMESPACE . '/generate-backup-codes' );
	$codes_request->set_body_params( array( 'user_id' => $pw_only->ID ) );
	$codes_response = rest_do_request( $codes_request );
	$check( 'administrator cannot generate another user\'s recovery codes', $codes_response->is_error() && empty( $codes_response->get_data()['codes'] ) );
	$check( 'upstream settings removed from other users\' profiles', false === has_action( 'edit_user_profile', array( Two_Factor_Core::class, 'user_two_factor_options' ) ) && false === has_action( 'edit_user_profile_update', array( Two_Factor_Core::class, 'user_two_factor_options_update' ) ) );

	// the REST guard through the real filter chain (registration and order), with a control.
	$rest_admin = aiwos_tf_user( 'administrator' );
	aiwos_tf_log_in( $rest_admin );
	$blocked = apply_filters( 'rest_authentication_errors', null );
	aiwos_tf_link_app( $rest_admin );
	aiwos_tf_log_in( $rest_admin, 'Two_Factor_Totp' );
	$control = apply_filters( 'rest_authentication_errors', null );
	$check( 'REST filter chain: user without 2FA gets our error', is_wp_error( $blocked ) && 'aiwos_two_factor_required' === $blocked->get_error_code() );
	$check( 'REST filter chain: 2FA session passes (control)', ! is_wp_error( $control ) );

	// a logged-in request without a session token fails closed.
	unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	$check( 'no session token: must revalidate', Enforcer::must_revalidate() );
	do_action( 'application_password_did_authenticate', $rest_admin, null );
	$check( 'application password: left to upstream\'s API policy', ! Enforcer::must_revalidate() );

	// A1: password reset keeps 2FA and ends old sessions.
	$pw_user = aiwos_tf_user( 'subscriber' );
	$pw_key  = aiwos_tf_link_app( $pw_user );
	aiwos_tf_log_in( $pw_user, 'Two_Factor_Totp' );
	$cookie = $_COOKIE[ LOGGED_IN_COOKIE ];
	reset_password( $pw_user, wp_generate_password( 24 ) );
	clean_user_cache( $pw_user->ID );
	$check( 'password reset keeps the app', Account::has_authenticator( $pw_user->ID ) && get_user_meta( $pw_user->ID, '_two_factor_totp_key', true ) === $pw_key );
	$check( 'password reset ends old browser logins', false === wp_validate_auth_cookie( $cookie, 'logged_in' ) );

	// Setup page fallback.
	$real_page = Setup_Page::page();
	if ( $real_page ) {
		wp_update_post( array( 'ID' => $real_page->ID, 'post_status' => 'draft' ) ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound
	}
	$_SERVER['REQUEST_URI'] = '/2FA/?aiwos-2fa=enrolled';
	$_GET                   = array( 'aiwos-2fa' => 'enrolled' );
	$check( 'fallback /2fa/ recognised (case, status param)', home_url( '/2fa/' ) === Setup_Page::url() && Setup_Page::is_current() );
	$_SERVER['REQUEST_URI'] = '/2fa/?p=1';
	$_GET                   = array( 'p' => '1' );
	$check( 'other query variables on /2fa/ are not the setup page', ! Setup_Page::is_current() );
	$_GET                   = array();
	$_SERVER['REQUEST_URI'] = '/2fa-other/';
	$check( 'other paths are not the setup page', ! Setup_Page::is_current() );
	if ( $real_page ) {
		wp_update_post( array( 'ID' => $real_page->ID, 'post_status' => 'publish' ) ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound
		$check( 'real page with the shortcode wins', get_permalink( $real_page ) === Setup_Page::url() );
		$_SERVER['REQUEST_URI'] = (string) wp_parse_url( get_permalink( $real_page ), PHP_URL_PATH );
		$check( 'real page recognised by path', Setup_Page::is_current() );
	}
} finally {
	aiwos_tf_finish();
}
