<?php
/**
 * Live-WordPress tests for Aiwos Frontend Two Factor.
 *
 * Run inside a host site with upstream Two Factor >= 0.17 active:
 *   ddev wp eval-file web/app/plugins/aiwos-two-factor/tests/run.php
 *
 * Creates throwaway users and removes them afterwards. Exits non-zero on failure.
 * The browser flow (redirects, real POST, login) lives in tests/e2e-enrollment.cjs.
 *
 * @package Aiwos\TwoFactor
 */

// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped, WordPress.WP.GlobalVariablesOverride.Prohibited -- CLI test script.

use Aiwos\TwoFactor\Enforcer;
use Aiwos\TwoFactor\Enrollment;
use Aiwos\TwoFactor\Plugin;
use Aiwos\TwoFactor\Recovery;
use Aiwos\TwoFactor\Setup_Page;

$failures = 0;
$checks   = 0;

$check = static function ( string $name, bool $ok ) use ( &$failures, &$checks ): void {
	++$checks;
	if ( ! $ok ) {
		++$failures;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . "\n";
};

$make_user = static function ( string $role ): int {
	$login = 'aftf_test_' . $role . '_' . wp_generate_password( 6, false );
	return (int) wp_insert_user(
		array(
			'user_login' => $login,
			'user_pass'  => wp_generate_password( 24 ),
			'user_email' => $login . '@example.invalid',
			'role'       => $role,
		)
	);
};

// Log the user in with a real session token, as process() stamps the current session.
$log_in = static function ( int $user_id ): void {
	wp_set_current_user( $user_id );
	$expiration                  = time() + HOUR_IN_SECONDS;
	$token                       = WP_Session_Tokens::get_instance( $user_id )->create( $expiration );
	$_COOKIE[ LOGGED_IN_COOKIE ] = wp_generate_auth_cookie( $user_id, $expiration, 'logged_in', $token );
};

// Render the form (creates the pending secret) and return a POST payload for it.
$form_input = static function ( int $user_id, ?string $code = null ): array {
	do_shortcode( '[two-factor-set-totp]' );
	$key = (string) get_user_meta( $user_id, Enrollment::PENDING_KEY_META, true );
	return array(
		'_aiwos_two_factor_nonce' => wp_create_nonce( 'aiwos-two-factor-enroll-' . $user_id ),
		'authcode'                => $code ?? ( $key ? Two_Factor_Totp::calc_totp( $key ) : '' ),
	);
};

$created = array();
$mails   = array();
add_filter(
	'pre_wp_mail',
	static function ( $short, $atts ) use ( &$mails ) {
		$mails[] = $atts;
		return true;
	},
	10,
	2
);
$totp_provider = Two_Factor_Core::get_providers()['Two_Factor_Totp'];

try {
	// Bootstrap / version gate.
	$check( 'plugin classes loaded', class_exists( Plugin::class ) );
	$check( 'fork 0.13.0.2 is rejected', ! Plugin::is_supported_version( '0.13.0.2' ) );
	$check( '0.16.0 is rejected', ! Plugin::is_supported_version( '0.16.0' ) );
	$check( '0.17.0 is accepted', Plugin::is_supported_version( '0.17.0' ) );
	$check( 'running Two Factor is supported', Plugin::is_supported() );
	$check( 'shortcode [two-factor-set-totp] registered', shortcode_exists( Enrollment::SHORTCODE ) );

	// Rendering.
	wp_set_current_user( 0 );
	$check( 'shortcode renders nothing for visitors', '' === trim( do_shortcode( '[two-factor-set-totp]' ) ) );

	$user_id   = $make_user( 'subscriber' );
	$created[] = $user_id;
	$log_in( $user_id );
	$html    = do_shortcode( '[two-factor-set-totp]' );
	$pending = (string) get_user_meta( $user_id, Enrollment::PENDING_KEY_META, true );
	$check( 'form posts with method=post', (bool) preg_match( '/<form method="post"/', $html ) );
	$check( 'pending secret stored server-side', '' !== $pending );
	$check( 'secret is not a form field', ! preg_match( '/<input[^>]+value="' . preg_quote( $pending, '/' ) . '"/', $html ) );
	$check( 'QR script enqueued', wp_script_is( 'two-factor-totp-qrcode', 'enqueued' ) );
	$check( 'secret is stable across renders', str_contains( do_shortcode( '[two-factor-set-totp]' ), $pending ) );

	// Enforcer decision.
	$user = get_userdata( $user_id );
	$check( 'unenrolled user is redirected', Enforcer::should_redirect( $user, false ) );
	$check( 'no redirect on the setup page itself', ! Enforcer::should_redirect( $user, true ) );
	$opt_out = static fn() => false;
	add_filter( Enforcer::CONDITION_FILTER, $opt_out );
	$check( 'legacy condition filter can opt out', ! Enforcer::should_redirect( $user, false ) );
	remove_filter( Enforcer::CONDITION_FILTER, $opt_out );

	$admin_id  = $make_user( 'administrator' );
	$created[] = $admin_id;
	$check( 'administrators are not exempt', Enforcer::should_redirect( get_userdata( $admin_id ), false ) );

	// Rejections change nothing.
	$input                            = $form_input( $user_id );
	$input['_aiwos_two_factor_nonce'] = 'bad';
	$array_input                      = $form_input( $user_id );
	$array_input['authcode']          = array( 'x' );
	$check( 'array authcode is rejected cleanly', 'invalid_code' === Enrollment::process( $user, $array_input ) );
	$check( 'bad nonce is rejected', 'invalid_nonce' === Enrollment::process( $user, $input ) );
	$wrong = '000000' === Two_Factor_Totp::calc_totp( $pending ) ? '111111' : '000000';
	$check( 'wrong code is rejected', 'invalid_code' === Enrollment::process( $user, $form_input( $user_id, $wrong ) ) );
	$check( 'rejections leave user unenrolled', ! Two_Factor_Core::is_user_using_two_factor( $user_id ) );

	// Valid enrollment.
	$input = $form_input( $user_id ) + array( 'user_id' => $admin_id );
	$check( 'valid code enrolls', 'enrolled' === Enrollment::process( $user, $input ) );
	$primary = Two_Factor_Core::get_primary_provider_for_user( $user_id );
	$check( 'TOTP is primary', $primary && 'Two_Factor_Totp' === $primary->get_key() );
	$check( 'confirmed key equals the pending key', get_user_meta( $user_id, '_two_factor_totp_key', true ) === $pending );
	$check( 'enrollment code recorded as used', (int) get_user_meta( $user_id, Two_Factor_Totp::LAST_SUCCESSFUL_LOGIN_META_KEY, true ) > 0 );
	$check( 'enrollment code cannot be replayed at login', ! $totp_provider->validate_code_for_user( get_userdata( $user_id ), Two_Factor_Totp::calc_totp( $pending ) ) );
	$check( 'pending secret removed', '' === get_user_meta( $user_id, Enrollment::PENDING_KEY_META, true ) );
	$check( 'session marked two-factor', Two_Factor_Core::is_current_user_session_two_factor() );
	$check( 'user_id in input is ignored', ! Two_Factor_Core::is_user_using_two_factor( $admin_id ) );
	$check( 'enrolled user is not redirected', ! Enforcer::should_redirect( get_userdata( $user_id ), false ) );
	$check( 'enrollment mails the user', 1 === count( array_filter( $mails, static fn( $m ) => $m['to'] === $user->user_email ) ) );
	$check( 'second submit does not overwrite', 'already' === Enrollment::process( $user, $form_input( $user_id, '123456' ) ) );
	$check( 'enrolled user sees no enrollment form', ! str_contains( do_shortcode( '[two-factor-set-totp]' ), 'name="authcode"' ) );

	// Recovery codes (session was stamped two-factor at enrollment).
	$recovery_input = array( '_aiwos_two_factor_recovery_nonce' => wp_create_nonce( 'aiwos-two-factor-recovery-' . $user_id ) );
	$check( 'recovery codes need a valid nonce', array() === Enrollment::process_recovery_codes( $user, array( '_aiwos_two_factor_recovery_nonce' => 'bad' ) ) );
	$codes = Enrollment::process_recovery_codes( $user, $recovery_input );
	$check( 'ten recovery codes generated', 10 === count( $codes ) );
	$check( 'recovery codes enabled as login method', in_array( Recovery::BACKUP_PROVIDER, Two_Factor_Core::get_enabled_providers_for_user( $user_id ), true ) );
	$check( 'TOTP stays primary after recovery codes', 'Two_Factor_Totp' === Two_Factor_Core::get_primary_provider_for_user( $user_id )->get_key() );
	$backup = Two_Factor_Core::get_providers()[ Recovery::BACKUP_PROVIDER ];
	$check( 'a recovery code logs in once', $backup->validate_code( $user, $codes[0] ) && ! $backup->validate_code( $user, $codes[0] ) );

	// Staff reset.
	wp_set_current_user( $admin_id );
	$check( 'reset link shown for another user', isset( Recovery::add_reset_link( array(), $user )['aiwos-reset-2fa'] ) );
	$check( 'no reset link for yourself', ! isset( Recovery::add_reset_link( array(), get_userdata( $admin_id ) )['aiwos-reset-2fa'] ) );
	$plain_id  = $make_user( 'subscriber' );
	$created[] = $plain_id;
	$check( 'no reset link for user without 2FA', ! isset( Recovery::add_reset_link( array(), get_userdata( $plain_id ) )['aiwos-reset-2fa'] ) );
	WP_Application_Passwords::create_new_application_password( $user_id, array( 'name' => 'aftf-test' ) );
	$editor_like = $make_user( 'subscriber' );
	$created[]   = $editor_like;
	get_userdata( $editor_like )->add_cap( 'edit_users' );
	wp_set_current_user( $editor_like );
	$check( 'user manager cannot reset an administrator', ! Recovery::can_reset( get_userdata( $admin_id ) ) );
	$check( 'user manager can reset a regular user', Recovery::can_reset( $user ) );
	wp_set_current_user( $admin_id );
	$mails_before = count( $mails );
	$codes_again  = Recovery::generate_codes( $user );
	$check( 'new recovery codes are mailed', count( $mails ) === $mails_before + 1 );
	Recovery::reset_user( $user );
	$check( 'reset revokes application passwords', array() === WP_Application_Passwords::get_user_application_passwords( $user_id ) );
	$check( 'reset removes 2FA', ! Two_Factor_Core::is_user_using_two_factor( $user_id ) && '' === get_user_meta( $user_id, '_two_factor_totp_key', true ) );
	$check( 'reset removes recovery codes', 0 === Two_Factor_Backup_Codes::codes_remaining_for_user( $user ) );
	$check( 'reset logs the user out everywhere', array() === WP_Session_Tokens::get_instance( $user_id )->get_all() );
	$check( 'reset user is sent to /2fa/ again', Enforcer::should_redirect( get_userdata( $user_id ), false ) );
	$subscriber_id = $make_user( 'subscriber' );
	$created[]     = $subscriber_id;
	wp_set_current_user( $subscriber_id );
	$check( 'subscriber gets no reset link', ! isset( Recovery::add_reset_link( array(), get_userdata( $admin_id ) )['aiwos-reset-2fa'] ) );

	// Setup page: built-in fallback when no "2fa" page exists.
	$real_page = Setup_Page::page();
	if ( $real_page ) {
		wp_update_post(
			array(
				'ID'          => $real_page->ID,
				'post_status' => 'draft',
			)
		);
	}
	$check( 'fallback setup URL is /2fa/', home_url( '/2fa/' ) === Setup_Page::url() );
	$_SERVER['REQUEST_URI'] = '/2fa/?utm=x';
	$check( 'fallback /2fa/ recognised with query string', Setup_Page::is_current() );
	$_SERVER['REQUEST_URI'] = '/2fa-other/';
	$check( 'other paths are not the setup page', ! Setup_Page::is_current() );
	if ( $real_page ) {
		wp_update_post(
			array(
				'ID'          => $real_page->ID,
				'post_status' => 'publish',
			)
		);
		$check( 'real page wins when published', get_permalink( $real_page ) === Setup_Page::url() );
	}

	// User on email codes without a recent 2FA login must revalidate first.
	$email_user = $make_user( 'subscriber' );
	$created[]  = $email_user;
	Two_Factor_Core::enable_provider_for_user( $email_user, 'Two_Factor_Email' );
	$log_in( $email_user );
	$check( 'email user without recent 2FA sees revalidate link', str_contains( do_shortcode( '[two-factor-set-totp]' ), 'aiwos-two-factor__revalidate' ) );
	$check( 'email user without recent 2FA cannot enroll', 'revalidate' === Enrollment::process( get_userdata( $email_user ), $form_input( $email_user ) ) );

	// Existing fork-made TOTP links keep working (same meta keys as upstream).
	$legacy    = $make_user( 'subscriber' );
	$created[] = $legacy;
	$key       = Two_Factor_Totp::generate_key();
	update_user_meta( $legacy, '_two_factor_totp_key', $key );
	update_user_meta( $legacy, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY, array( 'Two_Factor_Totp' ) );
	update_user_meta( $legacy, Two_Factor_Core::PROVIDER_USER_META_KEY, 'Two_Factor_Totp' );
	$check( 'fork-made TOTP link counts as enrolled', Two_Factor_Core::is_user_using_two_factor( $legacy ) );
	$check( 'fork-made TOTP key validates a fresh code', Two_Factor_Totp::is_valid_authcode( $key, Two_Factor_Totp::calc_totp( $key ) ) );
} finally {
	require_once ABSPATH . 'wp-admin/includes/user.php';
	foreach ( $created as $id ) {
		wp_delete_user( $id );
	}
	wp_set_current_user( 0 );
}

echo "\n{$checks} checks, {$failures} failed\n";
if ( $failures > 0 ) {
	exit( 1 );
}
