<?php
/**
 * Frontend authenticator setup, replacement and recovery codes on top of upstream Two Factor.
 *
 * @package Aiwos\TwoFactor
 */

namespace Aiwos\TwoFactor;

use Two_Factor_Backup_Codes;
use Two_Factor_Core;
use Two_Factor_Totp;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Plain POST forms, deliberately not upstream's REST/JS flow: our sites lock the REST API
 * down for non-admins. Secrets are generated and kept server-side until a code proves them.
 * Every change by a user who already has 2FA needs a recent second-factor proof.
 */
final class Enrollment {

	/**
	 * Shortcode name kept identical to the old fork so existing pages keep working.
	 */
	public const SHORTCODE = 'two-factor-set-totp';

	public const STATUS_PARAM = 'aiwos-2fa';

	private const NONCE_FIELD  = '_aiwos_two_factor_nonce';
	private const ACTION_FIELD = 'aiwos_two_factor_action';
	private const ACTIONS      = array( 'enroll', 'replace', 'cancel', 'recovery_codes', 'redeem' );

	/**
	 * Recovery codes generated in this request; shown once, never stored in plain text.
	 *
	 * @var string[]
	 */
	private static array $fresh_codes = array();

	/**
	 * Register shortcode and form handling.
	 */
	public static function register(): void {
		if ( ! shortcode_exists( self::SHORTCODE ) ) {
			add_shortcode( self::SHORTCODE, array( self::class, 'render' ) );
		}
		add_action( 'template_redirect', array( self::class, 'handle_request' ), 0 );
	}

	/**
	 * On the setup page: no caching, redeem a recovery link, process a submitted form.
	 */
	public static function handle_request(): void {
		$on_setup_page = Setup_Page::is_current();
		if ( ! $on_setup_page && ( ! is_singular() || ! has_shortcode( (string) get_post_field( 'post_content', get_queried_object_id() ), self::SHORTCODE ) ) ) {
			return;
		}
		View::no_cache();
		$url = $on_setup_page ? Setup_Page::url() : (string) get_permalink( get_queried_object_id() );

		// phpcs:disable WordPress.Security.NonceVerification -- forms are verified in process().
		if ( isset( $_GET[ Recovery_Token::QUERY_ARG ] ) && ! is_user_logged_in() ) {
			// Log in first, without carrying the token into the login URL; the user then opens the link again.
			wp_safe_redirect( wp_login_url( $url ) );
			exit;
		}

		if ( ! is_user_logged_in() || ! isset( $_POST[ self::ACTION_FIELD ] ) ) {
			return;
		}
		$action = sanitize_key( wp_unslash( $_POST[ self::ACTION_FIELD ] ) );
		$input  = wp_unslash( $_POST );
		// phpcs:enable

		if ( 'recovery_codes' === $action ) {
			// Shown once in this response; a redirect would have to store them.
			self::$fresh_codes = self::process_recovery_codes( wp_get_current_user(), $input );
			return;
		}

		$status = self::process( wp_get_current_user(), $action, $input );
		wp_safe_redirect( add_query_arg( self::STATUS_PARAM, $status, $url ) );
		exit;
	}

	/**
	 * POST to the setup page by a user who still has to set up 2FA. Called by the Enforcer on
	 * wp_loaded, before any other plugin sees the request: only this plugin's forms are
	 * handled (always ending in a redirect); anything else is refused.
	 */
	public static function handle_gated_post(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in process().
		$action = isset( $_POST[ self::ACTION_FIELD ] ) ? sanitize_key( wp_unslash( $_POST[ self::ACTION_FIELD ] ) ) : '';
		if ( ! in_array( $action, array( 'enroll', 'redeem', 'replace', 'cancel' ), true ) ) {
			wp_die( esc_html__( 'Two-factor authentication is required. Set it up or confirm your code first.', 'aiwos-two-factor' ), '', array( 'response' => 403 ) );
		}
		View::no_cache();
		$status = self::process( wp_get_current_user(), $action, wp_unslash( $_POST ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in process().
		wp_safe_redirect( add_query_arg( self::STATUS_PARAM, $status, Setup_Page::url() ) );
		exit;
	}

	/**
	 * Handle a submitted form for the current user. Any user id in the input is ignored.
	 *
	 * @param WP_User              $user   Current user.
	 * @param string               $action enroll, replace or cancel.
	 * @param array<string, mixed> $input  Unslashed POST data.
	 * @return string Status code for the message shown afterwards.
	 */
	public static function process( WP_User $user, string $action, array $input ): string {
		if ( ! self::verify_nonce( $user, $action, $input ) ) {
			return 'invalid_nonce';
		}
		if ( 'redeem' === $action ) {
			$token = is_string( $input['token'] ?? null ) ? $input['token'] : '';
			return Recovery_Token::redeem( $token ) ? 'recovery_ok' : 'recovery_invalid';
		}
		// During a staff recovery nothing changes before the mailed link was opened in this session.
		if ( ! Recovery_Token::session_may_enroll() ) {
			return 'recovery_required';
		}
		switch ( $action ) {
			case 'enroll':
				return self::enroll( $user, $input );
			case 'replace':
				if ( ! Account::has_authenticator( $user->ID ) ) {
					return 'error';
				}
				if ( ! Account::has_recent_proof() ) {
					return 'revalidate';
				}
				// The current app keeps working until the new one is proven.
				Account::set_pending_secret( $user->ID, Two_Factor_Totp::generate_key() );
				return 'replace_started';
			case 'cancel':
				Account::clear_pending_secret( $user->ID );
				return 'cancelled';
		}
		return 'error';
	}

	/**
	 * Replace the user's recovery codes. Needs a recent 2FA proof, like every 2FA change.
	 *
	 * @param WP_User              $user  Current user.
	 * @param array<string, mixed> $input Unslashed POST data.
	 * @return string[] Plain codes, empty when not allowed.
	 */
	public static function process_recovery_codes( WP_User $user, array $input ): array {
		$backup = Two_Factor_Core::get_providers()[ Account::BACKUP_CODES ] ?? null;
		if ( ! self::verify_nonce( $user, 'recovery_codes', $input ) || ! $backup instanceof Two_Factor_Backup_Codes || ! Account::has_recent_proof() ) {
			return array();
		}
		$codes = $backup->generate_codes( $user, array( 'method' => 'replace' ) );
		Two_Factor_Core::enable_provider_for_user( $user->ID, Account::BACKUP_CODES );
		Notifier::inform( $user, __( 'New recovery codes created', 'aiwos-two-factor' ), __( 'New two-factor recovery codes were just created for your account. Older codes no longer work.', 'aiwos-two-factor' ) . ' ' . Notifier::not_you() );
		return $codes;
	}

	/**
	 * Prove the pending secret with a code from the app and make it the authenticator.
	 *
	 * @param WP_User              $user  Current user.
	 * @param array<string, mixed> $input Unslashed POST data.
	 */
	private static function enroll( WP_User $user, array $input ): string {
		if ( Two_Factor_Core::is_user_using_two_factor( $user->ID ) && ! Account::has_recent_proof() ) {
			return 'revalidate';
		}
		$key = Account::pending_secret( $user->ID );
		if ( null === $key || ! self::provider() ) {
			return 'expired';
		}
		$code = is_string( $input['authcode'] ?? null ) ? preg_replace( '/\s+/', '', $input['authcode'] ) : '';
		// Exactly six digits: upstream derives the length from the input, so "1" would pass.
		$tick = 1 === preg_match( '/^\d{6}$/', (string) $code ) ? Two_Factor_Totp::get_authcode_valid_ticktime( $key, $code ) : false;
		if ( false === $tick ) {
			return 'invalid_code';
		}

		$replacing  = Account::has_authenticator( $user->ID );
		$recovering = Recovery_Token::is_pending( $user->ID );
		Account::commit_authenticator( $user->ID, $key, (int) $tick, $replacing );
		Recovery_Token::complete( $user->ID );
		if ( $recovering ) {
			error_log( sprintf( '[aiwos-two-factor] staff recovery completed: user %d linked a new app', $user->ID ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- audit trail in the server log.
		}
		if ( get_current_user_id() === $user->ID ) {
			Account::secure_current_session();
		}

		$message = $replacing
			? __( 'A new authenticator app was just linked to your account. The old app and your old recovery codes no longer work.', 'aiwos-two-factor' )
			: __( 'An authenticator app was just linked to your account for two-factor authentication.', 'aiwos-two-factor' );
		if ( $recovering ) {
			$message .= ' ' . __( 'The recovery of your account is complete.', 'aiwos-two-factor' );
		}
		Notifier::inform( $user, __( 'Authenticator app linked', 'aiwos-two-factor' ), $message . ' ' . Notifier::not_you() );

		return $replacing ? 'replaced' : 'enrolled';
	}

	/**
	 * Shortcode callback.
	 */
	public static function render(): string {
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			return '';
		}
		$totp = self::provider();
		if ( ! $totp ) {
			return View::message( __( 'Authenticator apps are switched off on this site. Contact the site administrator.', 'aiwos-two-factor' ) );
		}
		// Also when rendered outside the setup page: the output can hold a secret.
		View::no_cache();
		$html = View::status_notice();

		if ( ! Recovery_Token::session_may_enroll() ) {
			if ( Recovery_Token::is_expired( $user->ID ) ) {
				return $html . View::message( __( 'Your recovery link has expired. Contact your account manager for a new one.', 'aiwos-two-factor' ) );
			}
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- only shown back in a POST form; redeemed after a nonce check.
			$token = isset( $_GET[ Recovery_Token::QUERY_ARG ] ) ? sanitize_text_field( wp_unslash( $_GET[ Recovery_Token::QUERY_ARG ] ) ) : '';
			if ( Recovery_Token::is_well_formed( $token ) ) {
				return $html . View::recovery_confirm( $token, self::nonce_action( $user, 'redeem' ), self::NONCE_FIELD, self::ACTION_FIELD );
			}
			return $html . View::message( __( 'Your two-factor authentication was reset. Open the link from the e-mail we sent you to link a new authenticator app.', 'aiwos-two-factor' ) );
		}

		$linked  = Account::has_authenticator( $user->ID );
		$proven  = Account::has_recent_proof();
		$pending = Account::pending_secret( $user->ID );

		if ( $linked && ! ( $pending && $proven ) ) {
			$html .= View::message( __( 'Your authenticator app is linked to your account.', 'aiwos-two-factor' ) );
			if ( ! $proven ) {
				return $html . View::revalidate( __( 'To change it or create recovery codes, confirm your current code first.', 'aiwos-two-factor' ) );
			}
			return $html . View::codes( self::$fresh_codes )
				. View::button( self::nonce_action( $user, 'replace' ), self::NONCE_FIELD, self::ACTION_FIELD, 'replace', __( 'Replace authenticator app', 'aiwos-two-factor' ) )
				. self::render_recovery_codes( $user );
		}

		if ( ! $linked && Two_Factor_Core::is_user_using_two_factor( $user->ID ) && ! $proven ) {
			return $html . View::revalidate( __( 'To link an authenticator app, confirm your current two-factor code first.', 'aiwos-two-factor' ) );
		}

		if ( null === $pending ) {
			$pending = Two_Factor_Totp::generate_key();
			Account::set_pending_secret( $user->ID, $pending );
		}
		$totp->enqueue_assets( '' );
		$html .= View::enroll_form( $user, $pending, self::nonce_action( $user, 'enroll' ), self::NONCE_FIELD, self::ACTION_FIELD );
		if ( $linked ) {
			$html .= View::button( self::nonce_action( $user, 'cancel' ), self::NONCE_FIELD, self::ACTION_FIELD, 'cancel', __( 'Cancel and keep the current app', 'aiwos-two-factor' ) );
		}
		return $html;
	}

	/**
	 * Recovery codes section for a user with a linked app and a recent proof.
	 *
	 * @param WP_User $user Current user.
	 */
	private static function render_recovery_codes( WP_User $user ): string {
		// Recovery codes can be switched off site-wide in Two Factor; its class is then not loaded.
		if ( self::$fresh_codes || ! class_exists( Two_Factor_Backup_Codes::class ) ) {
			return '';
		}
		$remaining = Two_Factor_Backup_Codes::codes_remaining_for_user( $user );
		$intro     = $remaining
			? sprintf(
				/* translators: %d: number of unused recovery codes. */
				_n( 'You have %d unused recovery code.', 'You have %d unused recovery codes.', $remaining, 'aiwos-two-factor' ),
				$remaining
			)
			: __( 'Create recovery codes, so you can still log in if you lose your phone.', 'aiwos-two-factor' );
		$label = $remaining ? __( 'Create new recovery codes', 'aiwos-two-factor' ) : __( 'Create recovery codes', 'aiwos-two-factor' );
		return View::message( $intro ) . View::button( self::nonce_action( $user, 'recovery_codes' ), self::NONCE_FIELD, self::ACTION_FIELD, 'recovery_codes', $label );
	}

	/**
	 * Upstream TOTP provider instance, if registered.
	 */
	private static function provider(): ?Two_Factor_Totp {
		$provider = Two_Factor_Core::get_providers()[ Account::TOTP ] ?? null;
		return $provider instanceof Two_Factor_Totp ? $provider : null;
	}

	/**
	 * Verify the user-bound nonce of a form.
	 *
	 * @param WP_User              $user   Current user.
	 * @param string               $action Form action.
	 * @param array<string, mixed> $input  Unslashed POST data.
	 */
	private static function verify_nonce( WP_User $user, string $action, array $input ): bool {
		$nonce = $input[ self::NONCE_FIELD ] ?? '';
		return in_array( $action, self::ACTIONS, true ) && is_string( $nonce ) && false !== wp_verify_nonce( $nonce, self::nonce_action( $user, $action ) );
	}

	/**
	 * Nonce action bound to the user and form.
	 *
	 * @param WP_User $user   User.
	 * @param string  $action Form action.
	 */
	private static function nonce_action( WP_User $user, string $action ): string {
		return 'aiwos-two-factor-' . $action . '-' . $user->ID;
	}
}
