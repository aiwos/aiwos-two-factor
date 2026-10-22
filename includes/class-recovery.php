<?php
/**
 * Lost authenticator app: recovery codes, staff reset and notification mails.
 *
 * @package Aiwos\TwoFactor
 */

namespace Aiwos\TwoFactor;

use Two_Factor_Backup_Codes;
use Two_Factor_Core;
use Two_Factor_Totp;
use WP_Application_Passwords;
use WP_Session_Tokens;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Two ways back in after losing the app:
 * - the user signs in with a recovery code (upstream backup codes), then links a new app;
 * - staff with edit_user reset the user's 2FA from Users; the user then signs in with
 *   the password only and is sent to /2fa/ to link a new app.
 * Linking an app, new recovery codes and a reset are mailed to the user, so a misuse is noticed.
 */
final class Recovery {

	public const BACKUP_PROVIDER = 'Two_Factor_Backup_Codes';

	/**
	 * Return false to disable the notification mails.
	 */
	public const NOTIFY_FILTER = 'aiwos/two-factor/notify-user';

	private const RESET_ACTION = 'aiwos_two_factor_reset';

	/**
	 * Register the staff reset.
	 */
	public static function register(): void {
		add_filter( 'user_row_actions', array( self::class, 'add_reset_link' ), 10, 2 );
		add_action( 'admin_post_' . self::RESET_ACTION, array( self::class, 'handle_reset' ) );
		add_action( 'admin_notices', array( self::class, 'render_reset_notice' ) );
	}

	/**
	 * Replace the user's recovery codes and enable them as a login method.
	 *
	 * @param WP_User $user User.
	 * @return string[] Plain codes, to be shown once.
	 */
	public static function generate_codes( WP_User $user ): array {
		$providers = Two_Factor_Core::get_providers();
		$backup    = $providers[ self::BACKUP_PROVIDER ] ?? null;
		if ( ! $backup instanceof Two_Factor_Backup_Codes ) {
			return array();
		}

		$codes = $backup->generate_codes( $user, array( 'method' => 'replace' ) );
		Two_Factor_Core::enable_provider_for_user( $user->ID, self::BACKUP_PROVIDER );
		self::notify(
			$user,
			__( 'New recovery codes created', 'aiwos-two-factor' ),
			__( 'New two-factor recovery codes were just created for your account. Older codes no longer work. If this was not you, contact us right away.', 'aiwos-two-factor' )
		);
		return $codes;
	}

	/**
	 * Remove all 2FA for a user and log them out everywhere.
	 *
	 * @param WP_User $user User.
	 */
	public static function reset_user( WP_User $user ): void {
		delete_user_meta( $user->ID, Two_Factor_Totp::SECRET_META_KEY );
		delete_user_meta( $user->ID, Two_Factor_Totp::LAST_SUCCESSFUL_LOGIN_META_KEY );
		delete_user_meta( $user->ID, Two_Factor_Backup_Codes::BACKUP_CODES_META_KEY );
		delete_user_meta( $user->ID, Enrollment::PENDING_KEY_META );
		delete_user_meta( $user->ID, Two_Factor_Core::ENABLED_PROVIDERS_USER_META_KEY );
		delete_user_meta( $user->ID, Two_Factor_Core::PROVIDER_USER_META_KEY );
		// Login state of upstream: pending login nonce, rate limit and lockout counters.
		delete_user_meta( $user->ID, Two_Factor_Core::USER_META_NONCE_KEY );
		delete_user_meta( $user->ID, Two_Factor_Core::USER_RATE_LIMIT_KEY );
		delete_user_meta( $user->ID, Two_Factor_Core::USER_FAILED_LOGIN_ATTEMPTS_KEY );
		delete_user_meta( $user->ID, '_two_factor_email_token' );
		// A reset is an incident action: nothing that bypasses the login screen may survive.
		WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
		WP_Application_Passwords::delete_all_application_passwords( $user->ID );
	}

	/**
	 * Add "Reset two-factor" to a user's row on Users.
	 *
	 * @param array<string, string> $actions Row actions.
	 * @param WP_User               $user    Listed user.
	 * @return array<string, string>
	 */
	public static function add_reset_link( array $actions, WP_User $user ): array {
		if ( ! self::can_reset( $user ) || ! self::has_two_factor_data( $user ) ) {
			return $actions;
		}

		$url = wp_nonce_url(
			add_query_arg(
				array(
					'action'  => self::RESET_ACTION,
					'user_id' => $user->ID,
				),
				admin_url( 'admin-post.php' )
			),
			self::RESET_ACTION . '_' . $user->ID
		);

		$actions['aiwos-reset-2fa'] = sprintf(
			'<a href="%s" onclick="return confirm(%s);">%s</a>',
			esc_url( $url ),
			esc_attr( wp_json_encode( __( 'Reset two-factor authentication for this user? They will be logged out and must link a new authenticator app at their next login.', 'aiwos-two-factor' ) ) ),
			esc_html__( 'Reset two-factor', 'aiwos-two-factor' )
		);
		return $actions;
	}

	/**
	 * Handle the staff reset.
	 */
	public static function handle_reset(): void {
		$user_id = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- checked on the next line.
		check_admin_referer( self::RESET_ACTION . '_' . $user_id );

		$user = get_userdata( $user_id );
		if ( ! $user || ! self::can_reset( $user ) ) {
			wp_die( esc_html__( 'You are not allowed to reset two-factor authentication for this user.', 'aiwos-two-factor' ), '', array( 'response' => 403 ) );
		}

		self::reset_user( $user );
		$actor = wp_get_current_user();

		/**
		 * Fires after staff reset a user's two-factor authentication (audit trail).
		 *
		 * @param WP_User $user  User whose 2FA was reset.
		 * @param WP_User $actor User who did the reset.
		 */
		do_action( 'aiwos/two-factor/reset', $user, $actor ); // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores -- same convention as aiwos/force-two-factor/*.

		self::notify(
			$user,
			__( 'Two-factor authentication was reset', 'aiwos-two-factor' ),
			sprintf(
				/* translators: 1: name of the person who reset it, 2: date and time. */
				__( 'The two-factor authentication for your account was reset by %1$s on %2$s. At your next login you will be asked to link a new authenticator app. If you did not ask for this, contact us right away.', 'aiwos-two-factor' ),
				$actor->display_name,
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) )
			)
		);

		wp_safe_redirect( add_query_arg( 'aiwos-2fa-reset', 1, admin_url( 'users.php' ) ) );
		exit;
	}

	/**
	 * Confirmation after a reset.
	 */
	public static function render_reset_notice(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only.
		if ( empty( $_GET['aiwos-2fa-reset'] ) || 'users' !== get_current_screen()?->id ) {
			return;
		}
		printf(
			'<div class="notice notice-success is-dismissible"><p>%s</p></div>',
			esc_html__( 'Two-factor authentication was reset. The user has been logged out.', 'aiwos-two-factor' )
		);
	}

	/**
	 * Mail the user about a 2FA change on their account.
	 *
	 * @param WP_User $user    User.
	 * @param string  $subject Subject (site name is prefixed).
	 * @param string  $message Body.
	 */
	public static function notify( WP_User $user, string $subject, string $message ): void {
		if ( ! apply_filters( self::NOTIFY_FILTER, true, $user ) || ! is_email( $user->user_email ) ) {
			return;
		}
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		wp_mail( $user->user_email, sprintf( '[%s] %s', $site, $subject ), $message . "\n\n" . home_url( '/' ) );
	}

	/**
	 * Whether the current user may reset this user's 2FA: not their own, they may edit the
	 * user, and they hold every admin-level capability the target holds (no resetting up).
	 *
	 * @param WP_User $user Target user.
	 */
	public static function can_reset( WP_User $user ): bool {
		if ( get_current_user_id() === $user->ID || ! current_user_can( 'edit_user', $user->ID ) ) {
			return false;
		}
		foreach ( array( 'manage_options', 'promote_users', 'edit_users' ) as $cap ) {
			if ( user_can( $user, $cap ) && ! current_user_can( $cap ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Whether the user has anything to reset.
	 *
	 * @param WP_User $user User.
	 */
	private static function has_two_factor_data( WP_User $user ): bool {
		return '' !== (string) get_user_meta( $user->ID, Two_Factor_Totp::SECRET_META_KEY, true )
			|| Two_Factor_Core::is_user_using_two_factor( $user->ID );
	}
}
