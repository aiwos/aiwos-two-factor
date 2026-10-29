<?php
/**
 * Two-factor state of an account, independent of which providers are loaded.
 *
 * @package Aiwos\TwoFactor
 */

namespace Aiwos\TwoFactor;

use Two_Factor_Core;
use WP_Application_Passwords;
use WP_Session_Tokens;

defined( 'ABSPATH' ) || exit;

/**
 * Upstream loads provider classes lazily and drops disabled ones, so everything here
 * works on literal meta keys and never needs Two_Factor_Totp or Two_Factor_Backup_Codes.
 */
final class Account {

	public const TOTP = 'Two_Factor_Totp';

	public const BACKUP_CODES = 'Two_Factor_Backup_Codes';

	/**
	 * Not yet confirmed secret: array{key: string, created: int}.
	 */
	public const PENDING_META = '_aiwos_two_factor_pending';

	/**
	 * Unconfirmed secrets expire, so an abandoned setup never lingers.
	 */
	public const PENDING_TTL = 30 * MINUTE_IN_SECONDS;

	/**
	 * Upstream meta that reset clears: secrets, recovery codes, login challenges and counters.
	 * Kept as literals so reset still works when a provider is disabled.
	 */
	private const TWO_FACTOR_META = array(
		'_two_factor_totp_key',
		'_two_factor_totp_last_successful_login',
		'_two_factor_backup_codes',
		'_two_factor_email_token',
		'_two_factor_email_token_timestamp',
		'_two_factor_sms_token',
		'_two_factor_enabled_providers',
		'_two_factor_provider',
		'_two_factor_nonce',
		'_two_factor_last_login_failure',
		'_two_factor_failed_login_attempts',
		'_two_factor_password_was_reset',
		'_two_factor_action_nonce',
	);

	/**
	 * Whether the user can log in with an authenticator app: TOTP enabled, configured and
	 * registered. A stored secret alone does not count (upstream keeps it when TOTP is off).
	 *
	 * @param int $user_id User ID.
	 */
	public static function has_authenticator( int $user_id ): bool {
		$available = Two_Factor_Core::get_available_providers_for_user( $user_id );
		return is_array( $available ) && isset( $available[ self::TOTP ] );
	}

	/**
	 * Whether the current user recently proved a second factor (any upstream provider,
	 * including a recovery code). Unlike the upstream helper this is false for users without 2FA.
	 *
	 * @param int $max_age Optional stricter limit in seconds than upstream's window.
	 */
	public static function has_recent_proof( int $max_age = 0 ): bool {
		if ( ! Two_Factor_Core::is_user_using_two_factor( get_current_user_id() ) || ! Two_Factor_Core::current_user_can_update_two_factor_options( 'save' ) ) {
			return false;
		}
		return 0 === $max_age || time() - (int) Two_Factor_Core::is_current_user_session_two_factor() <= $max_age;
	}

	/**
	 * Upstream's revalidation screen (on wp-login.php, so it works without wp-admin) that
	 * returns to $back instead of upstream's default, wp-admin.
	 *
	 * @param string $back URL to return to.
	 */
	public static function revalidate_url( string $back ): string {
		return add_query_arg( 'redirect_to', rawurlencode( $back ), Two_Factor_Core::get_user_two_factor_revalidate_url() );
	}

	/**
	 * The unexpired pending secret, if any.
	 *
	 * @param int $user_id User ID.
	 */
	public static function pending_secret( int $user_id ): ?string {
		$pending = get_user_meta( $user_id, self::PENDING_META, true );
		if ( ! is_array( $pending ) || empty( $pending['key'] ) || (int) ( $pending['created'] ?? 0 ) < time() - self::PENDING_TTL ) {
			return null;
		}
		return (string) $pending['key'];
	}

	/**
	 * Store a new pending secret.
	 *
	 * @param int    $user_id User ID.
	 * @param string $key     Base32 secret.
	 */
	public static function set_pending_secret( int $user_id, string $key ): void {
		update_user_meta(
			$user_id,
			self::PENDING_META,
			array(
				'key'     => $key,
				'created' => time(),
			)
		);
	}

	/**
	 * Remove the pending secret.
	 *
	 * @param int $user_id User ID.
	 */
	public static function clear_pending_secret( int $user_id ): void {
		delete_user_meta( $user_id, self::PENDING_META );
	}

	/**
	 * Make the authenticator app the user's only TOTP and primary method. Old recovery
	 * codes are invalidated when an existing app is replaced (the phone may be lost).
	 *
	 * @param int    $user_id   User ID.
	 * @param string $key       Proven secret.
	 * @param int    $tick      Time step of the code that proved it.
	 * @param bool   $replacing Whether an authenticator was already linked.
	 */
	public static function commit_authenticator( int $user_id, string $key, int $tick, bool $replacing ): void {
		$enabled = array_values( array_diff( (array) get_user_meta( $user_id, '_two_factor_enabled_providers', true ), array( '' ) ) );
		if ( $replacing ) {
			delete_user_meta( $user_id, '_two_factor_backup_codes' );
			$enabled = array_values( array_diff( $enabled, array( self::BACKUP_CODES ) ) );
		}
		$enabled[] = self::TOTP;

		update_user_meta( $user_id, '_two_factor_totp_key', $key );
		// Mark the code as used, so it cannot be replayed at the next login.
		update_user_meta( $user_id, '_two_factor_totp_last_successful_login', $tick );
		update_user_meta( $user_id, '_two_factor_enabled_providers', array_values( array_unique( $enabled ) ) );
		update_user_meta( $user_id, '_two_factor_provider', self::TOTP );
		self::clear_pending_secret( $user_id );
	}

	/**
	 * Log the user out everywhere and revoke all application passwords.
	 *
	 * @param int $user_id User ID.
	 */
	public static function revoke_access( int $user_id ): void {
		WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		WP_Application_Passwords::delete_all_application_passwords( $user_id );
	}

	/**
	 * Remove every second factor and pending login challenge of the user.
	 *
	 * @param int $user_id User ID.
	 */
	public static function clear_two_factor( int $user_id ): void {
		foreach ( self::TWO_FACTOR_META as $meta_key ) {
			delete_user_meta( $user_id, $meta_key );
		}
		self::clear_pending_secret( $user_id );
	}

	/**
	 * Mark the current session as proven by the authenticator and log out other sessions,
	 * which may have been opened with the password only.
	 */
	public static function secure_current_session(): void {
		Two_Factor_Core::update_current_user_session(
			array(
				'two-factor-provider' => self::TOTP,
				'two-factor-login'    => time(),
			)
		);
		wp_destroy_other_sessions();
	}
}
