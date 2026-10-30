<?php
/**
 * Staff-assisted recovery: a single-use link that unlocks enrollment after a 2FA reset.
 *
 * @package Aiwos\TwoFactor
 */

namespace Aiwos\TwoFactor;

use Two_Factor_Core;
use WP_Session_Tokens;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * After a staff reset the account has no second factor. Without this, anyone who knows
 * the password could link their own app first. Enrollment therefore also needs the link
 * mailed to the account's existing address. Each recovery has its own id: the session that
 * used the link is bound to that id, so a link from an earlier recovery never unlocks a
 * later one, and finishing one recovery never ends a newer one.
 */
final class Recovery_Token {

	public const QUERY_ARG = 'aiwos-recovery';

	/**
	 * Array{id: string, hash: string, expires: int, actor: int, pw: string}; pw is '1' while a
	 * password reset is still required.
	 */
	public const META = '_aiwos_two_factor_recovery';

	public const TTL = DAY_IN_SECONDS;

	/**
	 * Session key holding the id of the recovery whose link was used in this session.
	 */
	private const SESSION_KEY = 'aiwos-two-factor-recovery';

	/**
	 * Register the password-reset hooks.
	 */
	public static function register(): void {
		add_action( 'after_password_reset', array( self::class, 'password_was_reset' ) );
		add_action( 'validate_password_reset', array( self::class, 'refuse_same_password' ), 10, 2 );
	}

	/**
	 * Put the account in recovery and return the plain token (only ever mailed).
	 *
	 * @param WP_User $user                    Account.
	 * @param WP_User $actor                   Staff member.
	 * @param bool    $require_password_change The link only works after the password was reset.
	 * @return string|null Token, or null when the recovery could not be stored (then nothing
	 *                     else may change).
	 */
	public static function issue( WP_User $user, WP_User $actor, bool $require_password_change ): ?string {
		$token  = bin2hex( random_bytes( 32 ) );
		$stored = update_user_meta(
			$user->ID,
			self::META,
			array(
				'id'      => bin2hex( random_bytes( 16 ) ),
				'hash'    => self::hash( $token ),
				'expires' => time() + self::TTL,
				'actor'   => $actor->ID,
				'pw'      => $require_password_change ? '1' : '',
			)
		);
		return $stored ? $token : null;
	}

	/**
	 * Whether a value has the shape of a token (64 hex characters).
	 *
	 * @param string $token Candidate.
	 */
	public static function is_well_formed( string $token ): bool {
		return 1 === preg_match( '/^[0-9a-f]{64}$/', $token );
	}

	/**
	 * Link that opens /2fa/ with the token.
	 *
	 * @param string $token Plain token.
	 */
	public static function url( string $token ): string {
		return add_query_arg( self::QUERY_ARG, $token, Setup_Page::url() );
	}

	/**
	 * Whether the account is waiting for staff-assisted recovery (expired or not).
	 *
	 * @param int $user_id User ID.
	 */
	public static function is_pending( int $user_id ): bool {
		return null !== self::state( $user_id );
	}

	/**
	 * Whether the recovery link expired.
	 *
	 * @param int $user_id User ID.
	 */
	public static function is_expired( int $user_id ): bool {
		$state = self::state( $user_id );
		return null !== $state && (int) $state['expires'] < time();
	}

	/**
	 * Whether the recovery waits for a password reset (staff marked the password as possibly
	 * compromised). Only a reset through the lost-password flow clears it; a hash upgrade at
	 * login keeps the same password and does not count.
	 *
	 * @param int $user_id User ID.
	 */
	public static function needs_new_password( int $user_id ): bool {
		$state = self::state( $user_id );
		return null !== $state && '1' === $state['pw'];
	}

	/**
	 * After a password reset: the password requirement of a pending recovery is met.
	 *
	 * @param mixed $user User (WP_User from core's after_password_reset).
	 */
	public static function password_was_reset( $user ): void {
		if ( ! $user instanceof WP_User ) {
			return;
		}
		Account::locked(
			$user->ID,
			static function () use ( $user ): void {
				$raw = get_user_meta( $user->ID, self::META, true );
				if ( is_array( $raw ) && '1' === ( $raw['pw'] ?? '' ) ) {
					$done       = $raw;
					$done['pw'] = '';
					update_user_meta( $user->ID, self::META, $done, $raw );
				}
			}
		);
	}

	/**
	 * A password that may be compromised cannot be "reset" to the same value.
	 *
	 * @param \WP_Error         $errors Errors so far.
	 * @param WP_User|\WP_Error $user   User of the reset key.
	 */
	public static function refuse_same_password( $errors, $user ): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput -- core's reset form; only compared with the stored hash.
		$new = isset( $_POST['pass1'] ) && is_string( $_POST['pass1'] ) ? wp_unslash( $_POST['pass1'] ) : '';
		if ( '' !== $new && $user instanceof WP_User && self::needs_new_password( $user->ID ) && wp_check_password( $new, $user->user_pass, $user->ID ) ) {
			$errors->add( 'aiwos_two_factor_same_password', __( 'Choose a different password than before.', 'aiwos-two-factor' ) );
		}
	}

	/**
	 * Use a token for the current user and bind its recovery to the current session.
	 * Single use: of two parallel requests only one succeeds.
	 *
	 * @param string $token Token from the link.
	 * @return string ok, password_first or invalid.
	 */
	public static function redeem( string $token ): string {
		$user_id = get_current_user_id();
		return (string) ( Account::locked( $user_id, static fn() => self::redeem_locked( $user_id, $token ) ) ?? 'invalid' );
	}

	/**
	 * Redeem under the account lock.
	 *
	 * @param int    $user_id User ID.
	 * @param string $token   Token from the link.
	 */
	private static function redeem_locked( int $user_id, string $token ): string {
		$state = self::state( $user_id );
		if ( null === $state || '' === $state['hash'] || self::is_expired( $user_id ) || ! hash_equals( $state['hash'], self::hash( $token ) ) ) {
			return 'invalid';
		}
		// Not used up: the user sets a new password first (which ends this session) and opens it then.
		if ( self::needs_new_password( $user_id ) ) {
			return 'password_first';
		}

		$used         = $state;
		$used['hash'] = '';
		// Conditional update on the old value: of two parallel requests only one succeeds.
		if ( ! update_user_meta( $user_id, self::META, $used, $state ) ) {
			return 'invalid';
		}
		Two_Factor_Core::update_current_user_session( array( self::SESSION_KEY => $state['id'] ) );
		return 'ok';
	}

	/**
	 * Whether the current session may enroll: no recovery pending, or the link of exactly
	 * this recovery was used in this session.
	 */
	public static function session_may_enroll(): bool {
		$user_id = get_current_user_id();
		$state   = self::state( $user_id );
		if ( null === $state ) {
			return true;
		}
		if ( self::is_expired( $user_id ) || self::needs_new_password( $user_id ) ) {
			return false;
		}
		$session = WP_Session_Tokens::get_instance( $user_id )->get( wp_get_session_token() );
		$bound   = is_array( $session ) ? (string) ( $session[ self::SESSION_KEY ] ?? '' ) : '';
		return '' !== $bound && hash_equals( $state['id'], $bound );
	}

	/**
	 * Id of the pending recovery, if any.
	 *
	 * @param int $user_id User ID.
	 */
	public static function current_id( int $user_id ): ?string {
		$state = self::state( $user_id );
		return null === $state ? null : $state['id'];
	}

	/**
	 * End the recovery with this id after a new app was linked; a newer recovery stays.
	 *
	 * @param int    $user_id User ID.
	 * @param string $id      Id of the recovery that was completed.
	 */
	public static function complete( int $user_id, string $id ): void {
		$raw = get_user_meta( $user_id, self::META, true );
		if ( is_array( $raw ) && hash_equals( (string) ( $raw['id'] ?? '' ), $id ) ) {
			// Deletes only the row with exactly this value.
			delete_user_meta( $user_id, self::META, $raw );
		}
	}

	/**
	 * The stored recovery, normalised; null when there is none.
	 *
	 * @param int $user_id User ID.
	 * @return array{id: string, hash: string, expires: int, actor: int, pw: string}|null
	 */
	private static function state( int $user_id ): ?array {
		$raw = get_user_meta( $user_id, self::META, true );
		if ( ! is_array( $raw ) || empty( $raw['id'] ) ) {
			return null;
		}
		return array(
			'id'      => (string) $raw['id'],
			'hash'    => (string) ( $raw['hash'] ?? '' ),
			'expires' => (int) ( $raw['expires'] ?? 0 ),
			'actor'   => (int) ( $raw['actor'] ?? 0 ),
			'pw'      => (string) ( $raw['pw'] ?? '' ),
		);
	}

	/**
	 * Keyed hash, so a database read alone does not reveal a usable token.
	 *
	 * @param string $value Value.
	 */
	private static function hash( string $value ): string {
		return hash_hmac( 'sha256', $value, wp_salt( 'auth' ) );
	}
}
