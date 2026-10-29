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
 * mailed to the account's existing address; it is bound to the session that opens it.
 */
final class Recovery_Token {

	public const QUERY_ARG = 'aiwos-recovery';

	/**
	 * Array{hash: string, expires: int, actor: int}.
	 */
	public const META = '_aiwos_two_factor_recovery';

	public const TTL = DAY_IN_SECONDS;

	/**
	 * Session key set once the link was opened in this session.
	 */
	private const SESSION_KEY = 'aiwos-two-factor-recovery';

	/**
	 * Put the account in recovery and return the plain token (only ever mailed).
	 *
	 * @param WP_User $user  Account.
	 * @param WP_User $actor Staff member.
	 */
	public static function issue( WP_User $user, WP_User $actor ): string {
		$token = bin2hex( random_bytes( 32 ) );
		update_user_meta(
			$user->ID,
			self::META,
			array(
				'hash'    => self::hash( $token ),
				'expires' => time() + self::TTL,
				'actor'   => $actor->ID,
			)
		);
		return $token;
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
		return is_array( get_user_meta( $user_id, self::META, true ) );
	}

	/**
	 * Whether the recovery link expired.
	 *
	 * @param int $user_id User ID.
	 */
	public static function is_expired( int $user_id ): bool {
		$state = get_user_meta( $user_id, self::META, true );
		return is_array( $state ) && (int) ( $state['expires'] ?? 0 ) < time();
	}

	/**
	 * Check a token for the current user and bind it to the current session. Single use:
	 * the stored hash is removed, so the link cannot be opened in a second session.
	 *
	 * @param string $token Token from the link.
	 */
	public static function redeem( string $token ): bool {
		$user_id = get_current_user_id();
		$state   = get_user_meta( $user_id, self::META, true );
		if ( ! is_array( $state ) || empty( $state['hash'] ) || self::is_expired( $user_id ) || ! hash_equals( (string) $state['hash'], self::hash( $token ) ) ) {
			return false;
		}

		$used         = $state;
		$used['hash'] = '';
		// Conditional update on the old value: of two parallel requests only one succeeds.
		if ( ! update_user_meta( $user_id, self::META, $used, $state ) ) {
			return false;
		}
		Two_Factor_Core::update_current_user_session( array( self::SESSION_KEY => time() ) );
		return true;
	}

	/**
	 * Whether the current session may enroll despite a pending recovery.
	 */
	public static function session_may_enroll(): bool {
		$user_id = get_current_user_id();
		if ( ! self::is_pending( $user_id ) ) {
			return true;
		}
		if ( self::is_expired( $user_id ) ) {
			return false;
		}
		$session = WP_Session_Tokens::get_instance( $user_id )->get( wp_get_session_token() );
		return ! empty( $session[ self::SESSION_KEY ] );
	}

	/**
	 * End the recovery after a new app was linked.
	 *
	 * @param int $user_id User ID.
	 */
	public static function complete( int $user_id ): void {
		delete_user_meta( $user_id, self::META );
	}

	/**
	 * Keyed hash, so a database read alone does not reveal a usable token.
	 *
	 * @param string $token Plain token.
	 */
	private static function hash( string $token ): string {
		return hash_hmac( 'sha256', $token, wp_salt( 'auth' ) );
	}
}
