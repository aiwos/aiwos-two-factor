<?php
/**
 * Closes upstream Two Factor's own paths for changing another user's second factor.
 *
 * @package Aiwos\TwoFactor
 */

namespace Aiwos\TwoFactor;

use Two_Factor_Core;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Upstream lets anyone who may edit a user set that user's authenticator secret or
 * generate (and see) their recovery codes, via REST, the profile screen or settings
 * actions. Staff must never receive another user's credentials: the only way to touch
 * someone else's 2FA is Staff_Reset, with its checks, verification note and recovery link.
 */
final class Upstream_Guard {

	/**
	 * Register the guards. Runs after upstream registered its hooks (plugins_loaded 20).
	 */
	public static function register(): void {
		add_filter( 'two_factor_rest_api_can_edit_user', array( self::class, 'own_account_only' ), 10, 2 );
		remove_action( 'edit_user_profile', array( Two_Factor_Core::class, 'user_two_factor_options' ) );
		remove_action( 'edit_user_profile_update', array( Two_Factor_Core::class, 'user_two_factor_options_update' ) );
		add_action( 'edit_user_profile', array( self::class, 'render_profile_note' ) );
		add_action( 'admin_init', array( self::class, 'block_settings_actions_for_others' ), 0 );
		// Upstream's own REST writes (own account) run under the same account lock as a staff
		// recovery, so the two never interleave; the permission check runs inside the lock.
		add_filter( 'rest_request_before_callbacks', array( self::class, 'lock_upstream_write' ), 10, 3 );
		add_filter( 'rest_request_after_callbacks', array( self::class, 'unlock_upstream_write' ) );
	}

	/**
	 * Account whose lock this request holds, if any.
	 *
	 * @var int
	 */
	private static int $locked_user = 0;

	/**
	 * Before an upstream two-factor REST write: take the current user's account lock.
	 *
	 * @param mixed            $response Response so far.
	 * @param array<mixed>     $handler  Route handler.
	 * @param \WP_REST_Request $request  Request.
	 * @return mixed
	 */
	public static function lock_upstream_write( $response, $handler, $request ) {
		$user_id = get_current_user_id();
		if ( is_wp_error( $response ) || ! $user_id || 'GET' === $request->get_method() || ! str_starts_with( (string) $request->get_route(), '/' . Two_Factor_Core::REST_NAMESPACE . '/' ) ) {
			return $response;
		}
		if ( ! Account::lock( $user_id ) ) {
			return new \WP_Error( 'aiwos_two_factor_busy', __( 'Please try again.', 'aiwos-two-factor' ), array( 'status' => 503 ) );
		}
		self::$locked_user = $user_id;
		return $response;
	}

	/**
	 * After the callback: release the lock taken above.
	 *
	 * @param mixed $response Response.
	 * @return mixed
	 */
	public static function unlock_upstream_write( $response ) {
		if ( self::$locked_user ) {
			Account::unlock( self::$locked_user );
			self::$locked_user = 0;
		}
		return $response;
	}

	/**
	 * Upstream REST (TOTP setup and delete, recovery codes): own account only.
	 *
	 * @param bool $can_edit Upstream's decision.
	 * @param int  $user_id  Account being changed.
	 */
	public static function own_account_only( $can_edit, $user_id ): bool {
		return (bool) $can_edit && (int) $user_id === get_current_user_id();
	}

	/**
	 * Upstream settings actions (?two_factor_action=...) on another user's account.
	 */
	public static function block_settings_actions_for_others(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- only refuses; never acts.
		if ( empty( $_REQUEST[ Two_Factor_Core::USER_SETTINGS_ACTION_QUERY_VAR ] ) || empty( $_REQUEST['user_id'] ) ) {
			return;
		}
		$user_id = absint( $_REQUEST['user_id'] );
		// phpcs:enable
		if ( $user_id !== get_current_user_id() ) {
			wp_die( esc_html__( 'Another user\'s two-factor settings can only be reset, not changed.', 'aiwos-two-factor' ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * Replacement for upstream's settings on another user's profile.
	 *
	 * @param WP_User $user Profile being edited.
	 */
	public static function render_profile_note( WP_User $user ): void {
		printf(
			'<h2>%s</h2><p>%s</p>',
			esc_html__( 'Two-factor authentication', 'aiwos-two-factor' ),
			esc_html(
				Two_Factor_Core::is_user_using_two_factor( $user->ID )
					? __( 'Set up by the user. Only the user can change it; if they lost access, use "Reset two-factor" on Users.', 'aiwos-two-factor' )
					: __( 'Not set up yet. The user sets it up on their next login.', 'aiwos-two-factor' )
			)
		);
	}
}
