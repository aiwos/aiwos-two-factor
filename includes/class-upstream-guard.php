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
