<?php
/**
 * Mandatory 2FA: redirect logged-in users without 2FA to the setup page.
 *
 * @package Aiwos\TwoFactor
 */

namespace Aiwos\TwoFactor;

use Two_Factor_Core;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Drop-in replacement for force-two-factor 1.0.x. Same filter, same /2fa/ URL, but it
 * covers every frontend template (not only singular views), recognises the setup page
 * by query instead of an exact REQUEST_URI, and works without a "2fa" page.
 */
final class Enforcer {

	/**
	 * Filter shared with force-two-factor; site plugins use it to exempt users.
	 * Return false to skip the redirect. Second argument: the WP_User.
	 */
	public const CONDITION_FILTER = 'aiwos/force-two-factor/force-2fa-condition';

	/**
	 * Register the frontend guard.
	 */
	public static function register(): void {
		add_action( 'template_redirect', array( self::class, 'maybe_redirect' ), 1 );
	}

	/**
	 * Whether a user must be sent to the setup page.
	 *
	 * @param WP_User $user          User.
	 * @param bool    $on_setup_page Whether the request is the setup page.
	 */
	public static function should_redirect( WP_User $user, bool $on_setup_page ): bool {
		if ( $on_setup_page || ! $user->exists() ) {
			return false;
		}
		if ( ! apply_filters( self::CONDITION_FILTER, true, $user ) ) {
			return false;
		}
		return ! Two_Factor_Core::is_user_using_two_factor( $user->ID );
	}

	/**
	 * Callback for template_redirect.
	 */
	public static function maybe_redirect(): void {
		if ( ! self::should_redirect( wp_get_current_user(), false ) || Setup_Page::is_current() ) {
			return;
		}

		nocache_headers();
		wp_safe_redirect( Setup_Page::url() );
		exit;
	}
}
