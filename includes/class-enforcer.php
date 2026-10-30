<?php
/**
 * Mandatory 2FA on every request type, not only frontend pages.
 *
 * @package Aiwos\TwoFactor
 */

namespace Aiwos\TwoFactor;

use Two_Factor_Core;
use WP_Error;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Two rules, applied to frontend pages, wp-admin, admin-ajax, admin-post, REST and XML-RPC:
 * - a user who must use 2FA but has none can only reach the setup page and wp-login.php
 *   (login, logout, lost password, revalidation);
 * - a user with 2FA whose browser session was not opened with it (a session from before
 *   2FA was set up) must confirm a code first.
 */
final class Enforcer {

	/**
	 * Filter shared with force-two-factor; site plugins use it to exempt users.
	 * Return false to exempt. Second argument: the WP_User (in XML-RPC logins the
	 * current user is not set yet).
	 */
	public const CONDITION_FILTER = 'aiwos/force-two-factor/force-2fa-condition';

	/**
	 * Register the gates.
	 */
	public static function register(): void {
		// Before parse_request and 'wp', where plugins such as Gravity Forms handle submissions.
		add_action( 'wp_loaded', array( self::class, 'guard_frontend' ), 0 );
		// Backstop: what WordPress actually serves must be the setup page.
		add_action( 'template_redirect', array( self::class, 'guard_query' ), 0 );
		add_action( 'admin_init', array( self::class, 'guard_admin' ), 1 );
		// After core's cookie and application-password checks.
		add_filter( 'rest_authentication_errors', array( self::class, 'guard_rest' ), 110 );
		add_filter( 'authenticate', array( self::class, 'guard_xmlrpc' ), 100 );
	}

	/**
	 * Whether the user has to set up 2FA before doing anything else.
	 *
	 * @param WP_User $user User.
	 */
	public static function must_enroll( WP_User $user ): bool {
		if ( ! $user->exists() ) {
			return false;
		}
		// A staff recovery is never exempt: otherwise the password alone could link an app.
		if ( Recovery_Token::is_pending( $user->ID ) ) {
			return true;
		}
		if ( ! apply_filters( self::CONDITION_FILTER, true, $user ) ) { // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores -- existing force-two-factor hook.
			return false;
		}
		return ! Two_Factor_Core::is_user_using_two_factor( $user->ID );
	}

	/**
	 * Whether the current browser session has to confirm a code first.
	 */
	public static function must_revalidate(): bool {
		return '' !== wp_get_session_token()
			&& Two_Factor_Core::is_user_using_two_factor( get_current_user_id() )
			&& ! Two_Factor_Core::is_current_user_session_two_factor();
	}

	/**
	 * Frontend requests: GET is sent to the setup page or the revalidation screen, anything
	 * else is refused. REST, AJAX, cron and XML-RPC have their own guards; wp-login.php stays
	 * open for login, logout, lost password and revalidation.
	 */
	public static function guard_frontend(): void {
		if (
			is_admin() || wp_doing_ajax() || wp_doing_cron() || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			|| 'wp-login.php' === ( $GLOBALS['pagenow'] ?? '' ) || self::is_rest_request() || ! is_user_logged_in()
		) {
			return;
		}
		$enroll = self::must_enroll( wp_get_current_user() );
		if ( ! $enroll && ! self::must_revalidate() ) {
			return;
		}
		$is_get = in_array( $_SERVER['REQUEST_METHOD'] ?? 'GET', array( 'GET', 'HEAD' ), true ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared against a whitelist.
		if ( Setup_Page::is_current() ) {
			if ( $is_get ) {
				return;
			}
			// A POST must never reach 'wp', where other plugins process submissions on any URL.
			if ( $enroll ) {
				Enrollment::handle_gated_post();
			}
			wp_die( esc_html( self::message() ), '', array( 'response' => 403 ) );
		}
		if ( ! $is_get ) {
			wp_die( esc_html( self::message() ), '', array( 'response' => 403 ) );
		}
		// Relative path of this request; upstream sanitises it and redirects with wp_safe_redirect.
		self::redirect( $enroll ? Setup_Page::url() : Account::revalidate_url( add_query_arg( array() ) ) );
	}

	/**
	 * After WordPress parsed the request: a user who must set up 2FA only gets the setup page.
	 */
	public static function guard_query(): void {
		$page = Setup_Page::page();
		if ( ! $page || ! is_user_logged_in() || ! self::must_enroll( wp_get_current_user() ) || is_page( $page->ID ) ) {
			return;
		}
		self::redirect( Setup_Page::url() );
	}

	/**
	 * Whether this is a REST request (decided before WordPress parses it).
	 */
	private static function is_rest_request(): bool {
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification.Recommended -- routing only, compared, never output.
		// Same rule as core: only a non-empty string makes WordPress serve REST.
		if ( isset( $_GET['rest_route'] ) && is_string( $_GET['rest_route'] ) && '' !== trim( $_GET['rest_route'] ) ) {
			return true;
		}
		if ( ! get_option( 'permalink_structure' ) ) {
			return false;
		}
		// Path only: a query string such as ?x=/wp-json/ must not skip this guard.
		$path = (string) wp_parse_url( (string) ( $_SERVER['REQUEST_URI'] ?? '' ), PHP_URL_PATH );
		// phpcs:enable
		$rest = (string) wp_parse_url( rest_url(), PHP_URL_PATH );
		return '/' !== $rest && '' !== $rest && str_starts_with( trailingslashit( $path ), $rest );
	}

	/**
	 * Wp-admin, admin-ajax and admin-post.
	 */
	public static function guard_admin(): void {
		if ( ! is_user_logged_in() ) {
			return;
		}
		$enroll = self::must_enroll( wp_get_current_user() );
		if ( ! $enroll && ! self::must_revalidate() ) {
			return;
		}
		if ( wp_doing_ajax() ) {
			wp_send_json_error( array( 'message' => self::message() ), 403 );
		}
		if ( 'admin-post.php' === ( $GLOBALS['pagenow'] ?? '' ) ) {
			wp_die( esc_html( self::message() ), '', array( 'response' => 403 ) );
		}
		self::redirect( $enroll ? Setup_Page::url() : Account::revalidate_url( admin_url() ) );
	}

	/**
	 * REST API (cookie and application-password logins).
	 *
	 * @param WP_Error|true|null $result Result of earlier checks.
	 * @return WP_Error|true|null
	 */
	public static function guard_rest( $result ) {
		if ( is_wp_error( $result ) || ! is_user_logged_in() ) {
			return $result;
		}
		if ( self::must_enroll( wp_get_current_user() ) || self::must_revalidate() ) {
			return new WP_Error( 'aiwos_two_factor_required', self::message(), array( 'status' => 403 ) );
		}
		return $result;
	}

	/**
	 * XML-RPC logins of users who must set up 2FA (upstream already blocks API logins of
	 * users who have 2FA).
	 *
	 * @param WP_User|WP_Error|null $user Authenticated user so far.
	 * @return WP_User|WP_Error|null
	 */
	public static function guard_xmlrpc( $user ) {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && $user instanceof WP_User && self::must_enroll( $user ) ) {
			return new WP_Error( 'aiwos_two_factor_required', self::message() );
		}
		return $user;
	}

	/**
	 * Error text for blocked requests.
	 */
	private static function message(): string {
		return __( 'Two-factor authentication is required. Set it up or confirm your code first.', 'aiwos-two-factor' );
	}

	/**
	 * Redirect without caching and stop.
	 *
	 * @param string $url Target.
	 */
	private static function redirect( string $url ): void {
		nocache_headers();
		wp_safe_redirect( $url );
		exit;
	}
}
