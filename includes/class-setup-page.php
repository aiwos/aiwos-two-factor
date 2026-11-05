<?php
/**
 * The /2fa/ setup page: a real page with that slug, or a built-in fallback.
 *
 * @package Aiwos\TwoFactor
 */

namespace Aiwos\TwoFactor;

use WP_Post;

defined( 'ABSPATH' ) || exit;

/**
 * Sites can style the page themselves by creating a page with slug "2fa" holding the
 * shortcode. Without one, /2fa/ is served by the plugin, so enforcement never depends
 * on a page existing.
 */
final class Setup_Page {

	public const SLUG = '2fa';

	/**
	 * Query variable of the built-in page on sites without pretty permalinks.
	 */
	public const FALLBACK_ARG = 'aiwos-two-factor-setup';

	/**
	 * Cached result of page(); false = not looked up yet.
	 *
	 * @var WP_Post|null|false
	 */
	private static $page = false;

	/**
	 * Register the fallback renderer.
	 */
	public static function register(): void {
		add_action( 'template_redirect', array( self::class, 'maybe_render_fallback' ), 5 );
		add_action( 'save_post_page', array( self::class, 'forget' ) );
	}

	/**
	 * Drop the cached page after a page was saved.
	 */
	public static function forget(): void {
		self::$page = false;
	}

	/**
	 * The published page with the setup slug holding the shortcode, if any (cached per request).
	 * The front page is never used: its URL is "/", which cannot be told apart from the site.
	 */
	public static function page(): ?WP_Post {
		if ( false === self::$page ) {
			$found      = get_page_by_path( self::SLUG );
			self::$page = $found instanceof WP_Post && 'publish' === $found->post_status
				&& has_shortcode( $found->post_content, Enrollment::SHORTCODE )
				&& (int) get_option( 'page_on_front' ) !== $found->ID ? $found : null;
		}
		return self::$page;
	}

	/**
	 * Where users are sent to set up 2FA.
	 */
	public static function url(): string {
		$page = self::page();
		if ( $page ) {
			return (string) get_permalink( $page );
		}
		// Without pretty permalinks /2fa/ would be a server 404.
		return get_option( 'permalink_structure' ) ? home_url( '/' . self::SLUG . '/' ) : add_query_arg( self::FALLBACK_ARG, '1', home_url( '/' ) );
	}

	/**
	 * Whether the current request is for the setup page and nothing else. Works on the raw
	 * request (path and query), so it gives the same answer before WordPress parsed it. Any
	 * other query variable (?p=, ?s=, ...) could make WordPress serve other content: refused.
	 */
	public static function is_current(): bool {
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification.Recommended -- compared exactly, never output or stored.
		$request = wp_parse_url( (string) ( $_SERVER['REQUEST_URI'] ?? '' ) );
		$query   = $_GET;
		// phpcs:enable
		$target = wp_parse_url( self::url() );
		$path   = static fn( $parts ): string => strtolower( trim( preg_replace( '#^/?index\.php(?=/|$)#', '', (string) ( $parts['path'] ?? '' ) ), '/' ) );
		parse_str( (string) ( $target['query'] ?? '' ), $target_query );

		$allowed = array_merge( array( Enrollment::STATUS_PARAM, Recovery_Token::QUERY_ARG ), array_keys( $target_query ) );
		if ( array_diff( array_keys( $query ), $allowed ) || $path( $request ) !== $path( $target ) ) {
			return false;
		}
		foreach ( $target_query as $key => $value ) {
			if ( ! isset( $query[ $key ] ) || ! is_string( $query[ $key ] ) || (string) $value !== $query[ $key ] ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Serve the fallback page when no real page exists.
	 */
	public static function maybe_render_fallback(): void {
		if ( self::page() || ! self::is_current() ) {
			return;
		}
		if ( ! is_user_logged_in() ) {
			auth_redirect();
		}

		global $wp_query;
		$wp_query->is_404 = false;
		status_header( 200 );
		header( 'X-Robots-Tag: noindex, nofollow' );
		add_filter( 'wp_robots', 'wp_robots_sensitive_page' );
		$title = __( 'Two-factor authentication', 'aiwos-two-factor' );
		add_filter( 'pre_get_document_title', static fn() => $title . ' – ' . get_bloginfo( 'name' ) );
		$content = Enrollment::render();
		?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
		<?php if ( ! current_theme_supports( 'title-tag' ) ) : ?>
	<title><?php echo esc_html( wp_get_document_title() ); ?></title>
		<?php endif; ?>
		<?php wp_head(); ?>
</head>
<body <?php body_class( 'aiwos-two-factor-setup' ); ?>>
		<?php wp_body_open(); ?>
	<main style="max-width:40rem;margin:2rem auto;padding:0 1rem">
		<h1><?php echo esc_html( $title ); ?></h1>
		<?php echo $content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in Enrollment::render(). ?>
		<p><a href="<?php echo esc_url( wp_logout_url( home_url( '/' ) ) ); ?>"><?php esc_html_e( 'Log out', 'aiwos-two-factor' ); ?></a></p>
	</main>
		<?php wp_footer(); ?>
</body>
</html>
		<?php
		exit;
	}
}
