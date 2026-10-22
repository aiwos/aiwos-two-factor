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
	 * Register the fallback renderer.
	 */
	public static function register(): void {
		add_action( 'template_redirect', array( self::class, 'maybe_render_fallback' ), 5 );
	}

	/**
	 * The published page with the setup slug, if any.
	 */
	public static function page(): ?WP_Post {
		$page = get_page_by_path( self::SLUG );
		// A "2fa" page without the form would leave users stuck: then use the built-in page.
		return $page instanceof WP_Post && 'publish' === $page->post_status && has_shortcode( $page->post_content, Enrollment::SHORTCODE ) ? $page : null;
	}

	/**
	 * Where users are sent to set up 2FA.
	 */
	public static function url(): string {
		$page = self::page();
		return $page ? (string) get_permalink( $page ) : home_url( '/' . self::SLUG . '/' );
	}

	/**
	 * Whether the current request is the setup page (real or fallback).
	 */
	public static function is_current(): bool {
		$page = self::page();
		if ( $page ) {
			return is_page( $page->ID );
		}

		$path = (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '', PHP_URL_PATH );
		$home = trim( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), '/' );
		$path = strtolower( trim( $path, '/' ) );
		if ( '' !== $home ) {
			$path = str_starts_with( $path, $home . '/' ) ? substr( $path, strlen( $home ) + 1 ) : $path;
		}
		// Plain permalinks: /index.php/2fa/.
		$path = str_starts_with( $path, 'index.php/' ) ? substr( $path, strlen( 'index.php/' ) ) : $path;
		return self::SLUG === $path;
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
