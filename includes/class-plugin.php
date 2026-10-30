<?php
/**
 * Bootstrap and dependency check.
 *
 * @package Aiwos\TwoFactor
 */

namespace Aiwos\TwoFactor;

defined( 'ABSPATH' ) || exit;

/**
 * Boots the add-on only when a supported upstream Two Factor is active.
 */
final class Plugin {

	/**
	 * Oldest upstream Two Factor this add-on is tested with (also the CVE-2026-100508 fix). The 0.13.x fork lacks
	 * the REST permission filter and must not be combined with this add-on.
	 */
	public const MIN_TWO_FACTOR_VERSION = '0.17.0';

	/**
	 * Register hooks, or an admin notice when Two Factor is missing or too old.
	 */
	public static function boot(): void {
		if ( ! self::is_supported() ) {
			add_action( 'admin_notices', array( self::class, 'render_dependency_notice' ) );
			return;
		}

		Enrollment::register();
		Enforcer::register();
		Setup_Page::register();
		Staff_Reset::register();
		Upstream_Guard::register();
		Recovery_Token::register();
	}

	/**
	 * Whether the active Two Factor plugin can be used.
	 */
	public static function is_supported(): bool {
		// Provider classes (Two_Factor_Totp) are loaded lazily, so only the core is checked here.
		return class_exists( 'Two_Factor_Core' )
			&& defined( 'TWO_FACTOR_VERSION' )
			&& self::is_supported_version( (string) TWO_FACTOR_VERSION );
	}

	/**
	 * Whether a Two Factor version string meets the minimum.
	 *
	 * @param string $version Two Factor version.
	 */
	public static function is_supported_version( string $version ): bool {
		return version_compare( $version, self::MIN_TWO_FACTOR_VERSION, '>=' );
	}

	/**
	 * Tell administrators that frontend 2FA is not active.
	 */
	public static function render_dependency_notice(): void {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}

		printf(
			'<div class="notice notice-error"><p>%s</p></div>',
			esc_html(
				sprintf(
					/* translators: %s: minimum Two Factor version. */
					__( 'Aiwos Two Factor is inactive: it needs the upstream Two Factor plugin, version %s or newer. Mandatory two-factor setup is NOT enforced.', 'aiwos-two-factor' ),
					self::MIN_TWO_FACTOR_VERSION
				)
			)
		);
	}
}
