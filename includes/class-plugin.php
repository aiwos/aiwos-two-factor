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
		// Registered in both cases: Site Health must show it exactly when enforcement is off.
		add_filter( 'site_status_tests', array( self::class, 'add_health_tests' ) );
		if ( ! self::is_supported() ) {
			add_action( 'admin_notices', array( self::class, 'render_dependency_notice' ) );
			self::log_unsupported();
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
	 * Site Health: whether 2FA is enforced at all, and whether the per-account database lock
	 * (MySQL/MariaDB GET_LOCK) works.
	 *
	 * @param array<string, mixed> $tests Tests.
	 * @return array<string, mixed>
	 */
	public static function add_health_tests( array $tests ): array {
		$tests['direct']['aiwos_two_factor_enforced'] = array(
			'label' => __( 'Two-factor enforcement', 'aiwos-two-factor' ),
			'test'  => array( self::class, 'enforcement_health_test' ),
		);
		if ( self::is_supported() ) {
			$tests['direct']['aiwos_two_factor_lock'] = array(
				'label' => __( 'Two-factor account lock', 'aiwos-two-factor' ),
				'test'  => array( self::class, 'lock_health_test' ),
			);
		}
		return $tests;
	}

	/**
	 * Site Health: mandatory 2FA is only enforced while upstream Two Factor is supported.
	 *
	 * @return array<string, mixed>
	 */
	public static function enforcement_health_test(): array {
		$ok = self::is_supported();
		return array(
			'label'       => $ok ? __( 'Two-factor authentication is enforced', 'aiwos-two-factor' ) : __( 'Two-factor authentication is NOT enforced', 'aiwos-two-factor' ),
			'status'      => $ok ? 'good' : 'critical',
			'badge'       => array(
				'label' => __( 'Security', 'aiwos-two-factor' ),
				'color' => $ok ? 'blue' : 'red',
			),
			'description' => '<p>' . esc_html(
				sprintf(
					/* translators: %s: minimum Two Factor version. */
					__( 'Aiwos Two Factor needs the upstream Two Factor plugin, version %s or newer, active. Without it nobody is forced to set up 2FA and staff recovery does not work.', 'aiwos-two-factor' ),
					self::MIN_TWO_FACTOR_VERSION
				)
			) . '</p>',
			'test'        => 'aiwos_two_factor_enforced',
		);
	}

	/**
	 * Server log line when enforcement is off (at most once an hour, no log flooding).
	 */
	private static function log_unsupported(): void {
		if ( get_transient( 'aiwos_two_factor_unsupported_logged' ) ) {
			return;
		}
		set_transient( 'aiwos_two_factor_unsupported_logged', 1, HOUR_IN_SECONDS );
		error_log( '[aiwos-two-factor] upstream Two Factor missing or too old: two-factor enforcement is OFF' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- operational alert.
	}

	/**
	 * Run the lock test.
	 *
	 * @return array<string, mixed>
	 */
	public static function lock_health_test(): array {
		$ok = Account::lock( 0 );
		if ( $ok ) {
			Account::unlock( 0 );
		}
		return array(
			'label'       => $ok ? __( 'The two-factor account lock works', 'aiwos-two-factor' ) : __( 'The two-factor account lock does not work', 'aiwos-two-factor' ),
			'status'      => $ok ? 'good' : 'critical',
			'badge'       => array(
				'label' => __( 'Security', 'aiwos-two-factor' ),
				'color' => $ok ? 'blue' : 'red',
			),
			'description' => '<p>' . esc_html__( 'Linking an authenticator app, recovery codes and staff resets use a database lock (GET_LOCK). Without it every such change is refused.', 'aiwos-two-factor' ) . '</p>',
			'test'        => 'aiwos_two_factor_lock',
		);
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
