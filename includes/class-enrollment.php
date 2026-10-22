<?php
/**
 * Frontend TOTP enrollment on top of upstream Two Factor.
 *
 * @package Aiwos\TwoFactor
 */

namespace Aiwos\TwoFactor;

use Two_Factor_Backup_Codes;
use Two_Factor_Core;
use Two_Factor_Totp;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Shortcode with a plain POST form. Deliberately not upstream's REST/JS flow: our sites
 * lock the REST API down for non-admins, which is also why the old fork saved this way.
 * The secret is generated and kept server-side until the user proves a code.
 */
final class Enrollment {

	/**
	 * Shortcode name kept identical to the old fork so existing pages keep working.
	 */
	public const SHORTCODE = 'two-factor-set-totp';

	/**
	 * User meta holding the not-yet-confirmed secret.
	 */
	public const PENDING_KEY_META = '_aiwos_two_factor_pending_key';

	public const STATUS_PARAM = 'aiwos-2fa';

	private const PROVIDER             = 'Two_Factor_Totp';
	private const NONCE_FIELD          = '_aiwos_two_factor_nonce';
	private const RECOVERY_NONCE_FIELD = '_aiwos_two_factor_recovery_nonce';

	/**
	 * Recovery codes generated in this request.
	 *
	 * @var string[]
	 */
	private static array $fresh_codes = array();

	/**
	 * Register shortcode and form handling.
	 */
	public static function register(): void {
		if ( ! shortcode_exists( self::SHORTCODE ) ) {
			add_shortcode( self::SHORTCODE, array( self::class, 'render' ) );
		}
		add_action( 'template_redirect', array( self::class, 'handle_request' ), 0 );
	}

	/**
	 * On the page holding the shortcode: disable caching and process a submitted form.
	 */
	public static function handle_request(): void {
		$on_setup_page = Setup_Page::is_current();
		if ( ! $on_setup_page && ( ! is_singular() || ! has_shortcode( (string) get_post_field( 'post_content', get_queried_object_id() ), self::SHORTCODE ) ) ) {
			return;
		}

		self::no_cache();
		if ( ! is_user_logged_in() ) {
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified in process() / process_recovery_codes().
		if ( isset( $_POST[ self::RECOVERY_NONCE_FIELD ] ) ) {
			// Shown once in this response; never stored or redirected.
			self::$fresh_codes = self::process_recovery_codes( wp_get_current_user(), wp_unslash( $_POST ) );
			return;
		}
		if ( ! isset( $_POST[ self::NONCE_FIELD ] ) ) {
			return;
		}
		$status = self::process( wp_get_current_user(), wp_unslash( $_POST ) );
		// phpcs:enable

		$url = $on_setup_page ? Setup_Page::url() : get_permalink( get_queried_object_id() );
		wp_safe_redirect( add_query_arg( self::STATUS_PARAM, $status, $url ) );
		exit;
	}

	/**
	 * Replace the user's recovery codes. Needs a recent 2FA login, like other 2FA changes.
	 *
	 * @param WP_User              $user  Current user.
	 * @param array<string, mixed> $input Unslashed POST data.
	 * @return string[] Plain codes, empty when not allowed.
	 */
	public static function process_recovery_codes( WP_User $user, array $input ): array {
		$nonce = $input[ self::RECOVERY_NONCE_FIELD ] ?? '';
		if ( ! is_string( $nonce ) || ! wp_verify_nonce( $nonce, self::nonce_action( $user, 'recovery' ) ) ) {
			return array();
		}
		if ( ! Two_Factor_Core::is_user_using_two_factor( $user->ID ) || ! Two_Factor_Core::current_user_can_update_two_factor_options( 'save' ) ) {
			return array();
		}
		return Recovery::generate_codes( $user );
	}

	/**
	 * Validate a submitted code against the user's pending secret and enable TOTP.
	 *
	 * Always acts on $user; any user id in the input is ignored.
	 *
	 * @param WP_User              $user  Current user.
	 * @param array<string, mixed> $input Unslashed POST data.
	 * @return string Status: enrolled, invalid_nonce, already, revalidate, invalid_code, error.
	 */
	public static function process( WP_User $user, array $input ): string {
		$nonce = $input[ self::NONCE_FIELD ] ?? '';
		if ( ! is_string( $nonce ) || ! wp_verify_nonce( $nonce, self::nonce_action( $user ) ) ) {
			return 'invalid_nonce';
		}

		$totp = self::provider();
		if ( ! $totp ) {
			return 'error';
		}
		if ( $totp->get_user_totp_key( $user->ID ) ) {
			return 'already';
		}
		if ( Two_Factor_Core::is_user_using_two_factor( $user->ID ) && ! Two_Factor_Core::current_user_can_update_two_factor_options( 'save' ) ) {
			return 'revalidate';
		}

		$key  = (string) get_user_meta( $user->ID, self::PENDING_KEY_META, true );
		$code = is_string( $input['authcode'] ?? null ) ? preg_replace( '/\s+/', '', $input['authcode'] ) : '';
		$tick = $totp->is_valid_key( $key ) ? Two_Factor_Totp::get_authcode_valid_ticktime( $key, $code ) : false;
		if ( false === $tick ) {
			return 'invalid_code';
		}

		if ( ! $totp->set_user_totp_key( $user->ID, $key ) || ! Two_Factor_Core::enable_provider_for_user( $user->ID, self::PROVIDER ) ) {
			return 'error';
		}

		// Mark this code as used, so it cannot be replayed at the next login.
		update_user_meta( $user->ID, Two_Factor_Totp::LAST_SUCCESSFUL_LOGIN_META_KEY, $tick );
		delete_user_meta( $user->ID, self::PENDING_KEY_META );
		update_user_meta( $user->ID, Two_Factor_Core::PROVIDER_USER_META_KEY, self::PROVIDER );
		if ( get_current_user_id() === $user->ID ) {
			// The user just proved a code: count this session as two-factor.
			Two_Factor_Core::update_current_user_session(
				array(
					'two-factor-provider' => self::PROVIDER,
					'two-factor-login'    => time(),
				)
			);
			// Sessions opened before enrollment were password-only.
			wp_destroy_other_sessions();
		}

		Recovery::notify(
			$user,
			__( 'Authenticator app linked', 'aiwos-two-factor' ),
			__( 'An authenticator app was just linked to your account for two-factor authentication. If this was not you, contact us right away.', 'aiwos-two-factor' )
		);

		return 'enrolled';
	}

	/**
	 * Shortcode callback.
	 */
	public static function render(): string {
		$user = wp_get_current_user();
		$totp = self::provider();
		if ( ! $user->exists() || ! $totp ) {
			return '';
		}

		$notice = self::status_notice();

		if ( $totp->get_user_totp_key( $user->ID ) ) {
			return $notice . '<p class="aiwos-two-factor__done">' . esc_html__( 'Your authenticator app is linked to your account.', 'aiwos-two-factor' ) . '</p>' . self::render_recovery( $user );
		}

		if ( Two_Factor_Core::is_user_using_two_factor( $user->ID ) && ! Two_Factor_Core::current_user_can_update_two_factor_options( 'save' ) ) {
			return $notice . sprintf(
				'<p class="aiwos-two-factor__revalidate">%s <a href="%s">%s</a></p>',
				esc_html__( 'To link an authenticator app, first confirm your current two-factor code.', 'aiwos-two-factor' ),
				esc_url( Two_Factor_Core::get_user_two_factor_revalidate_url() ),
				esc_html__( 'Confirm code', 'aiwos-two-factor' )
			);
		}

		// Also when rendered outside the page itself (widget, template): the output holds a secret.
		self::no_cache();

		$key = (string) get_user_meta( $user->ID, self::PENDING_KEY_META, true );
		if ( ! $totp->is_valid_key( $key ) ) {
			$key = Two_Factor_Totp::generate_key();
			update_user_meta( $user->ID, self::PENDING_KEY_META, $key );
		}
		$totp_url = Two_Factor_Totp::generate_qr_code_url( $user, $key );

		// Upstream only registers its scripts in wp-admin; the QR script draws into #two-factor-qr-code a.
		$totp->enqueue_assets( '' );
		wp_localize_script(
			'two-factor-totp-qrcode',
			'twoFactorTotpQrcode',
			array(
				'totpUrl'     => $totp_url,
				'qrCodeLabel' => __( 'Authenticator app QR code', 'aiwos-two-factor' ),
			)
		);
		wp_enqueue_script( 'two-factor-totp-qrcode' );

		ob_start();
		?>
		<form method="post" class="aiwos-two-factor" action="<?php echo esc_url( remove_query_arg( self::STATUS_PARAM ) ); ?>" autocomplete="off">
			<?php echo $notice; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in status_notice(). ?>
			<p id="two-factor-qr-code"><a href="<?php echo esc_url( $totp_url, array( 'otpauth' ) ); ?>"><?php esc_html_e( 'Open in authenticator app', 'aiwos-two-factor' ); ?></a></p>
			<p><?php esc_html_e( 'Can\'t scan the QR code? Enter this key in your app:', 'aiwos-two-factor' ); ?> <code><?php echo esc_html( $key ); ?></code></p>
			<p>
				<label for="aiwos-two-factor-authcode"><?php esc_html_e( 'Code from the app', 'aiwos-two-factor' ); ?></label>
				<input type="text" inputmode="numeric" pattern="[0-9 ]*" autocomplete="one-time-code" required name="authcode" id="aiwos-two-factor-authcode">
			</p>
			<?php wp_nonce_field( self::nonce_action( $user ), self::NONCE_FIELD ); ?>
			<p><button type="submit"><?php esc_html_e( 'Verify and enable', 'aiwos-two-factor' ); ?></button></p>
		</form>
		<?php
		return (string) ob_get_clean();
	}

	/**
	 * Recovery codes: show freshly generated codes once, or offer to generate them.
	 *
	 * @param WP_User $user Current user.
	 */
	private static function render_recovery( WP_User $user ): string {
		if ( self::$fresh_codes ) {
			$items = '';
			foreach ( self::$fresh_codes as $code ) {
				$items .= '<li><code>' . esc_html( $code ) . '</code></li>';
			}
			return sprintf(
				'<div class="aiwos-two-factor__codes"><p><strong>%s</strong></p><ol>%s</ol></div>',
				esc_html__( 'Your recovery codes. Store them somewhere safe (not on your phone). Each code works once, if you lose your authenticator app. They are shown only now; reloading this page creates new codes.', 'aiwos-two-factor' ),
				$items
			);
		}

		// Recovery codes can be switched off site-wide in Two Factor; its class is then not loaded.
		if ( ! class_exists( Two_Factor_Backup_Codes::class ) || ! Two_Factor_Core::current_user_can_update_two_factor_options( 'save' ) ) {
			return '';
		}

		$remaining = Two_Factor_Backup_Codes::codes_remaining_for_user( $user );
		$intro     = $remaining
			? sprintf(
				/* translators: %d: number of unused recovery codes. */
				_n( 'You have %d unused recovery code.', 'You have %d unused recovery codes.', $remaining, 'aiwos-two-factor' ),
				$remaining
			)
			: __( 'Create recovery codes, so you can still log in if you lose your phone.', 'aiwos-two-factor' );

		ob_start();
		?>
		<form method="post" class="aiwos-two-factor__recovery" action="<?php echo esc_url( remove_query_arg( self::STATUS_PARAM ) ); ?>">
			<p><?php echo esc_html( $intro ); ?></p>
			<?php wp_nonce_field( self::nonce_action( $user, 'recovery' ), self::RECOVERY_NONCE_FIELD ); ?>
			<p><button type="submit"><?php echo $remaining ? esc_html__( 'Create new recovery codes', 'aiwos-two-factor' ) : esc_html__( 'Create recovery codes', 'aiwos-two-factor' ); ?></button></p>
		</form>
		<?php
		return (string) ob_get_clean();
	}

	/**
	 * Message for the status passed back after a submit.
	 */
	private static function status_notice(): string {
		$messages = array(
			'enrolled'      => __( 'Two-factor authentication is now enabled.', 'aiwos-two-factor' ),
			'invalid_code'  => __( 'That code is not valid. Check the time on your phone and try again with a new code.', 'aiwos-two-factor' ),
			'invalid_nonce' => __( 'Your session expired. Please try again.', 'aiwos-two-factor' ),
			'revalidate'    => __( 'Confirm your current two-factor code first.', 'aiwos-two-factor' ),
			'error'         => __( 'Something went wrong while saving. Please try again.', 'aiwos-two-factor' ),
		);
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only, value is whitelisted.
		$status = isset( $_GET[ self::STATUS_PARAM ] ) ? sanitize_key( wp_unslash( $_GET[ self::STATUS_PARAM ] ) ) : '';
		if ( ! isset( $messages[ $status ] ) ) {
			return '';
		}
		$type = 'enrolled' === $status ? 'success' : 'error';
		return sprintf( '<div class="feedback feedback-%s" role="status">%s</div>', esc_attr( $type ), esc_html( $messages[ $status ] ) );
	}

	/**
	 * The page shows a secret: keep it out of browser and page caches.
	 */
	private static function no_cache(): void {
		if ( ! headers_sent() ) {
			nocache_headers();
			send_frame_options_header();
			header( 'Referrer-Policy: same-origin' );
		}
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true );
		}
	}

	/**
	 * Upstream TOTP provider instance, if registered.
	 */
	private static function provider(): ?Two_Factor_Totp {
		$providers = Two_Factor_Core::get_providers();
		return ( $providers[ self::PROVIDER ] ?? null ) instanceof Two_Factor_Totp ? $providers[ self::PROVIDER ] : null;
	}

	/**
	 * Nonce action bound to the user.
	 *
	 * @param WP_User $user User.
	 * @param string  $what Form: enroll or recovery.
	 */
	private static function nonce_action( WP_User $user, string $what = 'enroll' ): string {
		return 'aiwos-two-factor-' . $what . '-' . $user->ID;
	}
}
