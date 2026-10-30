<?php
/**
 * HTML for the setup page. Everything is escaped here; callers concatenate the result.
 *
 * @package Aiwos\TwoFactor
 */

namespace Aiwos\TwoFactor;

use Two_Factor_Totp;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Small, stateless renderers.
 */
final class View {

	/**
	 * Message for the status passed back after a submit (whitelisted).
	 */
	public static function status_notice(): string {
		$messages = array(
			'enrolled'          => array( 'success', __( 'Two-factor authentication is now enabled.', 'aiwos-two-factor' ) ),
			'replaced'          => array( 'success', __( 'Your new authenticator app is linked. The old app and old recovery codes no longer work.', 'aiwos-two-factor' ) ),
			'replace_started'   => array( 'info', __( 'Scan the new QR code with your new app. Your current app keeps working until the new one is verified.', 'aiwos-two-factor' ) ),
			'cancelled'         => array( 'info', __( 'Nothing was changed.', 'aiwos-two-factor' ) ),
			'recovery_ok'       => array( 'info', __( 'Link accepted. Now link your new authenticator app.', 'aiwos-two-factor' ) ),
			'recovery_invalid'  => array( 'error', __( 'This link is not valid (any more). Contact your account manager for a new one.', 'aiwos-two-factor' ) ),
			'recovery_required' => array( 'error', __( 'Open the link from the e-mail first.', 'aiwos-two-factor' ) ),
			'password_first'    => array( 'error', __( 'Set a new password first, then log in again and open the recovery link once more.', 'aiwos-two-factor' ) ),
			'invalid_code'      => array( 'error', __( 'That code is not valid. Enter the 6 digits from the app; check the time on your phone if it keeps failing.', 'aiwos-two-factor' ) ),
			'expired'           => array( 'error', __( 'The setup took too long. Scan the new QR code and try again.', 'aiwos-two-factor' ) ),
			'invalid_nonce'     => array( 'error', __( 'Your session expired. Please try again.', 'aiwos-two-factor' ) ),
			'revalidate'        => array( 'error', __( 'Confirm your current two-factor code first.', 'aiwos-two-factor' ) ),
			'error'             => array( 'error', __( 'Something went wrong. Please try again.', 'aiwos-two-factor' ) ),
		);
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only, whitelisted.
		$status = isset( $_GET[ Enrollment::STATUS_PARAM ] ) ? sanitize_key( wp_unslash( $_GET[ Enrollment::STATUS_PARAM ] ) ) : '';
		if ( ! isset( $messages[ $status ] ) ) {
			return '';
		}
		return sprintf( '<div class="feedback feedback-%s" role="status">%s</div>', esc_attr( $messages[ $status ][0] ), esc_html( $messages[ $status ][1] ) );
	}

	/**
	 * The page shows secrets: keep it out of caches, frames and referrers.
	 */
	public static function no_cache(): void {
		if ( ! headers_sent() ) {
			nocache_headers();
			send_frame_options_header();
			// The recovery link carries a token in its URL: never pass it on, not even to own assets.
			header( 'Referrer-Policy: no-referrer' );
		}
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true );
		}
	}

	/**
	 * Confirm button for a recovery link: the token is only redeemed by POST.
	 *
	 * @param string $token        Token from the link.
	 * @param string $nonce_action Nonce action.
	 * @param string $nonce_field  Nonce field name.
	 * @param string $action_field Action field name.
	 */
	public static function recovery_confirm( string $token, string $nonce_action, string $nonce_field, string $action_field ): string {
		return sprintf(
			'<form method="post" class="aiwos-two-factor__redeem" action="%1$s"><p>%2$s</p>%3$s<input type="hidden" name="token" value="%4$s"><input type="hidden" name="%5$s" value="redeem"><p><button type="submit">%6$s</button></p></form>',
			esc_url( remove_query_arg( array( Enrollment::STATUS_PARAM, Recovery_Token::QUERY_ARG ) ) ),
			esc_html__( 'Continue to link a new authenticator app.', 'aiwos-two-factor' ),
			wp_nonce_field( $nonce_action, $nonce_field, false, false ),
			esc_attr( $token ),
			esc_attr( $action_field ),
			esc_html__( 'Continue', 'aiwos-two-factor' )
		);
	}

	/**
	 * A paragraph of text.
	 *
	 * @param string $text Text.
	 */
	public static function message( string $text ): string {
		return '<p class="aiwos-two-factor__message">' . esc_html( $text ) . '</p>';
	}

	/**
	 * Text with a link to upstream's revalidation (works without wp-admin).
	 *
	 * @param string      $text Explanation.
	 * @param string|null $back Where to return afterwards; default the setup page.
	 */
	public static function revalidate( string $text, ?string $back = null ): string {
		return sprintf(
			'<p class="aiwos-two-factor__revalidate">%s <a href="%s">%s</a></p>',
			esc_html( $text ),
			esc_url( Account::revalidate_url( $back ?? Setup_Page::url() ) ),
			esc_html__( 'Confirm code', 'aiwos-two-factor' )
		);
	}

	/**
	 * A single-button POST form.
	 *
	 * @param string $nonce_action Nonce action.
	 * @param string $nonce_field  Nonce field name.
	 * @param string $action_field Action field name.
	 * @param string $action       Action value.
	 * @param string $label        Button label.
	 */
	public static function button( string $nonce_action, string $nonce_field, string $action_field, string $action, string $label ): string {
		return sprintf(
			'<form method="post" class="aiwos-two-factor__%1$s" action="%2$s">%3$s<input type="hidden" name="%4$s" value="%1$s"><p><button type="submit">%5$s</button></p></form>',
			esc_attr( $action ),
			esc_url( remove_query_arg( Enrollment::STATUS_PARAM ) ),
			wp_nonce_field( $nonce_action, $nonce_field, false, false ),
			esc_attr( $action_field ),
			esc_html( $label )
		);
	}

	/**
	 * Freshly generated recovery codes, shown once.
	 *
	 * @param string[] $codes Plain codes.
	 */
	public static function codes( array $codes ): string {
		if ( ! $codes ) {
			return '';
		}
		$items = '';
		foreach ( $codes as $code ) {
			$items .= '<li><code>' . esc_html( $code ) . '</code></li>';
		}
		return sprintf(
			'<div class="aiwos-two-factor__codes"><p><strong>%s</strong></p><ol>%s</ol></div>',
			esc_html__( 'Your recovery codes. Store them somewhere safe (not on your phone). Each code works once, if you lose your authenticator app. They are shown only now; reloading this page creates new codes.', 'aiwos-two-factor' ),
			$items
		);
	}

	/**
	 * QR code, secret and code field for a pending secret.
	 *
	 * @param WP_User $user         Current user.
	 * @param string  $key          Pending secret.
	 * @param string  $nonce_action Nonce action.
	 * @param string  $nonce_field  Nonce field name.
	 * @param string  $action_field Action field name.
	 */
	public static function enroll_form( WP_User $user, string $key, string $nonce_action, string $nonce_field, string $action_field ): string {
		$totp_url = Two_Factor_Totp::generate_qr_code_url( $user, $key );
		// Upstream's QR script draws into #two-factor-qr-code a.
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
		<form method="post" class="aiwos-two-factor" action="<?php echo esc_url( remove_query_arg( Enrollment::STATUS_PARAM ) ); ?>" autocomplete="off">
			<p id="two-factor-qr-code"><a href="<?php echo esc_url( $totp_url, array( 'otpauth' ) ); ?>"><?php esc_html_e( 'Open in authenticator app', 'aiwos-two-factor' ); ?></a></p>
			<p><?php esc_html_e( 'Can\'t scan the QR code? Enter this key in your app:', 'aiwos-two-factor' ); ?> <code><?php echo esc_html( $key ); ?></code></p>
			<p>
				<label for="aiwos-two-factor-authcode"><?php esc_html_e( 'Code from the app', 'aiwos-two-factor' ); ?></label>
				<input type="text" inputmode="numeric" pattern="[0-9 ]*" minlength="6" maxlength="7" autocomplete="one-time-code" required name="authcode" id="aiwos-two-factor-authcode">
			</p>
			<?php wp_nonce_field( $nonce_action, $nonce_field ); ?>
			<input type="hidden" name="<?php echo esc_attr( $action_field ); ?>" value="enroll">
			<p><button type="submit"><?php esc_html_e( 'Verify and enable', 'aiwos-two-factor' ); ?></button></p>
		</form>
		<?php
		return (string) ob_get_clean();
	}
}
