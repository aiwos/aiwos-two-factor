<?php
/**
 * Mails about 2FA changes on the user's own account.
 *
 * @package Aiwos\TwoFactor
 */

namespace Aiwos\TwoFactor;

use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Plain-text mails to the account's existing address. A failure never interrupts the
 * change itself; it is reported through the return value and WordPress' wp_mail_failed.
 */
final class Notifier {

	/**
	 * Return false to stop informational mails. The recovery link mail is always sent.
	 */
	public const FILTER = 'aiwos/two-factor/notify-user';

	/**
	 * Send an informational mail (can be switched off with the filter).
	 *
	 * @param WP_User $user    Recipient.
	 * @param string  $subject Subject; the site name is prefixed.
	 * @param string  $message Body.
	 * @return bool Whether the mail was accepted for delivery (true when switched off).
	 */
	public static function inform( WP_User $user, string $subject, string $message ): bool {
		if ( ! apply_filters( self::FILTER, true, $user ) ) { // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores -- aiwos/* hook convention.
			return true;
		}
		return self::send( $user, $subject, $message );
	}

	/**
	 * Send a mail that is part of a security flow.
	 *
	 * @param WP_User $user    Recipient.
	 * @param string  $subject Subject; the site name is prefixed.
	 * @param string  $message Body.
	 */
	public static function send( WP_User $user, string $subject, string $message ): bool {
		if ( ! is_email( $user->user_email ) ) {
			return false;
		}
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		return wp_mail( $user->user_email, sprintf( '[%s] %s', $site, $subject ), $message . "\n\n" . home_url( '/' ) );
	}

	/**
	 * Closing line used in every mail.
	 */
	public static function not_you(): string {
		return __( 'If this was not you, contact us right away.', 'aiwos-two-factor' );
	}
}
