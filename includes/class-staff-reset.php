<?php
/**
 * Staff-assisted 2FA recovery for users who lost their app and recovery codes.
 *
 * @package Aiwos\TwoFactor
 */

namespace Aiwos\TwoFactor;

use Two_Factor_Core;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * One entry point, start_recovery(), with every check inside it. Two thin interfaces call
 * it: a confirmation screen behind the Users row action (wp-admin) and the shortcode
 * [two-factor-staff-reset] for account managers without wp-admin access.
 */
final class Staff_Reset {

	/**
	 * Granted to users with manage_options automatically; give it to other roles explicitly
	 * (wp cap add <role> aiwos_reset_two_factor).
	 */
	public const CAP = 'aiwos_reset_two_factor';

	public const SHORTCODE = 'two-factor-staff-reset';

	private const ACTION      = 'aiwos_two_factor_reset';
	private const NONCE_FIELD = '_aiwos_two_factor_staff_nonce';
	private const PAGE        = 'aiwos-two-factor-reset';
	private const STATUS_ARG  = 'aiwos-2fa-staff';
	private const PRIVILEGED  = array( 'manage_options', 'promote_users', 'edit_users', self::CAP );

	/**
	 * A reset needs a 2FA proof from the last 10 minutes (stricter than upstream's 20).
	 */
	private const PROOF_MAX_AGE = 10 * MINUTE_IN_SECONDS;

	/**
	 * Register capability, wp-admin screens and the frontend form.
	 */
	public static function register(): void {
		add_filter( 'user_has_cap', array( self::class, 'grant_to_site_managers' ) );
		add_filter( 'user_row_actions', array( self::class, 'add_row_action' ), 10, 2 );
		add_action( 'admin_menu', array( self::class, 'add_confirm_page' ) );
		add_action( 'admin_post_' . self::ACTION, array( self::class, 'handle_admin_post' ) );
		add_action( 'admin_notices', array( self::class, 'render_admin_notice' ) );
		add_shortcode( self::SHORTCODE, array( self::class, 'render_shortcode' ) );
		add_action( 'template_redirect', array( self::class, 'handle_frontend_post' ), 0 );
	}

	/**
	 * Site managers may always recover accounts.
	 *
	 * @param array<string, bool> $allcaps User capabilities.
	 * @return array<string, bool>
	 */
	public static function grant_to_site_managers( array $allcaps ): array {
		if ( ! empty( $allcaps['manage_options'] ) ) {
			$allcaps[ self::CAP ] = true;
		}
		return $allcaps;
	}

	/**
	 * Why the current user may not recover the target, or '' when allowed.
	 *
	 * @param WP_User $target Account to recover.
	 * @return string '', not_allowed, self, own_2fa_required or revalidate.
	 */
	public static function check( WP_User $target ): string {
		$actor = wp_get_current_user();
		if ( ! $actor->exists() || ! $target->exists() || ! current_user_can( self::CAP ) || ! current_user_can( 'edit_user', $target->ID ) ) {
			return 'not_allowed';
		}
		if ( $actor->ID === $target->ID ) {
			return 'self';
		}
		// Multisite: only members of this site, never a network administrator.
		if ( is_multisite() && ( is_super_admin( $target->ID ) || ! is_user_member_of_blog( $target->ID ) ) ) {
			return 'not_allowed';
		}
		if ( ! current_user_can( 'manage_options' ) && ! self::in_manager_scope( $target ) ) {
			return 'not_allowed';
		}
		/**
		 * Capabilities that make an account privileged: only site managers holding the same
		 * capability may recover it. Add site-specific ones (e.g. a shop manager capability).
		 *
		 * @param string[] $caps Capabilities.
		 */
		$privileged = (array) apply_filters( 'aiwos/two-factor/privileged-caps', self::PRIVILEGED ); // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores -- aiwos/* hook convention.
		foreach ( $privileged as $cap ) {
			if ( user_can( $target, $cap ) && ( ! current_user_can( $cap ) || ! current_user_can( 'manage_options' ) ) ) {
				return 'not_allowed';
			}
		}
		/**
		 * Final say on whether the actor may recover this target.
		 *
		 * @param bool    $allowed Default true.
		 * @param WP_User $target  Account to recover.
		 * @param WP_User $actor   Staff member.
		 */
		if ( ! apply_filters( 'aiwos/two-factor/can-reset', true, $target, $actor ) ) { // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores -- aiwos/* hook convention.
			return 'not_allowed';
		}
		// The actor needs 2FA and a recent proof of it, not just a login cookie.
		if ( ! Two_Factor_Core::is_user_using_two_factor( $actor->ID ) ) {
			return 'own_2fa_required';
		}
		return Account::has_recent_proof( self::PROOF_MAX_AGE ) ? '' : 'revalidate';
	}

	/**
	 * Account managers (no manage_options): only accounts whose every role they may assign,
	 * using WordPress' own "who manages whom" setting (editable_roles). That setting only
	 * counts when the site actually limits it for this manager; unlimited means no delegated
	 * scope. Capabilities given to the target individually must be held by the manager too.
	 *
	 * @param WP_User $target Account to recover.
	 */
	private static function in_manager_scope( WP_User $target ): bool {
		require_once ABSPATH . 'wp-admin/includes/user.php';
		$all      = array_keys( wp_roles()->roles );
		$editable = array_keys( get_editable_roles() );
		if ( ! array_diff( $all, $editable ) || ! $target->roles || array_diff( $target->roles, $editable ) ) {
			return false;
		}
		foreach ( $target->caps as $cap => $granted ) {
			if ( $granted && ! in_array( $cap, $all, true ) && ! current_user_can( $cap ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Remove the target's 2FA and put the account in recovery: only the mailed link lets the
	 * user link a new app. Order: recovery state first (so the account is never open), then
	 * revoke access, clear 2FA, audit, mail.
	 *
	 * @param WP_User $target         Account to recover.
	 * @param string  $reason         How identity was verified and why (audit trail).
	 * @param bool    $password_reset The password may be compromised: send the password reset
	 *                                mail, and the link only works after a new password was set.
	 * @return string started, error, mail_failed, password_mail_failed, reason_required, or a check() code.
	 */
	public static function start_recovery( WP_User $target, string $reason, bool $password_reset ): string {
		$denied = self::check( $target );
		if ( '' !== $denied ) {
			return $denied;
		}
		$reason = trim( sanitize_textarea_field( $reason ) );
		if ( '' === $reason ) {
			return 'reason_required';
		}

		$actor = wp_get_current_user();
		$token = Account::locked(
			$target->ID,
			static function () use ( $target, $actor, $password_reset ) {
				// Recovery state first and only if it was stored: the account is never left open.
				$token = Recovery_Token::issue( $target, $actor, $password_reset );
				if ( null !== $token ) {
					Account::revoke_access( $target->ID );
					Account::clear_two_factor( $target->ID );
				}
				return $token;
			}
		);
		if ( ! is_string( $token ) ) {
			return 'error';
		}

		/**
		 * Fires after staff started 2FA recovery for an account (audit trail).
		 *
		 * @param WP_User $target Account.
		 * @param WP_User $actor  Staff member.
		 * @param string  $reason Verification and reason given by the staff member.
		 */
		do_action( 'aiwos/two-factor/recovery-started', $target, $actor, $reason ); // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores -- aiwos/* hook convention.
		error_log( sprintf( '[aiwos-two-factor] staff recovery started: user %d by user %d', $target->ID, $actor->ID ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- audit trail in the server log.

		$sent = Notifier::send(
			$target,
			__( 'Link a new authenticator app', 'aiwos-two-factor' ),
			sprintf(
				/* translators: 1: staff member, 2: date and time, 3: link, 4: hours the link stays valid. */
				__( "%1\$s reset the two-factor authentication of your account on %2\$s. You have been logged out everywhere.\n\nLog in with your password, then open this link to link a new authenticator app:\n%3\$s\n\nThe link works once and expires in %4\$d hours.", 'aiwos-two-factor' ),
				$actor->display_name,
				wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) ),
				Recovery_Token::url( $token ),
				(int) ( Recovery_Token::TTL / HOUR_IN_SECONDS )
			) . ( $password_reset ? "\n\n" . __( 'You will also receive a mail to set a new password. Set the new password first; the link above only works after that.', 'aiwos-two-factor' ) : '' )
			. "\n\n" . Notifier::not_you()
		);

		if ( ! $sent ) {
			return 'mail_failed';
		}
		if ( $password_reset && true !== retrieve_password( $target->user_login ) ) {
			return 'password_mail_failed';
		}
		return 'started';
	}

	/**
	 * Help a user with a forgotten password only: send the standard WordPress password reset
	 * mail. 2FA is not touched, so the next login still needs the app or a recovery code.
	 *
	 * @param WP_User $target Account.
	 * @param string  $reason Why (audit trail).
	 * @return string password_sent, password_failed, reason_required, or a check() code.
	 */
	public static function send_password_reset( WP_User $target, string $reason ): string {
		$denied = self::check( $target );
		if ( '' !== $denied ) {
			return $denied;
		}
		$reason = trim( sanitize_textarea_field( $reason ) );
		if ( '' === $reason ) {
			return 'reason_required';
		}
		$actor = wp_get_current_user();
		/**
		 * Fires after staff sent a password reset mail for an account (audit trail).
		 *
		 * @param WP_User $target Account.
		 * @param WP_User $actor  Staff member.
		 * @param string  $reason Reason given by the staff member.
		 */
		do_action( 'aiwos/two-factor/password-reset-sent', $target, $actor, $reason ); // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores -- aiwos/* hook convention.
		error_log( sprintf( '[aiwos-two-factor] staff password reset mail: user %d by user %d', $target->ID, $actor->ID ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- audit trail in the server log.
		return true === retrieve_password( $target->user_login ) ? 'password_sent' : 'password_failed';
	}

	/**
	 * "Reset two-factor" on Users opens a confirmation screen; GET never changes anything.
	 *
	 * @param array<string, string> $actions Row actions.
	 * @param WP_User               $user    Listed user.
	 * @return array<string, string>
	 */
	public static function add_row_action( array $actions, WP_User $user ): array {
		if ( in_array( self::check( $user ), array( '', 'revalidate', 'own_2fa_required' ), true ) ) {
			$url = add_query_arg(
				array(
					'page'    => self::PAGE,
					'user_id' => $user->ID,
				),
				admin_url( 'admin.php' )
			);

			$actions['aiwos-reset-2fa'] = sprintf( '<a href="%s">%s</a>', esc_url( $url ), esc_html__( 'Reset two-factor', 'aiwos-two-factor' ) );
		}
		return $actions;
	}

	/**
	 * Hidden confirmation screen.
	 */
	public static function add_confirm_page(): void {
		add_submenu_page( '', __( 'Reset two-factor', 'aiwos-two-factor' ), '', self::CAP, self::PAGE, array( self::class, 'render_confirm_page' ) );
	}

	/**
	 * Confirmation screen in wp-admin.
	 */
	public static function render_confirm_page(): void {
		$target = get_userdata( isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0 ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only.
		$denied = $target ? self::check( $target ) : 'not_allowed';
		echo '<div class="wrap"><h1>' . esc_html__( 'Reset two-factor', 'aiwos-two-factor' ) . '</h1>';
		if ( 'revalidate' === $denied ) {
			echo View::revalidate( __( 'To reset two-factor authentication for others, confirm your own code first.', 'aiwos-two-factor' ), add_query_arg( array() ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in View.
		} elseif ( '' !== $denied ) {
			echo self::notice( $denied ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in notice().
		} else {
			echo self::form( admin_url( 'admin-post.php' ), $target ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in form().
		}
		echo '</div>';
	}

	/**
	 * POST from the wp-admin confirmation screen.
	 */
	public static function handle_admin_post(): void {
		$status = self::process_post();
		wp_safe_redirect( add_query_arg( self::STATUS_ARG, $status, admin_url( 'users.php' ) ) );
		exit;
	}

	/**
	 * Result notice on Users.
	 */
	public static function render_admin_notice(): void {
		if ( 'users' === get_current_screen()?->id ) {
			echo self::status_notice(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in status_notice().
		}
	}

	/**
	 * On the page with the frontend form: no caching, and handle a POST (PRG back).
	 */
	public static function handle_frontend_post(): void {
		if ( ! is_singular() || ! has_shortcode( (string) get_post_field( 'post_content', get_queried_object_id() ), self::SHORTCODE ) ) {
			return;
		}
		View::no_cache();
		if ( ! isset( $_POST[ self::NONCE_FIELD ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in process_post().
			return;
		}
		$status = self::process_post();
		wp_safe_redirect( add_query_arg( self::STATUS_ARG, $status, get_permalink( get_queried_object_id() ) ) );
		exit;
	}

	/**
	 * Frontend form for account managers.
	 */
	public static function render_shortcode(): string {
		if ( ! current_user_can( self::CAP ) ) {
			return '';
		}
		$notice = self::status_notice();
		if ( ! Two_Factor_Core::is_user_using_two_factor( get_current_user_id() ) ) {
			return $notice . self::notice( 'own_2fa_required' );
		}
		if ( ! Account::has_recent_proof( self::PROOF_MAX_AGE ) ) {
			return $notice . View::revalidate( __( 'To reset two-factor authentication for others, confirm your own code first.', 'aiwos-two-factor' ), (string) get_permalink() );
		}
		return $notice . self::form( (string) get_permalink() );
	}

	/**
	 * Validate the submitted form and start the recovery.
	 *
	 * @return string Status code.
	 */
	private static function process_post(): string {
		$nonce = isset( $_POST[ self::NONCE_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::NONCE_FIELD ] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, self::ACTION ) ) {
			return 'invalid_nonce';
		}
		$account = isset( $_POST['account'] ) ? sanitize_text_field( wp_unslash( $_POST['account'] ) ) : '';
		$target  = ctype_digit( $account ) ? get_userdata( (int) $account ) : get_user_by( 'email', $account );
		if ( ! $target && ! ctype_digit( $account ) ) {
			$target = get_user_by( 'login', $account );
		}
		if ( ! $target ) {
			return 'not_allowed';
		}
		$reason = isset( $_POST['reason'] ) ? sanitize_textarea_field( wp_unslash( $_POST['reason'] ) ) : '';
		if ( isset( $_POST['mode'] ) && 'password' === sanitize_key( wp_unslash( $_POST['mode'] ) ) ) {
			return self::send_password_reset( $target, $reason );
		}
		return self::start_recovery( $target, $reason, ! empty( $_POST['password_reset'] ) );
	}

	/**
	 * Form shared by wp-admin (fixed target) and frontend (account field).
	 *
	 * @param string       $action Form action URL.
	 * @param WP_User|null $target Fixed target in wp-admin.
	 */
	private static function form( string $action, ?WP_User $target = null ): string {
		ob_start();
		?>
		<form method="post" action="<?php echo esc_url( $action ); ?>" class="aiwos-two-factor-staff">
			<?php if ( $target ) : ?>
				<p>
					<?php
					/* translators: %s: user display name and login. */
					echo esc_html( sprintf( __( 'Account: %s', 'aiwos-two-factor' ), $target->display_name . ' (' . $target->user_login . ')' ) );
					?>
				</p>
				<input type="hidden" name="account" value="<?php echo esc_attr( (string) $target->ID ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION ); ?>">
			<?php else : ?>
				<p><label for="aiwos-two-factor-staff-account"><?php esc_html_e( 'E-mail address or username', 'aiwos-two-factor' ); ?></label><br>
				<input type="text" name="account" id="aiwos-two-factor-staff-account" required autocomplete="off"></p>
			<?php endif; ?>
			<p><?php esc_html_e( 'This removes the authenticator app and recovery codes, logs the user out everywhere and mails them a one-time link to link a new app. Only do this after verifying the identity of the user through a known contact channel.', 'aiwos-two-factor' ); ?></p>
			<p><label for="aiwos-two-factor-staff-reason"><?php esc_html_e( 'How was the identity verified, and why?', 'aiwos-two-factor' ); ?></label><br>
			<textarea name="reason" id="aiwos-two-factor-staff-reason" rows="3" cols="50" required></textarea></p>
			<p><label><input type="checkbox" name="password_reset" value="1"> <?php esc_html_e( 'The password may be compromised: also send a password reset mail, and only allow linking a new app after the password was changed', 'aiwos-two-factor' ); ?></label></p>
			<?php wp_nonce_field( self::ACTION, self::NONCE_FIELD ); ?>
			<p>
				<button type="submit" name="mode" value="recovery" class="button button-primary"><?php esc_html_e( 'Reset two-factor', 'aiwos-two-factor' ); ?></button>
				<button type="submit" name="mode" value="password" class="button"><?php esc_html_e( 'Only send a password reset mail (keeps two-factor)', 'aiwos-two-factor' ); ?></button>
			</p>
		</form>
		<?php
		return (string) ob_get_clean();
	}

	/**
	 * Message for the status passed back after a submit (whitelisted).
	 */
	private static function status_notice(): string {
		$status = isset( $_GET[ self::STATUS_ARG ] ) ? sanitize_key( wp_unslash( $_GET[ self::STATUS_ARG ] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only, whitelisted.
		return '' === $status ? '' : self::notice( $status );
	}

	/**
	 * Notice for a status code; unknown codes give ''.
	 *
	 * @param string $status Status code.
	 */
	private static function notice( string $status ): string {
		$messages = array(
			'started'              => __( 'Two-factor authentication was reset. The user was logged out and received a link to link a new app.', 'aiwos-two-factor' ),
			'password_sent'        => __( 'A password reset mail was sent. Two-factor authentication was not changed.', 'aiwos-two-factor' ),
			'password_failed'      => __( 'The password reset mail could not be sent. Check the mail log, or ask the user to use "Lost your password?".', 'aiwos-two-factor' ),
			'mail_failed'          => __( 'Two-factor authentication was reset, but the mail with the link could not be sent. Check the mail log and reset again to send a new link.', 'aiwos-two-factor' ),
			'password_mail_failed' => __( 'Two-factor authentication was reset and the link was sent, but the password reset mail could not be sent. Ask the user to use "Lost your password?".', 'aiwos-two-factor' ),
			'reason_required'      => __( 'Fill in how the identity was verified.', 'aiwos-two-factor' ),
			'revalidate'           => __( 'Confirm your own two-factor code first.', 'aiwos-two-factor' ),
			'own_2fa_required'     => __( 'Set up two-factor authentication for your own account first.', 'aiwos-two-factor' ),
			'self'                 => __( 'You cannot reset your own two-factor authentication here.', 'aiwos-two-factor' ),
			'not_allowed'          => __( 'Account not found, or you are not allowed to reset it.', 'aiwos-two-factor' ),
			'invalid_nonce'        => __( 'Your session expired. Please try again.', 'aiwos-two-factor' ),
			'error'                => __( 'Nothing was changed: the reset could not be saved. Please try again.', 'aiwos-two-factor' ),
		);
		if ( ! isset( $messages[ $status ] ) ) {
			return '';
		}
		$type = in_array( $status, array( 'started', 'password_sent' ), true ) ? 'success' : 'error';
		return sprintf( '<div class="notice notice-%1$s feedback feedback-%1$s" role="status"><p>%2$s</p></div>', esc_attr( $type ), esc_html( $messages[ $status ] ) );
	}
}
