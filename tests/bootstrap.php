<?php
/**
 * Shared helpers for the live-WordPress tests. Mails are captured, never sent.
 *
 * @package Aiwos\TwoFactor
 */

// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped, WordPress.WP.GlobalVariablesOverride.Prohibited -- CLI test script.

$GLOBALS['aiwos_tf_test'] = array(
	'checks'   => 0,
	'failures' => 0,
	'users'    => array(),
	'mails'    => array(),
	'actions'  => array(),
);

add_filter(
	'pre_wp_mail',
	static function ( $short, $atts ) {
		$GLOBALS['aiwos_tf_test']['mails'][] = $atts;
		return true;
	},
	10,
	2
);

/**
 * Record one check.
 *
 * @param string $name Description.
 * @param bool   $ok   Result.
 */
function aiwos_tf_check( string $name, bool $ok ): void {
	++$GLOBALS['aiwos_tf_test']['checks'];
	if ( ! $ok ) {
		++$GLOBALS['aiwos_tf_test']['failures'];
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $name . "\n";
}

/**
 * Throwaway user, removed by aiwos_tf_finish().
 *
 * @param string   $role Role.
 * @param string[] $caps Extra capabilities.
 */
function aiwos_tf_user( string $role, array $caps = array() ): WP_User {
	$login = 'aftf_test_' . $role . '_' . wp_generate_password( 6, false );
	$id    = (int) wp_insert_user(
		array(
			'user_login' => $login,
			'user_pass'  => wp_generate_password( 24 ),
			'user_email' => $login . '@example.invalid',
			'role'       => $role,
		)
	);
	$user  = get_userdata( $id );
	foreach ( $caps as $cap ) {
		$user->add_cap( $cap );
	}
	$GLOBALS['aiwos_tf_test']['users'][] = $id;
	return get_userdata( $id );
}

/**
 * Log the user in with a real session; optionally stamped as a 2FA login.
 *
 * @param WP_User     $user     User.
 * @param string|null $provider Provider that proved this session, or null for password only.
 * @return string Session token.
 */
function aiwos_tf_log_in( WP_User $user, ?string $provider = null ): string {
	// Log out first: upstream copies two-factor-* data of the current session into new ones.
	wp_set_current_user( 0 );
	unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	$expiration                  = time() + HOUR_IN_SECONDS;
	$session                     = $provider ? array(
		'two-factor-provider' => $provider,
		'two-factor-login'    => time(),
	) : array();
	$manager                     = WP_Session_Tokens::get_instance( $user->ID );
	$token                       = $manager->create( $expiration );
	$_COOKIE[ LOGGED_IN_COOKIE ] = wp_generate_auth_cookie( $user->ID, $expiration, 'logged_in', $token );
	if ( $session ) {
		$manager->update( $token, array_merge( $manager->get( $token ), $session ) );
	}
	wp_set_current_user( $user->ID );
	return $token;
}

/**
 * Give the user a linked authenticator app.
 *
 * @param WP_User $user User.
 * @return string The secret.
 */
function aiwos_tf_link_app( WP_User $user ): string {
	$key = Two_Factor_Totp::generate_key();
	update_user_meta( $user->ID, '_two_factor_totp_key', $key );
	update_user_meta( $user->ID, '_two_factor_enabled_providers', array( 'Two_Factor_Totp' ) );
	update_user_meta( $user->ID, '_two_factor_provider', 'Two_Factor_Totp' );
	return $key;
}

/**
 * Mails sent to the user so far.
 *
 * @param WP_User $user User.
 * @return array<int, array<string, mixed>>
 */
function aiwos_tf_mails_to( WP_User $user ): array {
	return array_values( array_filter( $GLOBALS['aiwos_tf_test']['mails'], static fn( $m ) => $m['to'] === $user->user_email ) );
}

/**
 * Remove throwaway users, print totals and exit non-zero on failures.
 */
function aiwos_tf_finish(): void {
	require_once ABSPATH . 'wp-admin/includes/user.php';
	foreach ( $GLOBALS['aiwos_tf_test']['users'] as $id ) {
		wp_delete_user( $id );
	}
	wp_set_current_user( 0 );
	$t = $GLOBALS['aiwos_tf_test'];
	echo "\n{$t['checks']} checks, {$t['failures']} failed\n";
	if ( $t['failures'] > 0 ) {
		exit( 1 );
	}
}
