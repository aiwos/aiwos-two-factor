<?php
/**
 * Plugin Name:       Aiwos Two Factor
 * Description:       Frontend authenticator setup, mandatory 2FA and account recovery on top of the upstream Two Factor plugin. Replaces the customized Two Factor fork and force-two-factor.
 * Version:           2.0.0
 * Requires at least: 7.0
 * Requires PHP:      8.1
 * Requires Plugins:  two-factor
 * Author:            Aiwos
 * License:           GPL-2.0-or-later
 * Text Domain:       aiwos-two-factor
 * Domain Path:       /languages
 *
 * @package Aiwos\TwoFactor
 */

defined( 'ABSPATH' ) || exit;

foreach ( array( 'plugin', 'account', 'notifier', 'recovery-token', 'view', 'enrollment', 'enforcer', 'setup-page', 'staff-reset' ) as $aiwos_two_factor_file ) {
	require_once __DIR__ . '/includes/class-' . $aiwos_two_factor_file . '.php';
}

// After Two Factor (plugins_loaded, default priority) has defined its classes.
add_action( 'plugins_loaded', array( Aiwos\TwoFactor\Plugin::class, 'boot' ), 20 );
