<?php
/**
 * Plugin Name:       Aiwos Two Factor
 * Description:       Frontend TOTP enrollment ([two-factor-set-totp]) and mandatory 2FA redirect on top of the upstream Two Factor plugin. Replaces the customized Two Factor fork and force-two-factor.
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

require_once __DIR__ . '/includes/class-plugin.php';
require_once __DIR__ . '/includes/class-enrollment.php';
require_once __DIR__ . '/includes/class-enforcer.php';
require_once __DIR__ . '/includes/class-setup-page.php';
require_once __DIR__ . '/includes/class-recovery.php';

// After Two Factor (plugins_loaded, default priority) has defined its classes.
add_action( 'plugins_loaded', array( Aiwos\TwoFactor\Plugin::class, 'boot' ), 20 );
