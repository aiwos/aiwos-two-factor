<?php
/**
 * Aiwos Two Factor
 *
 * @package     Two_Factor
 * @author      Plugin Contributors
 * @copyright   2020 Plugin Contributors
 * @license     GPL-2.0-or-later
 *
 * @wordpress-plugin
 * Plugin Name: Aiwos Two Factor
 * Plugin URI: https://github.com/aiwos/aiwos-two-factor
 * Description: Customized Two Factor plugin.
 * Author: Aiwos, Plugin Contributors
 * Version: 1.0
 * Author URI: https://github.com/wordpress/two-factor/graphs/contributors
 * Network: True
 * Text Domain: aiwos-two-factor
 */

/**
 * Shortcut constant to the path of this file.
 */
define( 'TWO_FACTOR_DIR', plugin_dir_path( __FILE__ ) );

/**
 * Version of the plugin.
 */
define( 'TWO_FACTOR_VERSION', '1.0' );

/**
 * Include the base class here, so that other plugins can also extend it.
 */
require_once TWO_FACTOR_DIR . 'providers/class-two-factor-provider.php';

/**
 * Include the core that handles the common bits.
 */
require_once TWO_FACTOR_DIR . 'class-two-factor-core.php';

/**
 * A compatibility layer for some of the most-used plugins out there.
 */
require_once TWO_FACTOR_DIR . 'class-two-factor-compat.php';

$two_factor_compat = new Two_Factor_Compat();

Two_Factor_Core::add_hooks( $two_factor_compat );

// Delete our options and user meta during uninstall.
register_uninstall_hook( __FILE__, array( Two_Factor_Core::class, 'uninstall' ) );
