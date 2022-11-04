<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */


// ** Database settings - You can get this info from your web host ** //
define( 'DB_DIR', __DIR__ );
define( 'DB_FILE', 'database.sqlite');

define( 'DB_NAME'       , 'null-db-name' );
define( 'DB_USER'       , 'null-db-user' );
define( 'DB_PASSWORD'   , 'null-db-pass' );
define( 'DB_HOST'       , 'null-db-host' );
define( 'DB_CHARSET'    , 'utf8' );
define( 'DB_COLLATE'    , '' );


/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* Add any custom values between this line and the "stop editing" line. */


/* Enable SSL, depending on WP_HOME value */
if (strpos(getenv('WP_HOME'), 'https') === 0) {
      $_SERVER['HTTPS']='on';
}


/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

define( 'UPLOADS', '/usr/src/wordpress' );

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
