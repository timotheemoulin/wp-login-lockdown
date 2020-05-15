<?php
/* 
Plugin Name: Login LockDown
Plugin URI: https://github.com/timotheemoulin/wp-login-lockdown
Version: v2.0.0
Author: Michael VanDeMar
Contributors: timotheemoulin
License: GPLv2
Description: Adds some extra security to WordPress by restricting the rate at which failed logins can be re-attempted from a given IP range. Distributed through <a href="http://www.bad-neighborhood.com/" target="_blank">Bad Neighborhood</a>.
Requires at least: 3.6
Tested up to: 5.4.1
Requires PHP: 5.6
*/

__('Login LockDown', 'loginlockdown');
__('Adds some extra security to WordPress by restricting the rate at which failed logins can be re-attempted from a given IP range. Distributed through <a href="http://www.bad-neighborhood.com/" target="_blank">Bad Neighborhood</a>.', 'loginlockdown');

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

$loginlockdown_db_version = "1.1";

if ( ! defined( 'WP_PLUGIN_DIR' ) ) {
	define( 'WP_PLUGIN_DIR', ABSPATH . 'wp-content/plugins' );
}

/**
 * Triggered during plugin install.
 * Create the database structure.
 */
function loginlockdown_install() {
	global $wpdb;

	$table_name = $wpdb->prefix . "login_fails";

	if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) != $table_name ) {
		$sql = "CREATE TABLE " . $table_name . " (
			`login_attempt_ID` bigint(20) NOT NULL AUTO_INCREMENT,
			`user_id` bigint(20) NOT NULL,
			`login_attempt_date` datetime NOT NULL default '0000-00-00 00:00:00',
			`login_attempt_IP` varchar(100) NOT NULL default '',
			PRIMARY KEY  (`login_attempt_ID`)
			);";

		require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
		dbDelta( $sql );
	}

	$table_name = $wpdb->prefix . "lockdowns";

	if ( $wpdb->get_var( "SHOW TABLES LIKE '$table_name'" ) != $table_name ) {
		$sql = "CREATE TABLE " . $table_name . " (
			`lockdown_ID` bigint(20) NOT NULL AUTO_INCREMENT,
			`user_id` bigint(20) NOT NULL,
			`lockdown_date` datetime NOT NULL default '0000-00-00 00:00:00',
			`release_date` datetime NOT NULL default '0000-00-00 00:00:00',
			`lockdown_IP` varchar(100) NOT NULL default '',
			PRIMARY KEY  (`lockdown_ID`)
			);";

		require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
		dbDelta( $sql );
	}

	add_option( "loginlockdown_db_version", "1.0", "", "no" );
	// added in 1.6, cleanup from previously improperly set db versions
	delete_option( "loginlockdown_db1_version" );
	delete_option( "loginlockdown_db2_version" );
}

register_activation_hook(__FILE__, 'loginlockdown_install');

/**
 * Return the number of failing attempts for one username.
 *
 * @param string $username
 *
 * @return string|null
 */
function loginlockdown_count_fails( $username = "" ) {
	global $wpdb;
	$loginlockdownOptions = loginlockdown_get_options();
	$table_name = $wpdb->prefix . "login_fails";
	$subnet     = loginlockdown_calculate_subnet( $_SERVER['REMOTE_ADDR'] );

	$numFailsquery = "SELECT COUNT(login_attempt_ID) FROM $table_name " .
	                 "WHERE login_attempt_date + INTERVAL " .
	                 $loginlockdownOptions['retries_within'] . " MINUTE > now() AND " .
	                 "login_attempt_IP LIKE '%s'";
	$numFailsquery = $wpdb->prepare( $numFailsquery, $subnet[1] . "%" );

	$numFails = $wpdb->get_var( $numFailsquery );

	return $numFails;
}

/**
 * Increment the failing attempts number for a username.
 *
 * @param string $username
 */
function loginlockdown_increment_fails( $username = "" ) {
	global $wpdb;
	$loginlockdownOptions = loginlockdown_get_options();
	$table_name = $wpdb->prefix . "login_fails";
	$subnet     = loginlockdown_calculate_subnet( $_SERVER['REMOTE_ADDR'] );

	$username = sanitize_user( $username );
	$user     = get_user_by( 'login', $username );
	if ( $user || "yes" == $loginlockdownOptions['lockout_invalid_usernames'] ) {
		if ( $user === false ) {
			$user_id = - 1;
		} else {
			$user_id = $user->ID;
		}
		$insert  = "INSERT INTO " . $table_name . " (user_id, login_attempt_date, login_attempt_IP) " .
		           "VALUES ('" . $user_id . "', now(), '%s')";
		$insert  = $wpdb->prepare( $insert, $subnet[0] );
		$results = $wpdb->query( $insert );
	}
}

/**
 * Lock a username.
 *
 * @param string $username
 */
function loginlockdown_lock_username( $username = "" ) {
	global $wpdb;
	$loginlockdownOptions = loginlockdown_get_options();
	$table_name = $wpdb->prefix . "lockdowns";
	$subnet     = loginlockdown_calculate_subnet( $_SERVER['REMOTE_ADDR'] );

	$username = sanitize_user( $username );
	$user     = get_user_by( 'login', $username );
	if ( $user || "yes" == $loginlockdownOptions['lockout_invalid_usernames'] ) {
		if ( $user === false ) {
			$user_id = - 1;
		} else {
			$user_id = $user->ID;
		}
		$insert  = "INSERT INTO " . $table_name . " (user_id, lockdown_date, release_date, lockdown_IP) " .
		           "VALUES ('" . $user_id . "', now(), date_add(now(), INTERVAL " .
		           $loginlockdownOptions['lockout_length'] . " MINUTE), '%s')";
		$insert  = $wpdb->prepare( $insert, $subnet[0] );
		$results = $wpdb->query( $insert );
	}
}

/**
 * Check if IP has been locked.
 * @return string|null
 */
function loginlockdown_is_ip_locked() {
	global $wpdb;
	$table_name = $wpdb->prefix . "lockdowns";
	$subnet     = loginlockdown_calculate_subnet( $_SERVER['REMOTE_ADDR'] );

	$stillLockedquery = "SELECT user_id FROM $table_name " .
	                    "WHERE release_date > now() AND " .
	                    "lockdown_IP LIKE %s";
	$stillLockedquery = $wpdb->prepare( $stillLockedquery, $subnet[1] . "%" );

	$stillLocked = $wpdb->get_var( $stillLockedquery );

	return $stillLocked;
}

/**
 * Get the locked IP addresses.
 * @return array|object|null
 */
function loginlockdown_list_locked_ips() {
	global $wpdb;
	$table_name = $wpdb->prefix . "lockdowns";

	$listLocked = $wpdb->get_results(
		"SELECT lockdown_ID, floor((UNIX_TIMESTAMP(release_date)-UNIX_TIMESTAMP(now()))/60) AS minutes_left, " .
		"lockdown_IP FROM $table_name WHERE release_date > now()",
		ARRAY_A
	);

	return $listLocked;
}

/**
 * Get the plugin options
 * @return array
 */
function loginlockdown_get_options() {
	$loginLockDownOptions = [
		'max_login_retries'         => 3,
		'retries_within'            => 5,
		'lockout_length'            => 60,
		'lockout_invalid_usernames' => 'no',
		'mask_login_errors'         => 'no',
		'show_credit_link'          => 'no',
	];
	$loginlockdownOptions = get_option( "loginlockdown_admin_options" );
	if ( ! empty( $loginlockdownOptions ) ) {
		foreach ( $loginlockdownOptions as $key => $option ) {
			$loginLockDownOptions[ $key ] = $option;
		}
	}
	update_option( "loginlockdown_admin_options", $loginLockDownOptions );

	return $loginLockDownOptions;
}

/**
 * Get the IP address subnet.
 *
 * @param $ip
 *
 * @return mixed
 */
function loginlockdown_calculate_subnet( $ip ) {
	$subnet[0] = $ip;
	if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) === false ) {
		$ip = loginlockdown_expand_ipv6( $ip );
		preg_match( "/^([0-9abcdef]{1,4}:){4}/", $ip, $matches );
		$subnet[0] = $ip;
		$subnet[1] = $matches[0];
	} else {
		$subnet[1] = substr( $ip, 0, strrpos( $ip, "." ) + 1 );
	}

	return $subnet;
}

/**
 * Get the IPV6 format.
 *
 * @param $ip
 *
 * @return false|string
 */
function loginlockdown_expand_ipv6( $ip ) {
	$hex = unpack( "H*hex", inet_pton( $ip ) );
	$ip  = substr( preg_replace( "/([A-f0-9]{4})/", "$1:", $hex['hex'] ), 0, - 1 );

	return $ip;
}

/**
 * Print the admin option page.
 */
function loginlockdown_admin_page() {
	global $wpdb;
	$table_name           = $wpdb->prefix . "lockdowns";
	$loginLockDownOptions = loginlockdown_get_options();

	if ( isset( $_POST['update_loginlockdownSettings'] ) ) {

		//wp_nonce check
		check_admin_referer( 'login-lockdown_update-options' );

		if ( isset( $_POST['ll_max_login_retries'] ) ) {
			$loginLockDownOptions['max_login_retries'] = $_POST['ll_max_login_retries'];
		}
		if ( isset( $_POST['ll_retries_within'] ) ) {
			$loginLockDownOptions['retries_within'] = $_POST['ll_retries_within'];
		}
		if ( isset( $_POST['ll_lockout_length'] ) ) {
			$loginLockDownOptions['lockout_length'] = $_POST['ll_lockout_length'];
		}
		if ( isset( $_POST['ll_lockout_invalid_usernames'] ) ) {
			$loginLockDownOptions['lockout_invalid_usernames'] = $_POST['ll_lockout_invalid_usernames'];
		}
		if ( isset( $_POST['ll_mask_login_errors'] ) ) {
			$loginLockDownOptions['mask_login_errors'] = $_POST['ll_mask_login_errors'];
		}
		if ( isset( $_POST['ll_show_credit_link'] ) ) {
			$loginLockDownOptions['show_credit_link'] = $_POST['ll_show_credit_link'];
		}
		update_option( "loginlockdown_admin_options", $loginLockDownOptions );
		?>
        <div class="updated"><p><strong><?php _e( "Settings Updated.", "loginlockdown" ); ?></strong></p></div>
		<?php
	}
	if ( isset( $_POST['release_lockdowns'] ) ) {

		//wp_nonce check
		check_admin_referer( 'login-lockdown_release-lockdowns' );

		if ( isset( $_POST['releaseme'] ) ) {
			$released = $_POST['releaseme'];
			foreach ( $released as $release_id ) {
				$releasequery = "UPDATE $table_name SET release_date = now() " .
				                "WHERE lockdown_ID = '%d'";
				$releasequery = $wpdb->prepare( $releasequery, $release_id );
				$results      = $wpdb->query( $releasequery );
			}
		}
		update_option( "loginlockdown_admin_options", $loginLockDownOptions );
		?>
        <div class="updated"><p><strong><?php _e( "Lockdowns Released.", "loginlockdown" ); ?></strong></p></div>
		<?php
	}
	$dalist = loginlockdown_list_locked_ips();
	?>
    <div class="wrap">
		<?php

		$active_tab = isset( $_GET['tab'] ) ? $_GET['tab'] : 'settings';

		?>
        <h2><?php _e( 'Login LockDown Options', 'loginlockdown' ) ?></h2>

        <h2 class="nav-tab-wrapper">
            <a href="?page=loginlockdown.php&tab=settings" class="nav-tab <?php echo $active_tab == 'settings' ? 'nav-tab-active' : ''; ?>"><?php _e( 'Settings', 'loginlockdown' ) ?></a>
            <a href="?page=loginlockdown.php&tab=activity" class="nav-tab <?php echo $active_tab == 'activity' ? 'nav-tab-active' : ''; ?>"><?php _e( 'Activity', 'loginlockdown' ) ?> (<?php echo count( $dalist ); ?>)</a>
        </h2>
		<?php if ( $active_tab == 'settings' ) { ?>
            <form method="post" action="<?php echo esc_attr( $_SERVER["REQUEST_URI"] ); ?>">
				<?php
				if ( function_exists( 'wp_nonce_field' ) ) {
					wp_nonce_field( 'login-lockdown_update-options' );
				}
				?>

                <h3><?php _e( 'Max Login Retries', 'loginlockdown' ) ?></h3>
                <p><?php _e( 'Number of failed login attempts within the "Retry Time Period Restriction" (defined below) needed to trigger a LockDown.', 'loginlockdown' ) ?></p>
                <p><input type="text" name="ll_max_login_retries" size="8" value="<?php echo esc_attr( $loginLockDownOptions['max_login_retries'] ); ?>"></p>
                <h3><?php _e( 'Retry Time Period Restriction (minutes)', 'loginlockdown' ) ?></h3>
                <p><?php _e( 'Amount of time that determines the rate at which failed login attempts are allowed before a LockDown occurs.', 'loginlockdown' ) ?></p>
                <p><input type="text" name="ll_retries_within" size="8" value="<?php echo esc_attr( $loginLockDownOptions['retries_within'] ); ?>"></p>
                <h3><?php _e( 'Lockout Length (minutes)', 'loginlockdown' ) ?></h3>
                <p><?php _e( 'How long a particular IP block will be locked out for once a LockDown has been triggered.', 'loginlockdown' ) ?></p>
                <p><input type="text" name="ll_lockout_length" size="8" value="<?php echo esc_attr( $loginLockDownOptions['lockout_length'] ); ?>"></p>
                <h3><?php _e( 'Lockout Invalid Usernames?', 'loginlockdown' ) ?></h3>
                <p><?php _e( 'By default Login LockDown will not trigger if an attempt is made to log in using a username that does not exist. You can override this behavior here.', 'loginlockdown' ) ?></p>
                <p><input type="radio" name="ll_lockout_invalid_usernames" value="yes" <?php if ( $loginLockDownOptions['lockout_invalid_usernames'] == "yes" ) {
						echo "checked";
					} ?>>&nbsp;<?php _e( 'Yes', 'loginlockdown' ) ?>&nbsp;&nbsp;&nbsp;<input type="radio" name="ll_lockout_invalid_usernames" value="no" <?php if ( $loginLockDownOptions['lockout_invalid_usernames'] == "no" ) {
						echo "checked";
					} ?>>&nbsp;<?php _e( 'No', 'loginlockdown' ) ?></p>
                <h3><?php _e( 'Mask Login Errors?', 'loginlockdown' ) ?></h3>
                <p><?php _e( 'WordPress will normally display distinct messages to the user depending on whether they try and log in with an invalid username, or with a valid username but the incorrect password. Toggling this option will hide why the login failed.', 'loginlockdown' ) ?></p>
                <p><input type="radio" name="ll_mask_login_errors" value="yes" <?php if ( $loginLockDownOptions['mask_login_errors'] == "yes" ) {
						echo "checked";
					} ?>>&nbsp;<?php _e( 'Yes', 'loginlockdown' ) ?>&nbsp;&nbsp;&nbsp;<input type="radio" name="ll_mask_login_errors" value="no" <?php if ( $loginLockDownOptions['mask_login_errors'] == "no" ) {
						echo "checked";
					} ?>>&nbsp;<?php _e( 'No', 'loginlockdown' ) ?></p>
                <h3><?php _e( 'Show Credit Link?', 'loginlockdown' ) ?></h3>
                <p><?php _e( 'If enabled, Login LockDown will display the following message on the login form', 'loginlockdown' ) ?>:<br/>
                <blockquote><?php _e( 'Login form protected by', 'loginlockdown' ) ?> <a href='http://www.bad-neighborhood.com/login-lockdown.html'>Login LockDown</a>.</blockquote>
				<?php _e( 'This helps others know about the plugin so they can protect their blogs as well if they like. You can enable or disable this message below', 'loginlockdown' ) ?>:</p>
                <input type="radio" name="ll_show_credit_link" value="yes" <?php if ( $loginLockDownOptions['show_credit_link'] == "yes" || $loginLockDownOptions['show_credit_link'] == "" ) {
					echo "checked";
				} ?>>&nbsp;<?php _e( 'Yes, display the credit link.', 'loginlockdown' ) ?><br/>
                <input type="radio" name="ll_show_credit_link" value="shownofollow" <?php if ( $loginLockDownOptions['show_credit_link'] == "shownofollow" ) {
					echo "checked";
				} ?>>&nbsp;<?php _e( 'Display the credit link, but add "rel=\'nofollow\'" (ie. do not pass any link juice).', 'loginlockdown' ) ?><br/>
                <input type="radio" name="ll_show_credit_link" value="no" <?php if ( $loginLockDownOptions['show_credit_link'] == "no" ) {
					echo "checked";
				} ?>>&nbsp;<?php _e( 'No, do not display the credit link.', 'loginlockdown' ) ?><br/>
                <div class="submit">
                    <input type="submit" class="button button-primary" name="update_loginlockdownSettings" value="<?php _e( 'Update Settings', 'loginlockdown' ) ?>"/></div>
            </form>
		<?php } else { ?>
            <form method="post" action="<?php echo esc_attr( $_SERVER["REQUEST_URI"] ); ?>">
				<?php
				if ( function_exists( 'wp_nonce_field' ) ) {
					wp_nonce_field( 'login-lockdown_release-lockdowns' );
				}
				?>
                <h3><?php
					if ( count( $dalist ) == 1 ) {
						printf( esc_html__( 'There is currently %d locked out IP address.', 'loginlockdown' ), count( $dalist ) );

					} else {
						printf( esc_html__( 'There are currently %d locked out IP addresses.', 'loginlockdown' ), count( $dalist ) );
					} ?></h3>

				<?php
				$num_lockedout = count( $dalist );
				if ( 0 == $num_lockedout ) {
					echo "<p>No IP blocks currently locked out.</p>";
				} else {
					foreach ( $dalist as $key => $option ) {
						?>
                        <li><input type="checkbox" name="releaseme[]" value="<?php echo esc_attr( $option['lockdown_ID'] ); ?>"> <?php echo esc_attr( $option['lockdown_IP'] ); ?> (<?php echo esc_attr( $option['minutes_left'] ); ?> <?php _e( 'minutes left', 'loginlockdown' ) ?>)</li>
						<?php
					}
				}
				?>
                <div class="submit">
                    <input type="submit" class="button button-primary" name="release_lockdowns" value="<?php _e( 'Release Selected', 'loginlockdown' ) ?>"/></div>
            </form>
		<?php } ?>
    </div>
	<?php
}

/**
 * Add the admin menu item.
 */
function loginlockdown_admin_menu() {
	if ( function_exists( 'add_options_page' ) ) {
		add_options_page( 'Login LockDown', 'Login LockDown', 'manage_options', basename( __FILE__ ), 'loginlockdown_admin_page' );
	}
}

add_action( 'admin_menu', 'loginlockdown_admin_menu' );

/**
 * Render the credig link.
 */
function loginlockdown_print_credit_link() {
	$loginlockdownOptions = loginlockdown_get_options();
	$thispage       = "http://" . $_SERVER["HTTP_HOST"] . $_SERVER["REQUEST_URI"];
	$homepage       = get_option( "home" );
	$showcreditlink = $loginlockdownOptions['show_credit_link'];
	$relnofollow    = "rel='nofollow'";
	if ( $showcreditlink != "shownofollow" && ( $thispage == $homepage || $thispage == $homepage . "/" || substr( $_SERVER["REQUEST_URI"], strlen( $_SERVER["REQUEST_URI"] ) - 12 ) == "wp-login.php" ) ) {
		$relnofollow = "";
	}
	if ( $showcreditlink != "no" ) {
		echo "<p>";
		_e( 'Login form protected by', 'loginlockdown' );
		echo " <a href='http://www.bad-neighborhood.com/login-lockdown.html' $relnofollow>Login LockDown</a>.<br /><br /><br /></p>";
	}
}

add_action( 'login_form', 'loginlockdown_print_credit_link' );

/**
 * Authenticate the user.
 *
 * @param $user
 * @param $username
 * @param $password
 *
 * @return mixed|void|WP_Error|WP_User
 */
function loginlockdown_wp_authenticate_username_password( $user, $username, $password ) {
	if ( is_a( $user, 'WP_User' ) ) {
		return $user;
	}

	if ( empty( $username ) || empty( $password ) ) {
		$error = new WP_Error();

		if ( empty( $username ) ) {
			$error->add( 'empty_username', __( '<strong>ERROR</strong>: The username field is empty.', 'loginlockdown' ) );
		}

		if ( empty( $password ) ) {
			$error->add( 'empty_password', __( '<strong>ERROR</strong>: The password field is empty.', 'loginlockdown' ) );
		}

		return $error;
	}

	$userdata = get_user_by( 'login', $username );

	if ( ! $userdata ) {
		return new WP_Error( 'invalid_username', sprintf( __( '<strong>ERROR</strong>: Invalid username. <a href="%s" title="Password Lost and Found">Lost your password</a>?', 'loginlockdown' ), site_url( 'wp-login.php?action=lostpassword', 'login' ) ) );
	}

	$userdata = apply_filters( 'wp_authenticate_user', $userdata, $password );
	if ( is_wp_error( $userdata ) ) {
		return $userdata;
	}

	if ( ! wp_check_password( $password, $userdata->user_pass, $userdata->ID ) ) {
		return new WP_Error( 'incorrect_password', sprintf( __( '<strong>ERROR</strong>: Incorrect password. <a href="%s" title="Password Lost and Found">Lost your password</a>?', 'loginlockdown' ), site_url( 'wp-login.php?action=lostpassword', 'login' ) ) );
	}

	$user = new WP_User( $userdata->ID );

	return $user;
}

remove_filter( 'authenticate', 'wp_authenticate_username_password', 20 );
add_filter( 'authenticate', 'loginlockdown_wp_authenticate_username_password', 20, 3 );

if ( ! function_exists( 'wp_authenticate' ) ) :
	/**
	 * Authenticate the user the WordPress way.
	 *
	 * @param string $username
	 * @param string $password
	 *
	 * @return WP_User
	 */
	function wp_authenticate( $username, $password ) {
		$loginlockdownOptions = loginlockdown_get_options();

		$username = sanitize_user( $username );
		$password = trim( $password );

		if ( "" != loginlockdown_is_ip_locked() ) {
			return new WP_Error( 'incorrect_password', __( "<strong>ERROR</strong>: We're sorry, but this IP range has been blocked due to too many recent failed login attempts.<br /><br />Please try again later.", 'loginlockdown' ) );
		}

		$user = apply_filters( 'authenticate', null, $username, $password );

		if ( $user == null ) {
			// TODO what should the error message be? (Or would these even happen?)
			// Only needed if all authentication handlers fail to return anything.
			$user = new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: Invalid username or incorrect password.', 'loginlockdown' ) );
		}

		$ignore_codes = [ 'empty_username', 'empty_password' ];

		if ( is_wp_error( $user ) && ! in_array( $user->get_error_code(), $ignore_codes ) ) {
			loginlockdown_increment_fails( $username );
			if ( $loginlockdownOptions['max_login_retries'] <= loginlockdown_count_fails( $username ) ) {
				loginlockdown_lock_username( $username );

				return new WP_Error( 'incorrect_password', __( "<strong>ERROR</strong>: We're sorry, but this IP range has been blocked due to too many recent failed login attempts.<br /><br />Please try again later.", 'loginlockdown' ) );
			}
			if ( 'yes' == $loginlockdownOptions['mask_login_errors'] ) {
				return new WP_Error( 'authentication_failed', sprintf( __( '<strong>ERROR</strong>: Invalid username or incorrect password. <a href="%s" title="Password Lost and Found">Lost your password</a>?', 'loginlockdown' ), site_url( 'wp-login.php?action=lostpassword', 'login' ) ) );
			} else {
				do_action( 'wp_login_failed', $username );
			}
		}

		return $user;
	}
endif;

/**
 * Multi site network-wide activation
 *
 * @param $networkwide
 */
function loginlockdown_multisite_activate( $networkwide ) {
	global $wpdb;

	if ( function_exists( 'is_multisite' ) && is_multisite() ) {
		// check if it is a network activation - if so, run the activation function for each blog id
		if ( $networkwide ) {
			$old_blog = $wpdb->blogid;
			// Get all blog ids
			$blogids = $wpdb->get_col( "SELECT blog_id FROM $wpdb->blogs" );
			foreach ( $blogids as $blog_id ) {
				switch_to_blog( $blog_id );
				loginlockdown_install();
			}
			switch_to_blog( $old_blog );

			return;
		}
	}
}

register_activation_hook( __FILE__, 'loginlockdown_multisite_activate' );

/**
 * Multi site new site activation
 *
 * @param $blog_id
 * @param $user_id
 * @param $domain
 * @param $path
 * @param $site_id
 * @param $meta
 */
function loginlockdown_multisite_newsite( $blog_id, $user_id, $domain, $path, $site_id, $meta ) {
	global $wpdb;

	if ( is_plugin_active_for_network( 'loginlockdown/loginlockdown.php' ) ) {
		$old_blog = $wpdb->blogid;
		switch_to_blog( $blog_id );
		loginlockdown_install();
		switch_to_blog( $old_blog );
	}
}

add_action( 'wpmu_new_blog', 'loginlockdown_multisite_newsite', 10, 6 );

/**
 * Multi site old sites check
 */
function loginlockdown_multisite_legacy() {
	$loginlockdownMSRunOnce = get_option( "loginlockdown_ms_run_once" );
	if ( empty( $loginlockdownMSRunOnce ) ) {
		global $wpdb;

		if ( function_exists( 'is_multisite' ) && is_multisite() ) {

			$old_blog = $wpdb->blogid;

			// Get all blog ids
			$blogids = $wpdb->get_col( "SELECT blog_id FROM $wpdb->blogs" );
			foreach ( $blogids as $blog_id ) {

				// check if already exists
				$bed_check = $wpdb->query( "SHOW TABLES LIKE '{$wpdb->base_prefix}{$blog_id}_login_fails'" );
				if ( ! $bed_check ) {

					switch_to_blog( $blog_id );
					loginlockdown_install();

				}
			}
			switch_to_blog( $old_blog );
		}
		add_option( "loginlockdown_ms_run_once", "done", "", "no" );

		return;
	}
}

add_action( 'admin_init', 'loginlockdown_multisite_legacy' );

/**
 * Initialize the plugin.
 */
function loginlockdown_init() {
	load_plugin_textdomain( 'loginlockdown', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );

	// use a snake_case option name
	if ( $options = get_option( 'loginlockdownAdminOptions' ) ) {
		update_option( 'loginlockdown_admin_options', $options );
		delete_option( 'loginlockdownAdminOptions' );
	}

	// convert the old option
	if ( $option = get_option( 'loginlockdownmsrunonce' ) ) {
		update_option( 'loginlockdown_ms_run_once', $option );
		delete_option( 'loginlockdownmsrunonce' );
	}
}

add_action( 'plugins_loaded', 'loginlockdown_init', 10 );