<?php
/*
Plugin Name: OpenID Logins
Plugin URI: https://github.com/meet/wp-openid
Description: Use OpenID logins.
Version: 1.0
Author: Max Goldman
License: X11 License
*/

require_once "wp-openid-config.php";
require_once "Auth/OpenID/Consumer.php";
require_once "Auth/OpenID/FileStore.php";
require_once "Auth/OpenID/AX.php";

function openid_login_store() {
  $store_path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'wordpress_openid_logins';
  if ( ! file_exists($store_path)) { mkdir($store_path); }
  return new Auth_OpenID_FileStore($store_path);
}

function openid_login_consumer() {
  return new Auth_OpenID_Consumer(openid_login_store());
}

function openid_login_scheme() {
    if (isset($_SERVER['HTTPS']) and $_SERVER['HTTPS'] == 'on') { return 'https'; }
    return 'http';
}

function openid_login_return_to() {
  return plugins_url('return', __FILE__);
}

function openid_login_trust_root() {
  return plugins_url('', __FILE__);
}

function openid_login_attributes() {
  return Array(
    'username' => Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson/friendly',1,1,'username'),
    'groups' => Auth_OpenID_AX_AttrInfo::make('http://id.meet.mit.edu/schema/groups-csv',1,1,'groups')
  );
}

function openid_login_head() {
  echo '<link rel="stylesheet" href="'.plugins_url('css/login.css', __FILE__).'" type="text/css">';
}
add_action('login_head', 'openid_login_head');

function openid_login_form() {
  global $openid_login_provider;
  $auth_req = openid_login_consumer()->begin($openid_login_provider);
  $ax_req = new Auth_OpenID_AX_FetchRequest;
  foreach (openid_login_attributes() as $attr) {
    $ax_req->add($attr);
  }
  $auth_req->addExtension($ax_req);
  $url = $auth_req->redirectURL(openid_login_trust_root(), openid_login_return_to());
  echo '<div id="openid-login">';
  if ($_REQUEST['action'] == 'openid-failed') {
    echo '<div id="login_error">OpenID login failed:<br/>'.esc_attr__($_REQUEST['message']).'</div>';
  } elseif ($_REQUEST['action'] == 'openid-only') {
    echo '<div id="login_error">WordPress does not know your password.</div>';
  }
  echo '<a class="button button-primary" href="'.$url.'">Click here to log in</a>';
  echo '<p>The form below will not work.</p>';
  echo '</div>';
}
add_action('login_form', 'openid_login_form');

function openid_login_parse_request($wp) {
  if (site_url($wp->query_vars['pagename']) == openid_login_return_to()) {
    $auth_resp = openid_login_consumer()->complete(openid_login_return_to());
    switch ($auth_resp->status) {
      case Auth_OpenID_SUCCESS:
        $ax = new Auth_OpenID_AX_FetchResponse();
        openid_login_user($ax->fromSuccessResponse($auth_resp)->data);
        break;
      case Auth_OpenID_CANCEL:
        wp_safe_redirect('/wp-login.php?action=openid-failed&message=Cancelled');
        break;
      case Auth_OpenID_FAILURE:
        wp_safe_redirect('/wp-login.php?action=openid-failed&message='.urlencode($auth_resp->message));
        break;
    }
    exit;
  }
}
add_action('parse_request', 'openid_login_parse_request');

function openid_login_user($ax) {
  global $openid_login_email_domain;
  $attrs = openid_login_attributes();
  $username = $ax[$attrs['username']->type_uri][0];
  $groups = $ax[$attrs['groups']->type_uri][0];
  $user = get_userdatabylogin($username);
  if ( ! $user) {
    $id = wp_insert_user(array(
      'user_login' => $username,
      'user_email' => $username.'@'.$openid_login_email_domain,
      'role' => 'contributor'
    ));
    if (is_wp_error($id)) {
      wp_safe_redirect('/wp-login.php?action=openid-failed&message='.urlencode($id->get_error_message()));
      exit;
    } else {
      $user = get_userdata($id);
    }
  }
  if ( ! $user) {
    wp_safe_redirect('/wp-login.php?action=openid-failed&message=WordPress user error');
  } else {
    wp_set_auth_cookie($user->ID, FALSE, TRUE);
    do_action('wp_login', $user->user_login);
    wp_safe_redirect(admin_url());
  }
  exit;
}

function openid_login_lost_password() {
  wp_safe_redirect('/wp-login.php?action=openid-only');
  exit;
}
add_action('lost_password', 'openid_login_lost_password');
add_action('lostpassword_post', 'openid_login_lost_password');

function openid_login_errors($errors) {
  return preg_replace('/<a .*>Lost your password<\/a>\?/', '', $errors);
}
add_filter('login_errors', 'openid_login_errors');
?>
