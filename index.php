<?php
session_start();

$client_id = '';
$client_secret = '';
$redirect_uri = 'http://localhost:8080/';
$metadata_url = 'https://*.okta.com/oauth2/default/.well-known/openid-configuration';



if(isset($_GET['logout'])) {
  unset($_SESSION['username']);
  unset($_SESSION['sub']);
  header('Location: /');
  die();
}

if(isset($_SESSION['sub'])) {
  echo '<p>Logged in as</p>';
  echo '<p>' . $_SESSION['username'] . '</p>';
  echo '<p><a href="/?logout">Log Out</a></p>';
  die();
}


$metadata = http($metadata_url);

if(!isset($_GET['code'])) {

  $_SESSION['state'] = bin2hex(random_bytes(5));
  $_SESSION['code_verifier'] = bin2hex(random_bytes(50));
  $code_challenge = base64_urlencode(hash('sha256', $_SESSION['code_verifier'], true));

  $authorize_url = $metadata->authorization_endpoint.'?'.http_build_query([
    'response_type' => 'code',
    'client_id' => $client_id,
    'redirect_uri' => $redirect_uri,
    'state' => $_SESSION['state'],
    'scope' => 'openid profile',
    'code_challenge' => $code_challenge,
    'code_challenge_method' => 'S256',
  ]);

  echo '<p>Not logged in</p>';
  echo '<p><a href="'.$authorize_url.'">Log In</a></p>';

} else {

  if($_SESSION['state'] != $_GET['state']) {
    die('Authorization server returned an invalid state parameter');
  }

  if(isset($_GET['error'])) {
    die('Authorization server returned an error: '.htmlspecialchars($_GET['error']));
  }

  $response = http($metadata->token_endpoint, [
    'grant_type' => 'authorization_code',
    'code' => $_GET['code'],
    'redirect_uri' => $redirect_uri,
    'client_id' => $client_id,
    'client_secret' => $client_secret,
    'code_verifier' => $_SESSION['code_verifier'],
  ]);

  if(!isset($response->access_token)) {
    die('Error fetching access token');
  }

  $userinfo = http($metadata->userinfo_endpoint, [
    'access_token' => $response->access_token,
  ]);

  if($userinfo->sub) {
    $_SESSION['sub'] = $userinfo->sub;
    $_SESSION['username'] = $userinfo->preferred_username;
    $_SESSION['profile'] = $userinfo;
    header('Location: /');
    die();
  }

}



// Base64-urlencoding is a simple variation on base64-encoding
// Instead of +/ we use -_, and the trailing = are removed.
function base64_urlencode($string) {
  return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
}


function http($url, $params=false) {
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  if($params)
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
  return json_decode(curl_exec($ch));
}

