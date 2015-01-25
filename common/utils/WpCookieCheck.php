<?php

namespace common\utils;
use common\models\User;

class WPCookieCheck {

    var $COOKIEHASH;
    var $USER_COOKIE;
    var $PASS_COOKIE;
    var $SECURE_AUTH_COOKIE;
    var $LOGGED_IN_COOKIE;
    var $AUTH_KEY;
    var $SECURE_AUTH_KEY;
    var $NONCE_KEY;
    var $LOGGED_IN_KEY;
    var $AUTH_SALT;
    var $NONCE_SALT;
    var $LOGGED_IN_SALT;

    function WPCookieCheck() {

        /// CONFIGURATION FIELDS!
        $this->AUTH_KEY = '----- TAKE THIS FROM YOUR wp-config.php -------';
        $this->SECURE_AUTH_KEY = '----- TAKE THIS FROM YOUR wp-config.php -------';
        $this->NONCE_KEY = '----- TAKE THIS FROM YOUR wp-config.php -------';
        $this->LOGGED_IN_KEY = '----- TAKE THIS FROM YOUR wp-config.php -------';
        $this->AUTH_SALT = '----- TAKE THIS FROM YOUR wp-config.php -------';
        $this->NONCE_SALT = '----- TAKE THIS FROM YOUR wp-config.php -------';
        $this->LOGGED_IN_SALT = '----- TAKE THIS FROM YOUR wp-config.php -------';
        $this->COOKIEHASH = md5('----- YOUR WEBSITE ADDRESS LIKE http://example.com -------');


        $this->USER_COOKIE = 'wordpressuser_' . $this->COOKIEHASH;
        $this->PASS_COOKIE = 'wordpress_' . $this->COOKIEHASH;
        $this->SECURE_AUTH_COOKIE = 'wordpress_sec_' . $this->COOKIEHASH;
        $this->LOGGED_IN_COOKIE = 'wordpress_logged_in_' . $this->COOKIEHASH;
        $this->AUTH_COOKIE = 'wordpress_' . $this->COOKIEHASH;
    }

    public function wp_validate_auth_cookie($cookie = '', $scheme = '') {

        if (!$cookie_elements = $this->wp_parse_auth_cookie($cookie, $scheme)) {

            return false;
        }

        $scheme = $cookie_elements['scheme'];
        $username = $cookie_elements['username'];
        $hmac = $cookie_elements['hmac'];
        $token = $cookie_elements['token'];
        $expired = $expiration = $cookie_elements['expiration'];

        // Quick check to see if an honest cookie has expired
        if ($expired < time()) {
            return false;
        }

        $user = User::findByUsername($username);

        if (!$user) {
            return false;
        }

        $pass_frag = substr($user->password_hash, 8, 4);

        $key = $this->wp_hash($username . '|' . $pass_frag . '|' . $expiration . '|' . $token, $scheme);



        // If ext/hash is not present, compat.php's hash_hmac() does not support sha256.
        $algo = function_exists('hash') ? 'sha256' : 'sha1';
        $hash = hash_hmac($algo, $username . '|' . $expiration . '|' . $token, $key);

        if (!$this->hash_equals($hash, $hmac)) {
            return false;
        }

        return $user->ID;
    }

    public function hash_equals($a, $b) {
        $a_length = strlen($a);
        if ($a_length !== strlen($b)) {
            return false;
        }
        $result = 0;

        // Do not attempt to "optimize" this.
        for ($i = 0; $i < $a_length; $i++) {
            $result |= ord($a[$i]) ^ ord($b[$i]);
        }

        return $result === 0;
    }

    pubilic function wp_parse_auth_cookie($cookie = '', $scheme = '') {

        if (empty($cookie)) {
            switch ($scheme) {
                case 'auth':
                    $cookie_name = $this->AUTH_COOKIE;
                    break;
                case 'secure_auth':
                    $cookie_name = $this->SECURE_AUTH_COOKIE;
                    break;
                case "logged_in":
                    $cookie_name = $this->LOGGED_IN_COOKIE;
                    break;
                default:
                    $cookie_name = $this->AUTH_COOKIE;
                    $scheme = 'auth';
            }



            if (empty($_COOKIE[$cookie_name]))
                return false;
            $cookie = $_COOKIE[$cookie_name];
        }
        $cookie_elements = explode('|', $cookie);
        if (count($cookie_elements) !== 4) {
            return false;
        }
        list( $username, $expiration, $token, $hmac ) = $cookie_elements;

        return compact('username', 'expiration', 'token', 'hmac', 'scheme');
    }

    public function wp_hash($data, $scheme = 'auth') {
        $salt = $this->wp_salt($scheme);      
        return hash_hmac('md5', $data, $salt);
    }

    public function wp_salt($scheme = 'auth') {
        static $cached_salts = array();
        static $duplicated_keys;
        if (null === $duplicated_keys) {
            $duplicated_keys = array('put your unique phrase here' => true);
            foreach (array('AUTH', 'SECURE_AUTH', 'LOGGED_IN', 'NONCE', 'SECRET') as $first) {
                foreach (array('KEY', 'SALT') as $second) {
                    if (!defined("{$first}_{$second}")) {
                        continue;
                    }
                    $value = constant("{$first}_{$second}");
                    $duplicated_keys[$value] = isset($duplicated_keys[$value]);
                }
            }
        }

        $values = array(
            'key' => '',
            'salt' => ''
        );
        if (defined('SECRET_KEY') && SECRET_KEY && empty($duplicated_keys[SECRET_KEY])) {
            $values['key'] = SECRET_KEY;
        }
        if ('auth' == $scheme && defined('SECRET_SALT') && SECRET_SALT && empty($duplicated_keys[SECRET_SALT])) {
            $values['salt'] = SECRET_SALT;
        }
        if (in_array($scheme, array('auth', 'secure_auth', 'logged_in', 'nonce'))) {
            foreach (array('key', 'salt') as $type) {
                $const = strtoupper("{$scheme}_{$type}");
                if ($this->$const) {

                    $values[$type] = $this->$const;
                }
            }


//
            $cached_salts[$scheme] = $values['key'] . $values['salt'];

//
//        /** This filter is documented in wp-includes/pluggable.php */
            return $cached_salts[$scheme];
        }
    }

    public function hash_hmac($algo, $data, $key, $raw_output = false) {
        echo '<pre>';
        var_dump($algo);
        var_dump($data);
        var_dump($key);
        var_dump($raw_output);
        echo '</pre>';
        return $this->_hash_hmac($algo, $data, $key, $raw_output);
    }

    public function _hash_hmac($algo, $data, $key, $raw_output = false) {
        $packs = array('md5' => 'H32', 'sha1' => 'H40');

        if (!isset($packs[$algo]))
            return false;

        $pack = $packs[$algo];

        if (strlen($key) > 64)
            $key = pack($pack, $algo($key));

        $key = str_pad($key, 64, chr(0));

        $ipad = (substr($key, 0, 64) ^ str_repeat(chr(0x36), 64));
        $opad = (substr($key, 0, 64) ^ str_repeat(chr(0x5C), 64));

        $hmac = $algo($opad . pack($pack, $algo($ipad . $data)));

        if ($raw_output)
            return pack($pack, $hmac);
        return $hmac;
    }

}
