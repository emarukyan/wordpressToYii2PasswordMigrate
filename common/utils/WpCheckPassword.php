<?php
namespace common\utils;

use common\utils\WpPasswordHash;

class WpCheckPassword extends User {
    function wp_check_password($password, $hash, $user_id = '') {
        $wp_hasher = new WpPasswordHash();
        $wp_hasher->PasswordHash(8, true);
        $check = $wp_hasher->CheckPassword($password, $hash); //check if password true
 
        return $check;
    }
}