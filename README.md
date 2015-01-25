WordPress 2 Yii2 Password Migration
===================================

These are helper classes, taken from WordPress Source Code.

If you are migrating a website from WordPress to Yii2, and want to be able to handle user 
authentication basedn on WordPress `user` table pwsswords, you will need WordPress functions
to validate password.



HOW DOES IT WORK
----------------
This script will check, to see if user has Yii2 password hash or WordPress one.
Check is based on password_hash length. If password_hash is not 60 characters, then
system tries to validate password via WordPress functions.
And if succeed, it will then convert the raw password into Yii2 password hash, 
generate and auth_key and save into database. So that after first log-in, users will have Yii2 password hash.



WORDPRESS COOKIE LOG-IN
----------------------
This script is able to handle log-ins, via WordPress cookies.
For this you need to configure parameters in WpCookieCheck.php,
crate instance of WPCookieCheck class, and call wp_validate_auth_cookie() function.


DIRECTORY STRUCTURE
-------------------

This is based on yii2 advanced application template
root
	/_protected
		/backend
		/common
			/utils
				- WpCheckPassword.php
				- WpCookiesCheck.php
				- WpPasswordHash.php
		/frontend
			/models
				- UserIdentity.php
