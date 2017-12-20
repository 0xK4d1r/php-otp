# PHP OTP (One Time Password) Implementation

[![Build Status](https://travis-ci.org/vjolenz/php-otp.svg?branch=master)](https://travis-ci.org/vjolenz/php-otp)
[![StyleCI](https://styleci.io/repos/113509427/shield?branch=master)](https://styleci.io/repos/113509427)

A PHP library to generate and verify one-time passwords. It is compatible with [HOTP](http://tools.ietf.org/html/rfc4226) 
and [TOTP](http://tools.ietf.org/html/rfc6238).

## Prerequisites

This library needs at least `PHP 7.2`.

[Click here](https://github.com/vjolenz/php-otp/tree/7.0-7.1-compatible) if you are using `PHP 7.0` or `PHP 7.1`

## HOTP USAGE

Generation and verification requires a moving factor that changes on per use. You can use a login counter
as moving factor.

##### Create Password
 ```php
    $user = User::find(1);
    
    $authenticator = new \vjolenz\OtpAuth\HotpAuthenticator();
    $authenticator->setSecret('12345678901234567890'); // Default: null
    $authenticator->setAlgorithm('SHA256'); // Default: SHA1
    $authenticator->setWindowSize(3); // Default: 1
    $authenticator->setPasswordLength(9); // Default: 6
    
    $password = $authenticator->generatePassword($user->getLoginCounter());
    
    $user->advanceLoginCounter();
```

##### Verify Password
 ```php
    $user = User::find(1);
    
    $authenticator = new \vjolenz\OtpAuth\HotpAuthenticator();
    $authenticator->setSecret('12345678901234567890'); // Default: null
    $authenticator->setAlgorithm('SHA256'); // Default: SHA1
    $authenticator->setWindowSize(3); // Default: 1
    $authenticator->setPasswordLength(9); // Default: 6
    
    $authenticator->verifyPassword($password, $user->getLoginCounter());
```

## TOTP USAGE

Unlike HOTP generation and verification, you don't need a moving factor since the current timestamp is used 
for these operations

##### Create Password
 ```php
    $authenticator = new \vjolenz\OtpAuth\TotpAuthenticator();
    $authenticator->setSecret('12345678901234567890'); // Default: null
    $authenticator->setAlgorithm('SHA256'); // Default: SHA1
    $authenticator->setWindowSize(3); // Default: 1
    $authenticator->setPasswordLength(9); // Default: 6
    $authenticator->setInterval(60); // Default: 30
    
    $password = $authenticator->generatePassword();
```
 

##### Verify Password
 ```php
    $user = User::find(1);
    
    $authenticator = new \vjolenz\OtpAuth\TotpAuthenticator();
    $authenticator->setSecret('12345678901234567890'); // Default: null
    $authenticator->setAlgorithm('SHA256'); // Default: SHA1
    $authenticator->setWindowSize(3); // Default: 1
    $authenticator->setPasswordLength(9); // Default: 6
    $authenticator->setInterval(60); // Default: 30
    
    $authenticator->verifyPassword($password);
```

## License

The MIT License (MIT). Please see [License File](LICENSE.MD) for more information.