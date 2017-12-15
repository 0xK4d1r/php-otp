# PHP OTP (One Time Password) Implementation

A PHP library to generate and verify one-time passwords. It is compatible with [HOTP](http://tools.ietf.org/html/rfc4226) 
and [TOTP](http://tools.ietf.org/html/rfc6238).

## Prerequisites

This library needs at least `PHP 7.2`.

[Click here](https://github.com/vjolenz/php-otp/tree/7.0-7.1-compatible) if you are using php 7.0 or 7.1

## Usage

### Basic Usage

#### Defaults
The defaults that will be used if you are not explicitly specify   
    
    Secret => NULL
    Hashing algorithm => SHA1
    Window size => 1
    Password length => 6
    Interval => 30 // for TOTP

#### HOTP

##### Create Password
 ```php
    $user = User::find(1);
    
    $authenticator = new vjolenz\OtpAuth\HotpAuthenticator;
    $authenticator->setSecret('12345678901234567890');
    
    $password = $authenticator->generatePassword($user->getLoginCounter());
```

##### Verify Password
 ```php
    $user = User::find(1);
    
    $authenticator = new vjolenz\OtpAuth\HotpAuthenticator;
    $authenticator->setSecret('12345678901234567890');
    
    $authenticator->verifyPassword($password, $user->getLoginCounter());
```

#### TOTP

##### Create Password
 ```php
    $user = User::find(1);
    
    $authenticator = new vjolenz\OtpAuth\HotpAuthenticator;
    $authenticator->setSecret('12345678901234567890');
    
    $password = $authenticator->generatePassword();
```

##### Verify Password
 ```php
    $user = User::find(1);
    
    $authenticator = new vjolenz\OtpAuth\HotpAuthenticator;
    $authenticator->setSecret('12345678901234567890');
    
    $authenticator->verifyPassword($password);
```