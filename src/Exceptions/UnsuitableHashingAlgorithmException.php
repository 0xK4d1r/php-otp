<?php

namespace vjolenz\OtpAuth\Exceptions;

class UnsuitableHashingAlgorithmException extends \InvalidArgumentException
{
    public function __construct()
    {
        parent::__construct('Given hashing algorithm is unsuitable for hash_hmac function');
    }
}
