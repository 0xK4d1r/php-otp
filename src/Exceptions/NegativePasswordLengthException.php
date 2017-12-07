<?php

namespace vjolenz\OtpAuth\Exceptions;


class NegativePasswordLengthException extends \LogicException
{
    public function __construct()
    {
        parent::__construct('One-time Password length must be greater than 0');
    }
}