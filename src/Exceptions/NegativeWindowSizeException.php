<?php

namespace vjolenz\OtpAuth\Exceptions;


class NegativeWindowSizeException extends \LogicException
{
    public function __construct()
    {
        parent::__construct('Window size must be greater than 0');
    }
}