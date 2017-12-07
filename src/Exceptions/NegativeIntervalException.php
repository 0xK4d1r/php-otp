<?php

namespace vjolenz\OtpAuth\Exceptions;


class NegativeIntervalException extends \LogicException
{
    public function __construct()
    {
        parent::__construct('Interval must be greater than 0');
    }
}