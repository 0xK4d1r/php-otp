<?php

namespace vjolenz\OtpAuth;


interface OtpAuthenticatorInterface
{
    /**
     * Generate one-time password
     *
     * @return string
     */
    public function generatePassword(): string;

    /**
     * Verify one-time password
     *
     * @param int|string $password the one-time password to be verified
     * @return bool
     */
    public function verifyPassword($password): bool;
}