<?php

namespace vjolenz\OtpAuth;

use vjolenz\OtpAuth\Exceptions\NegativePasswordLengthException;
use vjolenz\OtpAuth\Exceptions\NegativeWindowSizeException;

class HotpAuthenticator implements OtpAuthenticatorInterface
{
    /**
     * @var string Key to be used in hash creation
     */
    protected $secret;

    /**
     * @var string hashing algorithm to be used in hash creation
     */
    protected $algorithm = 'sha1';

    /**
     * @var int Flexibility to accept previous nth and next nth password
     */
    protected $windowSize = 1;

    /**
     * @var int Length of the password that will generated
     */
    protected $passwordLength = 6;

    /**
     * Generate one-time password using given moving factor.
     *
     * @param $movingFactor int a value that changes on a per use basis.
     *
     * @return string generated one-time password
     */
    public function generatePassword(int $movingFactor = 1): string
    {
        $binaryMovingFactor = pack('N*', 0, $movingFactor);

        $hash = hash_hmac($this->algorithm, $binaryMovingFactor, $this->secret, true);

        $hashByteArray = unpack('C*', $hash);

        // Array should be re-indexed
        // Since unpack returns array with index starting from 1
        $hashByteArray = array_values($hashByteArray);

        $offset = $hashByteArray[count($hashByteArray) - 1] & 0xF;

        $binary = ($hashByteArray[$offset] & 0x7F) << 24 |
            ($hashByteArray[$offset + 1] & 0xFF) << 16 |
            ($hashByteArray[$offset + 2] & 0xFF) << 8 |
            ($hashByteArray[$offset + 3] & 0xFF);

        $password = $binary % pow(10, $this->passwordLength);

        return (string) $password;
    }

    /**
     * Verify one-time password using given moving factor.
     *
     * @param int|string $password
     * @param int        $movingFactor
     *
     * @return bool
     */
    public function verifyPassword($password, int $movingFactor = 1): bool
    {
        return $this->isPasswordInGivenWindow($password, $movingFactor, $this->windowSize);
    }

    /**
     * Check if password is in given window.
     *
     * @param $password
     * @param int $movingFactor
     * @param int $windowSize
     *
     * @return bool
     */
    protected function isPasswordInGivenWindow($password, int $movingFactor, int $windowSize): bool
    {
        for ($i = $movingFactor - $windowSize; $i <= $movingFactor + $windowSize; $i++) {
            if ($this->generatePassword($i) == $password) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * @param string $secret
     */
    public function setSecret(string $secret): void
    {
        $this->secret = $secret;
    }

    /**
     * @return string
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * @param string $algorithm
     *
     */
    public function setAlgorithm(string $algorithm): void
    {
        $this->algorithm = $algorithm;
    }

    /**
     * @return int
     */
    public function getPasswordLength(): int
    {
        return $this->passwordLength;
    }

    /**
     * @param int $passwordLength
     *
     * @throws \vjolenz\OtpAuth\Exceptions\NegativePasswordLengthException
     */
    public function setPasswordLength(int $passwordLength): void
    {
        if ($passwordLength < 1) {
            throw new NegativePasswordLengthException();
        }
        $this->passwordLength = $passwordLength;
    }

    /**
     * @return int
     */
    public function getWindowSize(): int
    {
        return $this->windowSize;
    }

    /**
     * @param int $windowSize
     *
     * @throws \vjolenz\OtpAuth\Exceptions\NegativeWindowSizeException
     */
    public function setWindowSize(int $windowSize): void
    {
        if ($windowSize < 0) {
            throw new NegativeWindowSizeException();
        }
        $this->windowSize = $windowSize;
    }
}
