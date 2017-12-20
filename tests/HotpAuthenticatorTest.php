<?php

namespace vjolenz\OtpAuth\Test;

use PHPUnit\Framework\TestCase;
use vjolenz\OtpAuth\Exceptions\NegativePasswordLengthException;
use vjolenz\OtpAuth\Exceptions\NegativeWindowSizeException;
use vjolenz\OtpAuth\Exceptions\UnsuitableHashingAlgorithmException;
use vjolenz\OtpAuth\HotpAuthenticator;

class HotpAuthenticatorTest extends TestCase
{
    /** @var  \vjolenz\OtpAuth\HotpAuthenticator */
    private $authenticator;

    /**
     * @var array Test cases taken from related RFC
     * @see https://tools.ietf.org/html/rfc4226#page-32 for more info
     */
    private $rfcTestCases = [
        0 => 755224,
        1 => 287082,
        2 => 359152,
        3 => 969429,
        4 => 338314,
        5 => 254676,
        6 => 287922,
        7 => 162583,
        8 => 399871,
        9 => 520489,
    ];

    public function setUp()
    {
        parent::setUp();

        $this->authenticator = new HotpAuthenticator();
        $this->authenticator->setSecret('12345678901234567890');
    }

    /** @test */
    public function should_generate_a_valid_password()
    {
        foreach ($this->rfcTestCases as $movingFactor => $expectedPassword) {
            $this->assertEquals($expectedPassword, $this->authenticator->generatePassword($movingFactor));
        }
    }

    /** @test */
    public function generatePassword_should_pad_on_the_left_with_0_if_length_of_generated_password_is_lower_than_expected()
    {
        $this->authenticator->setPasswordLength(12);

        $password = $this->authenticator->generatePassword();

        $this->assertStringStartsWith('00', $password);
        $this->assertEquals(12, strlen($password));
    }

    /** @test */
    public function should_verify_password()
    {
        foreach ($this->rfcTestCases as $movingFactor => $password) {
            $this->assertTrue($this->authenticator->verifyPassword($password, $movingFactor));
        }
    }

    /** @test */
    public function verifyPassword_should_return_true_if_given_password_in_window_size()
    {
        $this->authenticator->setWindowSize(2);

        // Passwords and movingFactor are taken from RFC document

        // Should return true for (n-2)th and (n+2)th password (0, 1, 3, 4)
        $this->assertTrue($this->authenticator->verifyPassword(755224, 2));
        $this->assertTrue($this->authenticator->verifyPassword(287082, 2));
        $this->assertTrue($this->authenticator->verifyPassword(969429, 2));
        $this->assertTrue($this->authenticator->verifyPassword(338314, 2));

        // Should return false for other passwords (5, 6)
        $this->assertFalse($this->authenticator->verifyPassword(254676, 2));
        $this->assertFalse($this->authenticator->verifyPassword(287922, 2));
    }

    /** @test */
    public function secret_key_can_be_set()
    {
        $this->authenticator->setSecret('JDDK4U6G3BJLEZ7Y');

        $this->assertEquals('JDDK4U6G3BJLEZ7Y', $this->authenticator->getSecret());
    }

    /** @test */
    public function hashing_algorithm_can_be_set()
    {
        $this->authenticator->setAlgorithm('sha256');

        $this->assertEquals('sha256', $this->authenticator->getAlgorithm());
    }

    /** @test */
    public function given_algorithm_to_setAlgorithm_should_be_suitable_for_hash_hmac()
    {
        $this->expectException(UnsuitableHashingAlgorithmException::class);

        $algo = 'non-existent-algorithm';

        $this->authenticator->setAlgorithm($algo);
    }

    /** @test */
    public function password_length_cant_be_lower_than_1()
    {
        $this->expectException(NegativePasswordLengthException::class);
        $this->authenticator->setPasswordLength(-10);
    }

    /** @test */
    public function window_can_be_set()
    {
        $this->authenticator->setWindowSize(3);

        $this->assertEquals(3, $this->authenticator->getWindowSize());
    }

    /** @test */
    public function window_cant_be_lower_then_0()
    {
        $this->expectException(NegativeWindowSizeException::class);

        $this->authenticator->setWindowSize(-1);
    }
}
