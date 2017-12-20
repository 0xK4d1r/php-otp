<?php

namespace vjolenz\OtpAuth\Test;

use PHPUnit\Framework\TestCase;
use vjolenz\OtpAuth\Exceptions\NegativeIntervalException;
use vjolenz\OtpAuth\TotpAuthenticator;

class TotpAuthenticatorTest extends TestCase
{
    private $authenticator;

    public function setUp()
    {
        parent::setUp();

        $this->authenticator = new TotpAuthenticator();
    }

    /** @test */
    public function should_generate_a_valid_password()
    {
        /*
         * Test values are taken from related RFC
         * @see https://tools.ietf.org/html/rfc6238#appendix-B for more info
         */
        $this->authenticator->setSecret('12345678901234567890');
        $this->authenticator->setPasswordLength(8);

        $testCases = [
            1234567890 => 89005924,
            59         => 94287082,
            2000000000 => 69279037,
        ];

        foreach ($testCases as $movingFactor => $expectedPassword) {
            $this->assertEquals($expectedPassword, $this->authenticator->generatePassword($movingFactor));
        }
    }

    /** @test */
    public function should_verify_password()
    {
        /*
         * Test values are taken from related RFC
         * @see https://tools.ietf.org/html/rfc6238#appendix-B for more info
         */
        $this->authenticator->setSecret('12345678901234567890');
        $this->authenticator->setPasswordLength(8);

        $testCases = [
            1234567890 => 89005924,
            59         => 94287082,
            2000000000 => 69279037,
        ];

        foreach ($testCases as $timestamp => $password) {
            $this->assertTrue($this->authenticator->verifyPassword($password, $timestamp));
        }
    }

    /** @test */
    public function verifyPassword_should_return_true_if_given_password_in_window_size()
    {
        $this->authenticator->setSecret('12345678901234567890');
        $this->authenticator->setWindowSize(2);

        // Timestamp to be used in generating newer and older timestamps
        $timestamp = 1512686960;

        $windowSize = $this->authenticator->getWindowSize();
        $interval = $this->authenticator->getInterval();

        // Create passwords using older and newer timestamps
        for ($i = -$windowSize; $i < $windowSize; $i++) {
            $pass = $this->authenticator->generatePassword($timestamp + ($i * $interval));

            $this->assertTrue($this->authenticator->verifyPassword($pass, $timestamp));
        }

        // Should return false for other passwords that are not in window size
        $invalidOlderPass = $this->authenticator->generatePassword($timestamp - 100000000);
        $invalidNewerPass = $this->authenticator->generatePassword($timestamp + 100000000);

        $this->assertFalse($this->authenticator->verifyPassword($invalidOlderPass, $timestamp));
        $this->assertFalse($this->authenticator->verifyPassword($invalidNewerPass, $timestamp));
    }

    /** @test */
    public function interval_can_be_set()
    {
        $this->authenticator->setInterval(60);

        $this->assertEquals(60, $this->authenticator->getInterval());
    }

    /** @test */
    public function interval_cant_be_lower_than_0()
    {
        $this->expectException(NegativeIntervalException::class);

        $this->authenticator->setInterval(-10);
    }
}
