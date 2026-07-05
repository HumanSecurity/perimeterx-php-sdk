<?php

use Perimeterx\PerimeterxContext;
use Perimeterx\PerimeterxActivitiesClient;
use Perimeterx\PerimeterxHttpClient;
use Psr\Log\AbstractLogger;

class PerimeterxOrigCookieVidTest extends PHPUnit\Framework\TestCase
{
    const VALID_VID = '69521dce-ab65-11e6-80f5-76304dec7eb7';
    const INVALID_VID = 'not-a-valid-uuid';
    const AUTH_TOKEN = 'test_auth_token';
    const APP_ID = 'PXtest123';
    const SDK_NAME = 'Test v1.0';

    public function testIsValidVidWithValidUuid()
    {
        $this->assertTrue(PerimeterxContext::isValidVid(self::VALID_VID));
    }

    public function testIsValidVidWithInvalidUuid()
    {
        $this->assertFalse(PerimeterxContext::isValidVid(self::INVALID_VID));
    }

    public function testIsValidVidWithEmptyString()
    {
        $this->assertFalse(PerimeterxContext::isValidVid(''));
    }

    public function testIsValidVidWithUppercaseUuid()
    {
        $this->assertFalse(PerimeterxContext::isValidVid('69521DCE-AB65-11E6-80F5-76304DEC7EB7'));
    }

    public function testIsValidVidRejectsPartialMatch()
    {
        $this->assertFalse(PerimeterxContext::isValidVid('prefix-69521dce-ab65-11e6-80f5-76304dec7eb7'));
        $this->assertFalse(PerimeterxContext::isValidVid('69521dce-ab65-11e6-80f5-76304dec7eb7-suffix'));
    }

    public function testInvalidPxvidSetsOrigCookieVid()
    {
        $pxCtx = $this->createContextWithPxvid(self::INVALID_VID);

        $this->assertEquals(self::INVALID_VID, $pxCtx->getOrigCookieVid());
        $this->assertNull($pxCtx->getVid());
        $this->assertNull($pxCtx->getVidSource());
    }

    public function testValidPxvidSetsVidAndSource()
    {
        $pxCtx = $this->createContextWithPxvid(self::VALID_VID);

        $this->assertEquals(self::VALID_VID, $pxCtx->getVid());
        $this->assertEquals('vid_cookie', $pxCtx->getVidSource());
        $this->assertNull($pxCtx->getOrigCookieVid());
    }

    public function testMissingPxvidSetsNothing()
    {
        $pxCtx = $this->createContextWithPxvid(null);

        $this->assertNull($pxCtx->getVid());
        $this->assertNull($pxCtx->getVidSource());
        $this->assertNull($pxCtx->getOrigCookieVid());
    }

    public function testActivityIncludesOrigCookieVidWhenInvalid()
    {
        $pxCtx = $this->createContextWithPxvid(self::INVALID_VID);
        $activitiesClient = $this->createActivitiesClient();

        $activity = $activitiesClient->generateActivity('page_requested', $pxCtx, ['pass_reason' => 'cookie']);

        $this->assertEquals(self::INVALID_VID, $activity['details']['orig_cookie_vid']);
        $this->assertArrayNotHasKey('vid', $activity);
    }

    public function testActivityDoesNotIncludeOrigCookieVidWhenValid()
    {
        $pxCtx = $this->createContextWithPxvid(self::VALID_VID);
        $activitiesClient = $this->createActivitiesClient();

        $activity = $activitiesClient->generateActivity('page_requested', $pxCtx, ['pass_reason' => 'cookie']);

        $this->assertArrayNotHasKey('orig_cookie_vid', $activity['details']);
        $this->assertEquals(self::VALID_VID, $activity['vid']);
        $this->assertEquals('vid_cookie', $activity['details']['enforcer_vid_source']);
    }

    public function testActivityIncludesEnforcerVidSourceWhenSet()
    {
        $pxCtx = $this->createContextWithPxvid(self::VALID_VID);
        $pxCtx->setVidSource('risk_cookie');
        $activitiesClient = $this->createActivitiesClient();

        $activity = $activitiesClient->generateActivity('page_requested', $pxCtx, ['pass_reason' => 's2s']);

        $this->assertEquals('risk_cookie', $activity['details']['enforcer_vid_source']);
    }

    public function testBlockActivityIncludesOrigCookieVid()
    {
        $pxCtx = $this->createContextWithPxvid(self::INVALID_VID);
        $activitiesClient = $this->createActivitiesClient();

        $activity = $activitiesClient->generateActivity('block', $pxCtx, [
            'block_score' => 100,
            'block_reason' => 's2s_high_score',
            'block_action' => 'c',
            'simulated_block' => false
        ]);

        $this->assertEquals(self::INVALID_VID, $activity['details']['orig_cookie_vid']);
    }

    /**
     * @return PerimeterxContext
     */
    private function createContextWithPxvid($pxvidValue)
    {
        $pxCtx = $this->getMockBuilder(PerimeterxContext::class)
            ->disableOriginalConstructor()
            ->setMethods([
                'getPxVidCookie',
                'getHeaders',
                'getIp',
                'getFullUrl',
                'getHttpMethod',
                'getHttpVersion',
                'getCookieOrigin',
                'getRiskRtt',
                'getPxhdCookie',
                'getUri'
            ])
            ->getMock();

        $pxCtx->method('getPxVidCookie')->willReturn($pxvidValue);
        $pxCtx->method('getHeaders')->willReturn([]);
        $pxCtx->method('getIp')->willReturn('1.1.1.1');
        $pxCtx->method('getFullUrl')->willReturn('http://localhost/');
        $pxCtx->method('getHttpMethod')->willReturn('GET');
        $pxCtx->method('getHttpVersion')->willReturn('1.1');
        $pxCtx->method('getCookieOrigin')->willReturn('cookie');
        $pxCtx->method('getRiskRtt')->willReturn(0);
        $pxCtx->method('getPxhdCookie')->willReturn(null);
        $pxCtx->method('getUri')->willReturn('/');

        if (isset($pxvidValue) && PerimeterxContext::isValidVid($pxvidValue)) {
            $pxCtx->setVid($pxvidValue);
            $pxCtx->setVidSource('vid_cookie');
        } elseif (isset($pxvidValue)) {
            $pxCtx->setOrigCookieVid($pxvidValue);
        }

        return $pxCtx;
    }

    /**
     * @return PerimeterxActivitiesClient
     */
    private function createActivitiesClient()
    {
        $httpClient = $this->createMock(PerimeterxHttpClient::class);
        $logger = $this->createMock(AbstractLogger::class);

        $pxConfig = [
            'app_id' => self::APP_ID,
            'auth_token' => self::AUTH_TOKEN,
            'sdk_name' => self::SDK_NAME,
            'http_client' => $httpClient,
            'logger' => $logger,
            'send_page_activities' => true,
            'sensitive_headers' => [],
            'defer_activities' => false,
            'module_mode' => 1
        ];

        return new PerimeterxActivitiesClient($pxConfig);
    }
}
