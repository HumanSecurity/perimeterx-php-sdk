<?php

use PHPUnit\Framework\TestCase;
use Perimeterx\PerimeterxRouteUtils;

class PerimeterxRouteUtilsTest extends TestCase
{
    // --- normalizePath tests ---

    public function testNormalizePath_basicPath()
    {
        $this->assertEquals('/login', PerimeterxRouteUtils::normalizePath('/login'));
    }

    public function testNormalizePath_stripsQueryString()
    {
        $this->assertEquals('/login', PerimeterxRouteUtils::normalizePath('/login?foo=bar'));
    }

    public function testNormalizePath_urlDecoding()
    {
        $this->assertEquals('/login', PerimeterxRouteUtils::normalizePath('/logi%6E'));
    }

    public function testNormalizePath_traversalResolution()
    {
        $this->assertEquals('/login', PerimeterxRouteUtils::normalizePath('/fake/../login'));
    }

    public function testNormalizePath_dotSegments()
    {
        $this->assertEquals('/login/profile', PerimeterxRouteUtils::normalizePath('/login/./profile'));
    }

    public function testNormalizePath_trailingSlashStripped()
    {
        $this->assertEquals('/login', PerimeterxRouteUtils::normalizePath('/login/'));
    }

    public function testNormalizePath_multipleTrailingSlashesStripped()
    {
        $this->assertEquals('/login', PerimeterxRouteUtils::normalizePath('/login///'));
    }

    public function testNormalizePath_repeatedSlashesCollapsed()
    {
        $this->assertEquals('/login/page', PerimeterxRouteUtils::normalizePath('/login//page'));
    }

    public function testNormalizePath_rootPath()
    {
        $this->assertEquals('/', PerimeterxRouteUtils::normalizePath('/'));
    }

    public function testNormalizePath_complexCombination()
    {
        $this->assertEquals('/login', PerimeterxRouteUtils::normalizePath('/fake/../logi%6E?session=123'));
    }

    // --- convertStringToRegex tests ---

    public function testConvertStringToRegex_validRegexString()
    {
        $result = PerimeterxRouteUtils::convertStringToRegex('/^\/path$/i');
        $this->assertNotNull($result);
        $this->assertEquals('/^\/path$/i', $result);
    }

    public function testConvertStringToRegex_validRegexNoFlags()
    {
        $result = PerimeterxRouteUtils::convertStringToRegex('/^\/login$/');
        $this->assertNotNull($result);
        $this->assertEquals('/^\/login$/', $result);
    }

    public function testConvertStringToRegex_nonRegexString()
    {
        $this->assertNull(PerimeterxRouteUtils::convertStringToRegex('/login'));
    }

    public function testConvertStringToRegex_nonRegexMultiSegmentPath()
    {
        $this->assertNull(PerimeterxRouteUtils::convertStringToRegex('/login/page'));
    }

    public function testConvertStringToRegex_invalidFlags()
    {
        $result = PerimeterxRouteUtils::convertStringToRegex('/path/z');
        $this->assertNull($result);
    }

    public function testConvertStringToRegex_trailingSlashAmbiguity()
    {
        $result = PerimeterxRouteUtils::convertStringToRegex('/login/');
        $this->assertNotNull($result, 'Trailing-slash path is detected as regex per spec');
        $this->assertEquals('/login/', $result);
    }

    public function testConvertStringToRegex_singleFlagCharSuffix()
    {
        $result = PerimeterxRouteUtils::convertStringToRegex('/something/i');
        $this->assertNotNull($result, 'Path ending with valid flag char is detected as regex per spec');
        $this->assertEquals('/something/i', $result);
    }

    public function testConvertStringToRegex_emptyString()
    {
        $this->assertNull(PerimeterxRouteUtils::convertStringToRegex(''));
    }

    public function testConvertStringToRegex_jsOnlyFlagsStripped()
    {
        $result = PerimeterxRouteUtils::convertStringToRegex('/^\/path$/gi');
        $this->assertNotNull($result);
        $this->assertEquals('/^\/path$/i', $result);
    }

    public function testConvertStringToRegex_invalidRegexBody()
    {
        $result = PerimeterxRouteUtils::convertStringToRegex('/[invalid/');
        $this->assertNull($result, 'Invalid regex body should return null');
    }

    // --- isPathInPatterns tests: backward compatibility (prefix match) ---

    public function testIsPathInPatterns_prefixExactMatch()
    {
        $this->assertTrue(PerimeterxRouteUtils::isPathInPatterns(['/login'], '/login'));
    }

    public function testIsPathInPatterns_prefixMatchSubpath()
    {
        $this->assertTrue(PerimeterxRouteUtils::isPathInPatterns(['/login'], '/login/page'));
    }

    public function testIsPathInPatterns_prefixMatchExtension()
    {
        $this->assertTrue(PerimeterxRouteUtils::isPathInPatterns(['/login'], '/loginx'));
    }

    public function testIsPathInPatterns_prefixNoMatchDifferentCase()
    {
        $this->assertFalse(PerimeterxRouteUtils::isPathInPatterns(['/login'], '/LOGIN'));
    }

    public function testIsPathInPatterns_prefixNoMatchMiddle()
    {
        $this->assertFalse(PerimeterxRouteUtils::isPathInPatterns(['/login'], '/my/login'));
    }

    // --- isPathInPatterns tests: regex match ---

    public function testIsPathInPatterns_regexExactMatch()
    {
        $this->assertTrue(PerimeterxRouteUtils::isPathInPatterns(['/^\/login$/'], '/login'));
    }

    public function testIsPathInPatterns_regexExactNoMatchSubpath()
    {
        $this->assertFalse(PerimeterxRouteUtils::isPathInPatterns(['/^\/login$/'], '/login/page'));
    }

    public function testIsPathInPatterns_regexSuffixMatch()
    {
        $this->assertTrue(PerimeterxRouteUtils::isPathInPatterns(['/\/login$/'], '/my/login'));
    }

    public function testIsPathInPatterns_regexCaseInsensitive()
    {
        $patterns = ['/^\/api\/.*\/payment$/i'];
        $this->assertTrue(PerimeterxRouteUtils::isPathInPatterns($patterns, '/api/v2/payment'));
        $this->assertTrue(PerimeterxRouteUtils::isPathInPatterns($patterns, '/API/v1/Payment'));
    }

    public function testIsPathInPatterns_regexExtensionMatch()
    {
        $this->assertTrue(PerimeterxRouteUtils::isPathInPatterns(['/.*\.json$/'], '/data/config.json'));
    }

    public function testIsPathInPatterns_regexNoMatch()
    {
        $this->assertFalse(PerimeterxRouteUtils::isPathInPatterns(['/^\/login$/'], '/other'));
    }

    // --- isPathInPatterns tests: mixed patterns ---

    public function testIsPathInPatterns_mixedPatternsStringMatch()
    {
        $patterns = ['/admin', '/^\/api\/.*$/'];
        $this->assertTrue(PerimeterxRouteUtils::isPathInPatterns($patterns, '/admin/panel'));
    }

    public function testIsPathInPatterns_mixedPatternsRegexMatch()
    {
        $patterns = ['/admin', '/^\/api\/.*$/'];
        $this->assertTrue(PerimeterxRouteUtils::isPathInPatterns($patterns, '/api/users'));
    }

    public function testIsPathInPatterns_mixedPatternsNoMatch()
    {
        $patterns = ['/admin', '/^\/api\/.*$/'];
        $this->assertFalse(PerimeterxRouteUtils::isPathInPatterns($patterns, '/other'));
    }

    // --- isPathInPatterns tests: normalization interaction ---

    public function testIsPathInPatterns_normalizationUrlEncoded()
    {
        $this->assertTrue(PerimeterxRouteUtils::isPathInPatterns(
            ['/^\/login$/'],
            '/logi%6E?session=123'
        ));
    }

    public function testIsPathInPatterns_normalizationTraversal()
    {
        $this->assertTrue(PerimeterxRouteUtils::isPathInPatterns(
            ['/^\/login$/'],
            '/fake/../login'
        ));
    }

    public function testIsPathInPatterns_normalizationTrailingSlash()
    {
        $this->assertTrue(PerimeterxRouteUtils::isPathInPatterns(
            ['/login'],
            '/login/'
        ));
    }

    public function testIsPathInPatterns_emptyPatterns()
    {
        $this->assertFalse(PerimeterxRouteUtils::isPathInPatterns([], '/login'));
    }
}
