<?php

namespace Perimeterx;

class PerimeterxRouteUtils
{
    const REGEX_STRUCTURE = '/^\/(.+?)\/([gimsuyvd]*)$/';
    const PHP_VALID_FLAGS = ['i', 'm', 's', 'u', 'x'];

    /**
     * Normalizes a URL path before pattern matching.
     * Strips query strings, decodes non-reserved characters, resolves traversals,
     * strips trailing slashes, and collapses repeated slashes.
     */
    public static function normalizePath($path)
    {
        $qpos = strpos($path, '?');
        if ($qpos !== false) {
            $path = substr($path, 0, $qpos);
        }

        $path = rawurldecode($path);

        $path = preg_replace('#/+#', '/', $path);

        $segments = explode('/', $path);
        $resolved = [];
        foreach ($segments as $segment) {
            if ($segment === '..') {
                if (count($resolved) > 1) {
                    array_pop($resolved);
                }
            } elseif ($segment !== '.') {
                $resolved[] = $segment;
            }
        }
        $path = implode('/', $resolved);

        $path = rtrim($path, '/');

        if ($path === '') {
            $path = '/';
        }

        return $path;
    }

    /**
     * Attempts to parse a string as a regex-format pattern (e.g. "/^\/path$/i").
     * Returns a preg_match-compatible pattern string, or null if not regex format.
     */
    public static function convertStringToRegex($pattern)
    {
        if (empty($pattern)) {
            return null;
        }

        if (!preg_match(self::REGEX_STRUCTURE, $pattern, $matches)) {
            return null;
        }

        $regexBody = $matches[1];
        $flags = $matches[2];

        $phpFlags = '';
        for ($i = 0; $i < strlen($flags); $i++) {
            if (in_array($flags[$i], self::PHP_VALID_FLAGS)) {
                $phpFlags .= $flags[$i];
            }
        }

        $regex = '/' . $regexBody . '/' . $phpFlags;

        if (@preg_match($regex, '') === false) {
            return null;
        }

        return $regex;
    }

    /**
     * Checks whether a path matches any of the given patterns.
     * Patterns can be plain strings (prefix match) or regex-format strings.
     */
    public static function isPathInPatterns($patterns, $path)
    {
        $normalizedPath = self::normalizePath($path);

        foreach ($patterns as $pattern) {
            $regex = self::convertStringToRegex($pattern);
            if ($regex !== null) {
                if (preg_match($regex, $normalizedPath)) {
                    return true;
                }
            } else {
                if (strpos($normalizedPath, $pattern) === 0) {
                    return true;
                }
            }
        }

        return false;
    }
}
