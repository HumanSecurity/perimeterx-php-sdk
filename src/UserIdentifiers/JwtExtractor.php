<?php

namespace Perimeterx\UserIdentifiers;

class JwtExtractor
{
    /**
     * @var array
     */
    private $pxConfig;

    /**
     * @var object
     */
    private $logger;

    public function __construct($pxConfig)
    {
        $this->pxConfig = $pxConfig;
        $this->logger = $pxConfig['logger'];
    }

    /**
     * @param array $cookies
     * @param array $headers
     * @return array|null
     */
    public function extract($cookies, $headers)
    {
        $result = $this->extractFromCookie($cookies);
        if ($result !== null) {
            return $result;
        }

        return $this->extractFromHeader($headers);
    }

    /**
     * @param array $cookies
     * @return array|null
     */
    private function extractFromCookie($cookies)
    {
        $cookieName = $this->pxConfig['px_jwt_cookie_name'];
        if (empty($cookieName) || !isset($cookies[$cookieName])) {
            return null;
        }

        $jwtToken = $cookies[$cookieName];
        $userIdFieldName = $this->pxConfig['px_jwt_cookie_user_id_field_name'];
        $additionalFieldNames = $this->pxConfig['px_jwt_cookie_additional_field_names'] ?? [];

        return $this->extractJwtData($jwtToken, $userIdFieldName, $additionalFieldNames);
    }

    /**
     * @param array $headers
     * @return array|null
     */
    private function extractFromHeader($headers)
    {
        $headerName = $this->pxConfig['px_jwt_header_name'];
        if (empty($headerName)) {
            return null;
        }

        $headersLower = array_change_key_case($headers, CASE_LOWER);
        $headerNameLower = strtolower($headerName);

        if (!isset($headersLower[$headerNameLower]) || empty($headersLower[$headerNameLower])) {
            return null;
        }

        $jwtToken = $headersLower[$headerNameLower];
        $userIdFieldName = $this->pxConfig['px_jwt_header_user_id_field_name'];
        $additionalFieldNames = $this->pxConfig['px_jwt_header_additional_field_names'] ?? [];

        return $this->extractJwtData($jwtToken, $userIdFieldName, $additionalFieldNames);
    }

    /**
     * @param string $jwtToken
     * @param string|null $userIdFieldName
     * @param array $additionalFieldNames
     * @return array|null
     */
    private function extractJwtData($jwtToken, $userIdFieldName, $additionalFieldNames)
    {
        try {
            $payload = $this->decodeJwtPayload($jwtToken);
            if ($payload === null) {
                return null;
            }

            $result = [];

            if (!empty($userIdFieldName)) {
                $appUserId = $this->extractFieldValue($payload, $userIdFieldName);
                if ($appUserId !== null) {
                    $result['app_user_id'] = $appUserId;
                }
            }

            if (!empty($additionalFieldNames)) {
                $additionalFields = [];
                foreach ($additionalFieldNames as $fieldName) {
                    $value = $this->extractFieldValue($payload, $fieldName);
                    if ($value !== null) {
                        $additionalFields[$fieldName] = $value;
                    }
                }
                if (!empty($additionalFields)) {
                    $result['jwt_additional_fields'] = $additionalFields;
                }
            }

            return !empty($result) ? $result : null;
        } catch (\Exception $e) {
            $this->logger->debug('Unable to extract JWT data: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * @param string $jwtToken
     * @return array|null
     */
    private function decodeJwtPayload($jwtToken)
    {
        $parts = explode('.', $jwtToken);
        if (count($parts) < 3) {
            return null;
        }

        $encodedPayload = $parts[1];
        $base64 = strtr($encodedPayload, '-_', '+/');
        
        $padLength = 4 - (strlen($base64) % 4);
        if ($padLength < 4) {
            $base64 .= str_repeat('=', $padLength);
        }

        $decoded = base64_decode($base64, true);
        if ($decoded === false) {
            return null;
        }

        $payload = json_decode($decoded, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return null;
        }

        return $payload;
    }

    /**
     * @param array $payload
     * @param string $fieldName
     * @return mixed|null
     */
    private function extractFieldValue($payload, $fieldName)
    {
        $keys = explode('.', $fieldName);
        $value = $payload;

        foreach ($keys as $key) {
            if (!is_array($value) || !array_key_exists($key, $value)) {
                return null;
            }
            $value = $value[$key];
        }

        return $value;
    }
}
