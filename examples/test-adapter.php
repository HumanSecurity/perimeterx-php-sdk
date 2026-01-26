<?php
/**
 * Test Adapter for PerimeterX Enforcer Spec Tests
 * 
 * Loads configuration from enforcer_config.json and runs pxVerify.
 * Translates spec test config names (px_*) to PHP SDK config names.
 * 
 * Usage: php -S localhost:3000 test-adapter.php
 */

require __DIR__ . "/../vendor/autoload.php";

use Perimeterx\Perimeterx;

// Config key translation: spec test names (px_*) => PHP SDK names
// null = keep the key as-is (SDK expects it with px_ prefix)
$CONFIG_MAP = [
    // Keys that need translation (spec tests use different names than SDK)
    'px_app_id' => 'app_id',
    'px_auth_token' => 'auth_token',
    'px_cookie_secret' => 'cookie_key',
    'px_module_enabled' => 'module_enabled',
    'px_blocking_score' => 'blocking_score',
    'px_module_mode' => 'module_mode',
    'px_backend_url' => 'perimeterx_server_host',
    'px_s2s_timeout' => 'api_timeout',
    'px_api_timeout' => 'api_timeout',
    'px_sensitive_routes' => 'sensitive_routes',
    'px_sensitive_headers' => 'sensitive_headers',
    'px_ip_headers' => 'ip_headers',
    // Keys that keep px_ prefix (SDK expects it as-is)
    'px_first_party_enabled' => null,
    'px_cd_first_party_enabled' => null,
    'px_jwt_cookie_name' => null,
    'px_jwt_cookie_user_id_field_name' => null,
    'px_jwt_cookie_additional_field_names' => null,
    'px_jwt_header_name' => null,
    'px_jwt_header_user_id_field_name' => null,
    'px_jwt_header_additional_field_names' => null,
    'px_login_credentials_extraction_enabled' => null,
    'px_login_credentials_extraction' => null,
    'px_compromised_credentials_header' => null,
    'px_credentials_intelligence_version' => null,
    'px_additional_s2s_activity_header_enabled' => null,
    'px_automatic_additional_s2s_activity_enabled' => null,
    'px_send_raw_username_on_additional_s2s_activity' => null,
    'px_login_successful_reporting_method' => null,
    'px_login_successful_status' => null,
    'px_login_successful_header_name' => null,
    'px_login_successful_header_value' => null,
];

/**
 * Translate spec test config (px_* names) to PHP SDK config names
 */
function translateConfig(array $config, array $configMap): array {
    $translated = [];
    
    foreach ($config as $key => $value) {
        if (array_key_exists($key, $configMap)) {
            $mappedKey = $configMap[$key];
            $translated[$mappedKey ?? $key] = $value;
        } elseif (strpos($key, 'px_') === 0) {
            // Unmapped px_* keys: strip prefix
            $translated[substr($key, 3)] = $value;
        } else {
            $translated[$key] = $value;
        }
    }
    
    // Translate module_mode string to SDK constant
    if (isset($translated['module_mode']) && is_string($translated['module_mode'])) {
        $mode = strtolower($translated['module_mode']);
        if ($mode === 'monitor' || $mode === 'monitoring') {
            $translated['module_mode'] = Perimeterx::$MONITOR_MODE;
        } elseif ($mode === 'active_blocking' || $mode === 'blocking' || $mode === 'active') {
            $translated['module_mode'] = Perimeterx::$ACTIVE_MODE;
        }
    }
    
    return $translated;
}

// Load config from JSON file
$configFile = __DIR__ . '/enforcer_config.json';
if (!file_exists($configFile)) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'enforcer_config.json not found']);
    exit;
}

$fileConfig = json_decode(file_get_contents($configFile), true);
if ($fileConfig === null) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Failed to parse enforcer_config.json']);
    exit;
}

$config = translateConfig($fileConfig, $CONFIG_MAP);

// Validate required config
if (empty($config['app_id']) || empty($config['cookie_key']) || empty($config['auth_token'])) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode([
        'error' => 'Missing required configuration',
        'required' => ['px_app_id', 'px_cookie_secret', 'px_auth_token']
    ]);
    exit;
}

// Run the enforcer
try {
    $px = Perimeterx::Instance($config);
    $px->pxVerify();
} catch (Exception $e) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => $e->getMessage()]);
}
