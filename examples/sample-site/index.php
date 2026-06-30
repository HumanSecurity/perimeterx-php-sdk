<?php
require_once __DIR__ . '/../../vendor/autoload.php';

use Perimeterx\Perimeterx;

$perimeterxConfig = [
    'app_id'         => getenv('PX_APP_ID') ?: 'PX_APP_ID',
    'cookie_key'     => getenv('PX_COOKIE_KEY') ?: 'PX_COOKIE_KEY',
    'auth_token'     => getenv('PX_AUTH_TOKEN') ?: 'PX_AUTH_TOKEN',
    'blocking_score' => 80,
    'module_mode'    => Perimeterx::$ACTIVE_MODE,
    'debug_mode'     => true,
    'sensitive_routes' => [
        '/login',                          // plain prefix match
        '/^\/api\/.*\/payment$/i',         // regex: /api/*/payment, case-insensitive
        '/.*\/checkout$/',                 // regex: suffix match for /checkout
        '/^\/admin$/',                     // regex: exact match /admin only
        '/^\/account\/.*\/delete$/',       // regex: any /account/*/delete path
        '/.*\.json$/',                     // regex: any path ending in .json
    ],
];

$requestUri = $_SERVER['REQUEST_URI'];
$path = parse_url($requestUri, PHP_URL_PATH);

$px = Perimeterx::Instance($perimeterxConfig);
$px->pxVerify();

$isSensitive = \Perimeterx\PerimeterxRouteUtils::isPathInPatterns(
    $perimeterxConfig['sensitive_routes'],
    $requestUri
);

$routes = [
    '/'                => ['title' => 'Home',            'body' => 'Welcome to the sample site!'],
    '/login'           => ['title' => 'Login',           'body' => 'This is the login page (sensitive route - prefix match).'],
    '/login/reset'     => ['title' => 'Password Reset',  'body' => 'This is the password reset page (sensitive - matches /login prefix).'],
    '/admin'           => ['title' => 'Admin',           'body' => 'This is the admin panel (sensitive route - exact regex match).'],
    '/admin/settings'  => ['title' => 'Admin Settings',  'body' => 'Admin settings page (NOT sensitive - /^\/admin$/ does not match subpaths).'],
    '/api/v1/payment'  => ['title' => 'Payment API',     'body' => 'Payment endpoint (sensitive route - regex match /api/*/payment).'],
    '/api/v2/payment'  => ['title' => 'Payment API v2',  'body' => 'Payment v2 endpoint (sensitive route - regex match).'],
    '/api/v1/users'    => ['title' => 'Users API',       'body' => 'Users endpoint (NOT sensitive).'],
    '/shop/checkout'   => ['title' => 'Checkout',        'body' => 'Checkout page (sensitive route - suffix regex match for /checkout).'],
    '/account/123/delete' => ['title' => 'Delete Account', 'body' => 'Delete account endpoint (sensitive - regex /account/*/delete).'],
    '/data/config.json' => ['title' => 'JSON Config',    'body' => 'JSON endpoint (sensitive - regex suffix match *.json).'],
    '/about'           => ['title' => 'About',           'body' => 'This is a regular page (not sensitive).'],
    '/contact'         => ['title' => 'Contact',         'body' => 'Contact page (not sensitive).'],
];

$page = isset($routes[$path]) ? $routes[$path] : null;
$title = $page ? $page['title'] : '404 Not Found';
$body = $page ? $page['body'] : 'Page not found.';

if (!$page) {
    http_response_code(404);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($title) ?> - PX Sample Site</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; }
        .header { background: #1a1a2e; color: white; padding: 20px 40px; }
        .header h1 { font-size: 1.4rem; font-weight: 600; }
        .header small { color: #888; }
        .container { max-width: 900px; margin: 30px auto; padding: 0 20px; }
        .card { background: white; border-radius: 8px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .card h2 { margin-bottom: 8px; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; margin-left: 8px; }
        .badge-sensitive { background: #ffe0e0; color: #c0392b; }
        .badge-normal { background: #e0f0e0; color: #27ae60; }
        .nav { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 20px; }
        .nav a { padding: 8px 16px; background: #e8e8e8; border-radius: 6px; text-decoration: none; color: #333; font-size: 0.9rem; transition: background 0.2s; }
        .nav a:hover { background: #d0d0d0; }
        .nav a.active { background: #1a1a2e; color: white; }
        .nav a.sensitive { border: 2px solid #c0392b; }
        .info { background: #f0f4ff; border-left: 4px solid #3498db; padding: 16px; border-radius: 0 8px 8px 0; margin-top: 16px; }
        .info code { background: #e0e8f0; padding: 2px 6px; border-radius: 3px; font-size: 0.85rem; }
        table { width: 100%; border-collapse: collapse; margin-top: 12px; }
        th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #eee; font-size: 0.85rem; }
        th { color: #666; font-weight: 600; }
        td code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>PX PHP Enforcer - Sensitive Routes Test Site</h1>
        <small>Testing regex/wildcard/suffix route matching</small>
    </div>
    <div class="container">
        <div class="nav">
            <?php foreach ($routes as $routePath => $routeInfo): 
                $routeSensitive = \Perimeterx\PerimeterxRouteUtils::isPathInPatterns(
                    $perimeterxConfig['sensitive_routes'], $routePath
                );
                $activeClass = ($path === $routePath) ? ' active' : '';
                $sensitiveClass = $routeSensitive ? ' sensitive' : '';
            ?>
                <a href="<?= $routePath ?>" class="<?= trim($activeClass . $sensitiveClass) ?>"><?= htmlspecialchars($routeInfo['title']) ?></a>
            <?php endforeach; ?>
        </div>

        <div class="card">
            <h2>
                <?= htmlspecialchars($title) ?>
                <?php if ($isSensitive): ?>
                    <span class="badge badge-sensitive">SENSITIVE ROUTE</span>
                <?php else: ?>
                    <span class="badge badge-normal">NORMAL ROUTE</span>
                <?php endif; ?>
            </h2>
            <p><?= htmlspecialchars($body) ?></p>

            <div class="info">
                <strong>Request details:</strong><br>
                Path: <code><?= htmlspecialchars($path) ?></code><br>
                Normalized: <code><?= htmlspecialchars(\Perimeterx\PerimeterxRouteUtils::normalizePath($requestUri)) ?></code><br>
                Sensitive: <code><?= $isSensitive ? 'true' : 'false' ?></code>
            </div>
        </div>

        <div class="card">
            <h2>Configured Sensitive Route Patterns</h2>
            <table>
                <thead>
                    <tr><th>Pattern</th><th>Type</th><th>Matches Current Path?</th></tr>
                </thead>
                <tbody>
                    <?php foreach ($perimeterxConfig['sensitive_routes'] as $pattern):
                        $isRegex = \Perimeterx\PerimeterxRouteUtils::convertStringToRegex($pattern) !== null;
                        $matches = \Perimeterx\PerimeterxRouteUtils::isPathInPatterns([$pattern], $requestUri);
                    ?>
                    <tr>
                        <td><code><?= htmlspecialchars($pattern) ?></code></td>
                        <td><?= $isRegex ? 'Regex' : 'Prefix' ?></td>
                        <td><?= $matches ? '&#10004;' : '&#10008;' ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>All Routes</h2>
            <table>
                <thead>
                    <tr><th>Path</th><th>Sensitive?</th><th>Why?</th></tr>
                </thead>
                <tbody>
                    <?php foreach ($routes as $routePath => $routeInfo):
                        $routeSensitive = \Perimeterx\PerimeterxRouteUtils::isPathInPatterns(
                            $perimeterxConfig['sensitive_routes'], $routePath
                        );
                        $matchedPattern = 'N/A';
                        if ($routeSensitive) {
                            foreach ($perimeterxConfig['sensitive_routes'] as $p) {
                                if (\Perimeterx\PerimeterxRouteUtils::isPathInPatterns([$p], $routePath)) {
                                    $matchedPattern = $p;
                                    break;
                                }
                            }
                        }
                    ?>
                    <tr>
                        <td><code><?= htmlspecialchars($routePath) ?></code></td>
                        <td><?= $routeSensitive ? '&#10004; Yes' : '&#10008; No' ?></td>
                        <td><code><?= htmlspecialchars($matchedPattern) ?></code></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <script type="text/javascript">
        (function(){
            window._pxAppId = '<?= htmlspecialchars(getenv('PX_APP_ID') ?: 'PX_APP_ID') ?>';
            var p = document.getElementsByTagName('script')[0],
                s = document.createElement('script');
            s.async = 1;
            s.src = '//client.px-cloud.net/<?= htmlspecialchars(getenv('PX_APP_ID') ?: 'PX_APP_ID') ?>/main.min.js';
            p.parentNode.insertBefore(s,p);
        }());
    </script>
</body>
</html>
