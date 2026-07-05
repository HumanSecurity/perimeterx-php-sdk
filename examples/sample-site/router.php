<?php
// Router for PHP's built-in server — routes all requests to index.php
$_SERVER['REQUEST_URI'] = $_SERVER['REQUEST_URI'] ?? '/';
require __DIR__ . '/index.php';
