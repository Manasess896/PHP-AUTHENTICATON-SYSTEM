<?php
/**
 * CSRF Token Generator Endpoint
 * Returns a new CSRF token as JSON for AJAX requests
 */

// Include the CSRF protection utility
require_once __DIR__ . '/csrf_protection.php';

// Set headers to allow same-origin requests only
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

// Generate a new token
$token = generateCSRFToken();

// Return the token as JSON
echo json_encode(['token' => $token, 'expires' => time() + 3600]);
