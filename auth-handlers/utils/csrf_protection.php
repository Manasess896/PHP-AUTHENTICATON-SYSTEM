<?php

/**
 * CSRF Protection Utility
 * 
 * Provides functions to generate, store, and validate CSRF tokens
 */

// Include session manager if not already included
if (!function_exists('initSecureSession')) {
    require_once __DIR__ . '/session_manager.php';
}

/**
 * Generate a new CSRF token and store it in the session
 * 
 * @return string The generated CSRF token
 */
function generateCSRFToken()
{
    // Ensure session is initialized
    initSecureSession();

    // Generate a secure random token
    $token = bin2hex(random_bytes(32));

    // Store token in session
    $_SESSION['csrf_token'] = $token;
    $_SESSION['csrf_token_time'] = time();

    return $token;
}

/**
 * Validate a CSRF token against the one stored in session
 * 
 * @param string $token The token to validate
 * @param int $maxAge Maximum age of token in seconds (default: 3600 = 1 hour)
 * @return bool True if token is valid, false otherwise
 */
function validateCSRFToken($token, $maxAge = 3600)
{
    // Ensure session is initialized
    initSecureSession();

    // Check if token exists in session
    if (empty($_SESSION['csrf_token']) || empty($_SESSION['csrf_token_time'])) {
        return false;
    }

    // Check if token matches
    $valid = hash_equals($_SESSION['csrf_token'], $token);

    // Check if token is expired
    $time = $_SESSION['csrf_token_time'];
    if (time() - $time > $maxAge) {
        // Token expired, generate a new one
        generateCSRFToken();
        return false;
    }

    return $valid;
}

/**
 * Add CSRF protection input field to a form
 * 
 * @return string HTML input field with CSRF token
 */
function csrfField()
{
    // Ensure session is initialized
    initSecureSession();

    $token = generateCSRFToken();
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
}

/**
 * Get the current CSRF token or generate a new one
 * 
 * @return string The current CSRF token
 */
function getCurrentCSRFToken()
{
    // Ensure session is initialized
    initSecureSession();

    // Always regenerate the token if it doesn't exist or if it's older than 10 minutes
    if (
        empty($_SESSION['csrf_token']) ||
        empty($_SESSION['csrf_token_time']) ||
        time() - $_SESSION['csrf_token_time'] > 600
    ) {
        return generateCSRFToken();
    }

    // Update token time to prevent expiration during long form filling sessions
    $_SESSION['csrf_token_time'] = time();

    return $_SESSION['csrf_token'];
}
