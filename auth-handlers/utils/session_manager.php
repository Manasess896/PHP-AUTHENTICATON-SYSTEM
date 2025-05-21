<?php

/**
 * Session Management Utility
 * 
 * Centralized session management functions
 */

// Include environment variables loader
require_once __DIR__ . '/../../config/env_loader.php';

/**
 * Initialize a secure session with proper settings
 * @return bool True if session was initialized successfully
 */
if (!function_exists('initSecureSession')) {
    function initSecureSession()
    {
        // Only set parameters if session hasn't started
        if (session_status() === PHP_SESSION_NONE) {
            // Set secure session parameters
            ini_set('session.gc_maxlifetime', 7200); // 2 hours
            session_set_cookie_params([
                'lifetime' => 7200,
                'path' => '/',
                'domain' => '',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Lax'
            ]);

            return session_start();
        }

        return true;
    }
}

/**
 * Check if user is authenticated
 * @return bool True if user is authenticated
 */
if (!function_exists('isAuthenticated')) {
    function isAuthenticated()
    {
        return isset($_SESSION['user_id']) &&
            isset($_SESSION['is_logged_in']) &&
            $_SESSION['is_logged_in'] === true;
    }
}

/**
 * Require authentication or redirect
 * @param string $redirectUrl URL to redirect to if not authenticated
 */
if (!function_exists('requireAuthentication')) {
    function requireAuthentication($redirectUrl = '../login.php')
    {
        if (!isAuthenticated()) {
            header("Location: $redirectUrl");
            exit;
        }

        // Check session timeout
        $sessionTimeout = 7200; // 2 hours
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $sessionTimeout)) {
            // Session expired, destroy it and redirect to login
            session_unset();
            session_destroy();
            header("Location: $redirectUrl?error=" . urlencode('Your session has expired. Please log in again.'));
            exit;
        }

        // Update last activity
        $_SESSION['last_activity'] = time();
    }
}

/**
 * Regenerate session ID for security
 */
if (!function_exists('regenerateSessionId')) {
    function regenerateSessionId()
    {
        if (
            !isset($_SESSION['last_regeneration']) ||
            (time() - $_SESSION['last_regeneration'] > 900)
        ) { // 15 minutes
            // Save the old session data
            $oldSessionData = $_SESSION;

            // Regenerate session ID
            session_regenerate_id(true);

            // Restore old session data
            $_SESSION = $oldSessionData;
            $_SESSION['last_regeneration'] = time();
        }
    }
}

/**
 * Get current CSRF token or generate a new one
 * @return string CSRF token
 */
if (!function_exists('getCsrfToken')) {
    function getCsrfToken()
    {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
}

/**
 * Validate CSRF token
 * @param string $token The token to validate
 * @return bool True if valid, false otherwise
 */
if (!function_exists('validateCsrfToken')) {
    function validateCsrfToken($token)
    {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }
}

/**
 * Log user activity for analytics
 * @param string $action The action being performed
 * @param array $details Optional additional details
 */
if (!function_exists('logUserActivity')) {
    function logUserActivity($action, $details = [])
    {
        $logsDir = __DIR__ . '/../logs';

        // Create logs directory if it doesn't exist
        if (!is_dir($logsDir)) {
            mkdir($logsDir, 0755, true);
        }

        $userId = $_SESSION['user_id'] ?? 'unknown';
        $timestamp = date('Y-m-d H:i:s');
        $ip = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'];

        // Prepare log entry
        $logEntry = [
            'timestamp' => $timestamp,
            'user_id' => $userId,
            'action' => $action,
            'ip' => $ip,
            'user_agent' => $userAgent,
            'details' => $details
        ];

        // Write to log file
        $logFile = "$logsDir/user_activity.log";
        file_put_contents(
            $logFile,
            json_encode($logEntry) . PHP_EOL,
            FILE_APPEND
        );
    }
}

/**
 * Set common security headers
 */
function setSecurityHeaders()
{
    header("X-Frame-Options: DENY");
    header("X-XSS-Protection: 1; mode=block");
    header("X-Content-Type-Options: nosniff");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    // Only set HSTS in production with HTTPS
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
    }
}

/**
 * Create a user session from a Remember Me token
 * @return bool True if session was created successfully
 */
function createSessionFromRememberToken()
{
    if (!isset($_COOKIE['remember_token']) || empty($_COOKIE['remember_token'])) {
        return false;
    }

    try {
        require_once __DIR__ . '/../config/database.php';
        $db = getDatabaseConnection();

        if ($db instanceof MongoDB\Database) {
            // Find token in database
            $tokenData = $db->auth_tokens->findOne([
                'token' => $_COOKIE['remember_token'],
                'expiry' => ['$gt' => new MongoDB\BSON\UTCDateTime(time() * 1000)]
            ]);

            if ($tokenData) {
                // Token is valid, find the user
                $user = $db->users->findOne(['_id' => $tokenData->user_id]);

                if ($user) {
                    // Create new session
                    $_SESSION['user_id'] = (string) $user->_id;
                    $_SESSION['user_email'] = $user->email;

                    // Set name using firstName and lastName if available, or extract from email
                    if (isset($user->firstName)) {
                        $_SESSION['user_name'] = $user->firstName . ' ' . ($user->lastName ?? '');
                    } else {
                        $_SESSION['user_name'] = explode('@', $user->email)[0];
                    }

                    $_SESSION['is_logged_in'] = true;
                    $_SESSION['last_activity'] = time();
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

                    // Check admin status
                    if ((isset($user->is_admin) && $user->is_admin) ||
                        (isset($user->isAdmin) && $user->isAdmin)
                    ) {
                        $_SESSION['is_admin'] = true;
                    }

                    // Update last login
                    $db->users->updateOne(
                        ['_id' => $user->_id],
                        ['$set' => ['last_login' => new MongoDB\BSON\UTCDateTime(time() * 1000)]]
                    );

                    // Regenerate session ID
                    session_regenerate_id(true);

                    return true;
                }
            }
        }
    } catch (Exception $e) {
        error_log("Error checking remember token: " . $e->getMessage());
    }

    // Token invalid or expired, delete it
    setcookie('remember_token', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'domain' => '',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);

    return false;
}

/**
 * Log out a user and clean up session
 * @param bool $destroyRememberToken Whether to destroy the remember token cookie
 */
function logoutUser($destroyRememberToken = true)
{
    // First, destroy remember token if requested
    if ($destroyRememberToken && isset($_COOKIE['remember_token'])) {
        // Delete token from database if possible
        try {
            require_once __DIR__ . '/../config/database.php';
            $db = getDatabaseConnection();

            if ($db instanceof MongoDB\Database) {
                $db->auth_tokens->deleteOne(['token' => $_COOKIE['remember_token']]);
            }
        } catch (Exception $e) {
            error_log("Error removing token from database: " . $e->getMessage());
        }

        // Delete cookie
        setcookie('remember_token', '', [
            'expires' => time() - 3600,
            'path' => '/',
            'domain' => '',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    }

    // Now destroy session
    session_unset();
    session_destroy();
}

/**
 * Completely terminate a user session and clean up
 */
function terminateSession()
{
    // Clean up "Remember Me" token if it exists
    if (isset($_COOKIE['remember_token'])) {
        try {
            // Include database connection if needed
            if (!function_exists('getDatabaseConnection')) {
                require_once __DIR__ . '/../config/database.php';
            }

            $db = getDatabaseConnection();

            // Delete token from database
            if ($db instanceof MongoDB\Database) {
                $db->auth_tokens->deleteOne(['token' => $_COOKIE['remember_token']]);
            } elseif (isset($db->delete)) {
                $db->delete('auth_tokens', ['token' => $_COOKIE['remember_token']]);
            }
        } catch (Exception $e) {
            error_log("Error removing remember token during logout: " . $e->getMessage());
        }

        // Delete the cookie
        setcookie('remember_token', '', [
            'expires' => time() - 3600,
            'path' => '/',
            'domain' => '',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    }

    // Clear all session data
    $_SESSION = [];

    // Delete the session cookie
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 3600,
            'path' => $params["path"],
            'domain' => $params["domain"],
            'secure' => $params["secure"],
            'httponly' => $params["httponly"],
            'samesite' => 'Lax'
        ]);
    }

    // Destroy the session
    session_destroy();
}
