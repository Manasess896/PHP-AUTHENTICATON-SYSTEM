<?php
// Start the session
session_start();

// Clear all session variables
$_SESSION = array();

// Delete the session cookie
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Destroy the session
session_destroy();

// Clear the remember me cookie if exists
if (isset($_COOKIE['remember_token'])) {
    setcookie('remember_token', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'domain' => '',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    
    // Optionally, also remove the token from database
    try {
        require_once __DIR__ . '/../config/database.php';
        $db = getDatabaseConnection();
        $tokensCollection = $db->auth_tokens;
        
        // Delete the token from database
        if (isset($_COOKIE['remember_token'])) {
            $tokensCollection->deleteOne(['token' => $_COOKIE['remember_token']]);
        }
    } catch (Exception $e) {
        // Just log the error but continue with logout process
        error_log("Error removing token from database: " . $e->getMessage());
    }
}

// Redirect to login page with success message
header("Location: ../pages/login.php?success=" . urlencode("You have been successfully logged out."));
exit;
