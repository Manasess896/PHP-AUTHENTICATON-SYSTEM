<?php
// Start session
session_start();

// Load environment variables
require_once __DIR__ . '/../config/env_loader.php';

// Load utilities
require_once __DIR__ . '/../auth-handlers/utils/email.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../auth-handlers/utils/tokens.php';
require_once __DIR__ . '/../auth-handlers/utils/logger.php';
require_once __DIR__ . '/../auth-handlers/utils/email_logger.php';
require_once __DIR__ . '/../auth-handlers/utils/rate_limiter.php';
require_once __DIR__ . '/../auth-handlers/utils/csrf_protection.php';

// Get client IP for rate limiting
$ip = $_SERVER['REMOTE_ADDR'];
if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && filter_var($_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP)) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
}

// Get email from URL parameter and sanitize
$email = isset($_GET['email']) ? filter_var($_GET['email'], FILTER_SANITIZE_EMAIL) : '';

// Apply rate limiting per email + IP (prevents enumeration and email bombing)
$rateLimitKey = 'resend_verify_' . md5($email . '_' . $ip);
$maxResendAttempts = getEnvVar('MAX_RESEND_ATTEMPTS', 3);
$resendTimeWindow = getEnvVar('RESEND_TIME_WINDOW', 1800); // 30 minutes

// Enforce rate limiting
if (!enforceRateLimit(
    $rateLimitKey,
    $maxResendAttempts,
    $resendTimeWindow,
    "Too many verification email requests. Please try again later."
)) {
    exit;
}

// Validate email format
if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    redirect_with_error("Invalid email address");
    exit;
}

try {
    // Log the resend attempt
    logEmailActivity("RESEND_VERIFICATION_REQUEST", ["email" => $email], "INFO", "User requested verification email resend");

    // Connect to database
    $db = getDatabaseConnection();

    // Check if database connection was successful
    if (!$db) {
        logEmailActivity("RESEND_VERIFICATION_FAILED", ["email" => $email], "ERROR", "Database connection failed");
        redirect_with_error("Database connection error. Please try again later.");
        exit;
    }

    // Find user by email
    $user = findUserByEmail($email);

    // Check if user exists
    if (!$user) {
        logEmailActivity("RESEND_VERIFICATION_FAILED", ["email" => $email], "WARNING", "Email not found in database");
        redirect_with_error("Email not found in our records");
        exit;
    }

    // Check if account is already verified
    if (isset($user->verified) && $user->verified === true) {
        logEmailActivity("RESEND_VERIFICATION_UNNECESSARY", ["email" => $email], "INFO", "Account already verified");
        redirect_with_message("Your account is already verified. You can log in now.", "login.php");
        exit;
    }

    // Generate new verification token
    $verificationToken = bin2hex(random_bytes(32));
    $tokenExpiry = new DateTime('+24 hours');

    // Update user with new token
    logEmailActivity("RESEND_VERIFICATION_TOKEN_UPDATE", ["email" => $email], "INFO", "Updating verification token");

    // Update verification token
    $updated = updateUserVerificationToken($email, $verificationToken, $tokenExpiry->format('Y-m-d H:i:s'));

    if (!$updated) {
        logEmailActivity("RESEND_VERIFICATION_TOKEN_UPDATE_FAILED", ["email" => $email], "ERROR", "Failed to update token");
        redirect_with_error("Error updating verification token. Please try again.");
        exit;
    }

    // Create verification link
    $userId = isset($user->_id) ? (string) $user->_id : '';
    if (empty($userId)) {
        logEmailActivity("RESEND_VERIFICATION_FAILED", ["email" => $email], "ERROR", "User ID not found");
        redirect_with_error("User identification error. Please contact support.");
        exit;
    }

    $verificationLink = "http://{$_SERVER['HTTP_HOST']}/auth/pages/verify.php?token=$verificationToken&id=$userId";

    // Send verification email
    $userName = isset($user->firstName) ? $user->firstName : (isset($user->first_name) ? $user->first_name : '');
    $emailResult = sendVerificationEmail($email, $userName, $verificationLink);

    if ($emailResult) {
        logEmailActivity("RESEND_VERIFICATION_SUCCESS", ["email" => $email], "SUCCESS", "Verification email resent successfully");
        // Redirect with success message
        redirect_with_message("Verification email has been resent successfully! Please check your inbox and spam folder.", "registration-success.php");
    } else {
        logEmailActivity("RESEND_VERIFICATION_DELIVERY_FAILED", ["email" => $email], "ERROR", "Failed to deliver verification email");

        // Check configuration for better error message
        $mailConfig = checkMailConfiguration();
        if (isset($mailConfig['driver']) && $mailConfig['driver'] === 'log') {
            // In development mode when using log driver
            redirect_with_message(
                "Development mode: Email would be sent in production. Check the logs at /logs/mail/ directory.",
                "registration-success.php"
            );
        } else {
            // Production mode with real error
            redirect_with_error("We encountered an issue sending your verification email. Please try again or contact support.");
        }
    }
} catch (Exception $e) {
    // Log error but don't expose details
    logEmailActivity("RESEND_VERIFICATION_EXCEPTION", ["email" => $email, "error" => $e->getMessage()], "ERROR", "Exception occurred");
    error_log("Resend verification error: " . $e->getMessage() . "\n" . $e->getTraceAsString());
    redirect_with_error("An error occurred. Please try again later.");
}

// Helper function to redirect with error (update path)
function redirect_with_error($message)
{
    $encodedMessage = urlencode($message);
    header("Location: ../pages/registration-success.php?error=$encodedMessage&email=" . urlencode($_GET['email']));
    exit;
}

// Helper function to redirect with success message (update default path)
function redirect_with_message($message, $page = null)
{
    $encodedMessage = urlencode($message);
    $redirectPage = $page ?? '../pages/registration-success.php';
    if (strpos($redirectPage, '../') !== 0 && strpos($redirectPage, 'http') !== 0) {
        $redirectPage = "../pages/$redirectPage";
    }
    header("Location: {$redirectPage}?success=$encodedMessage" .
        (isset($_GET['email']) ? "&email=" . urlencode($_GET['email']) : ""));
    exit;
}
