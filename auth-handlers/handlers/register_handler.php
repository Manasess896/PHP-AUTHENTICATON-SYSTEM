<?php
// Start session
session_start();

// Load environment variables from .env file
require_once __DIR__ . '/../../config/env_loader.php';

// Require database and other dependencies
require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../utils/validation.php';
require_once __DIR__ . '/../utils/email.php';
require_once __DIR__ . '/../utils/tokens.php';
require_once __DIR__ . '/../utils/logger.php';
require_once __DIR__ . '/../utils/db_diagnostics.php';
require_once __DIR__ . '/../utils/rate_limiter.php';
require_once __DIR__ . '/../utils/csrf_protection.php'; // Include CSRF protection

// Get client IP for rate limiting
$clientIP = $_SERVER['REMOTE_ADDR'];
if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && filter_var($_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP)) {
    $clientIP = $_SERVER['HTTP_X_FORWARDED_FOR'];
}

// Get rate limit configuration for registration
$rateLimitKey = 'register:' . $clientIP;

// Enforce rate limiting using configuration
$config = getRateLimitConfig('registration');
$maxAttempts = $config['max_attempts'];
$timeWindow = $config['window'];

// Enforce rate limiting before processing
if (!enforceRateLimit(
    $rateLimitKey,
    $maxAttempts,
    $timeWindow,
    "Too many registration attempts. Please wait a while before trying again."
)) {
    // Rate limit exceeded and response already sent
    logRegistration(
        "Registration rate limit exceeded",
        [
            "ip" => $clientIP,
            "attempts" => $maxAttempts,
            "window" => $timeWindow
        ],
        "WARNING"
    );
    exit;
}

// Check if the form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Log registration attempt
    logRegistration("Registration attempt started", ["ip" => $_SERVER['REMOTE_ADDR']]);

    // Get form data
    $firstName = trim($_POST['firstName'] ?? '');
    $lastName = trim($_POST['lastName'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirmPassword'] ?? '';
    $termsAgreement = isset($_POST['termsAgreement']);
    $csrfToken = $_POST['csrf_token'] ?? '';

    // CSRF protection check using our new utility
    if (!validateCSRFToken($csrfToken)) {
        logRegistration("CSRF token validation failed", ["ip" => $clientIP], "ERROR");
        redirect_with_error("Security check failed. Please try again.");
        exit;
    }

    // Basic validation
    $errors = [];

    if (empty($firstName)) {
        $errors[] = "First name is required";
    }

    if (empty($lastName)) {
        $errors[] = "Last name is required";
    }

    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Valid email is required";
    }

    if (empty($password)) {
        $errors[] = "Password is required";
    } elseif (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters";
    } elseif (!validatePasswordStrength($password)) {
        $errors[] = "Password must include uppercase, lowercase, numbers, and special characters";
    }

    if ($password !== $confirmPassword) {
        $errors[] = "Passwords do not match";
    }

    if (!$termsAgreement) {
        $errors[] = "You must agree to the terms and conditions";
    }

    // If no validation errors, proceed
    if (empty($errors)) {
        logRegistration("Registration validation passed", ["email" => $email]);

        try {
            // Check if user with this email already exists
            $existingUser = findUserByEmail($email);

            if ($existingUser) {
                logRegistration("Registration failed - Email already exists", ["email" => $email], "WARNING");
                redirect_with_error("Email already registered. Please log in or use a different email.");
                exit;
            }

            // Generate verification token
            $verificationToken = generateToken();
            $tokenExpiry = date('Y-m-d H:i:s', strtotime('+30 minutes'));

            // Hash password
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            // Prepare user data with formatted DateTime strings
            $userData = [
                'firstName' => $firstName,
                'lastName' => $lastName,
                'email' => $email,
                'password' => $hashedPassword,
                'verificationToken' => $verificationToken,
                'tokenExpiry' => $tokenExpiry,
                'verified' => false,
                'active' => true,
                'created_at' => (new DateTime())->format('Y-m-d H:i:s'),
                'updated_at' => (new DateTime())->format('Y-m-d H:i:s')
            ];

            logRegistration("Attempting to create user record", ["email" => $email]);

            // Insert user into database
            $result = insertUser($userData);

            // Check if insertion was successful
            if ($result && (getDbType() === 'mongodb' ? $result->getInsertedCount() : true)) {
                // Get user ID
                $userId = getDbType() === 'mongodb' ?
                    (string) $result->getInsertedId() :
                    $result->getInsertedId();

                logRegistration("User created successfully", ["email" => $email, "userId" => $userId]);

                // Create verification link
                $verificationLink = "http://{$_SERVER['HTTP_HOST']}/auth/pages/verify.php?token=$verificationToken&id=$userId";

                // Send verification email
                $emailSent = false;
                try {
                    logRegistration("Sending verification email", ["email" => $email, "userId" => $userId]);
                    $emailSent = sendVerificationEmail($email, $firstName, $verificationLink);
                } catch (Exception $e) {
                    logError("Failed to send verification email: " . $e->getMessage(), ["email" => $email, "userId" => $userId], "registration.log");
                    error_log("Failed to send email: " . $e->getMessage());
                }

                if ($emailSent) {
                    logRegistration("Registration completed successfully", ["email" => $email, "userId" => $userId]);
                    $_SESSION['registration_success'] = true;
                    $_SESSION['registration_email'] = $email;

                    // Redirect to the registration success page (correct path)
                    header("Location: ../../pages/registration-success.php");
                    exit;
                } else {
                    // Account created but email failed to send
                    logRegistration("Registration completed but email delivery failed", ["email" => $email, "userId" => $userId], "WARNING");
                    $_SESSION['registration_success'] = true;
                    $_SESSION['registration_email'] = $email;

                    // Check mail configuration for better error reporting
                    $mailConfig = checkMailConfiguration();
                    logRegistration("Mail configuration check", $mailConfig, "INFO");

                    // Redirect to success page but with warning about email (correct path)
                    header("Location: ../../pages/registration-success.php?email=" . urlencode($email) . "&warning=" .
                        urlencode("Your account was created successfully! However, we couldn't send the verification email. " .
                            "You can request a new verification email from this page."));
                    exit;
                }
            } else {
                // Run database diagnostics to identify the issue
                $diagnostics = runDatabaseDiagnostics('user_registration_failure');

                // Log detailed information about the failure
                logRegistration(
                    "Failed to insert user into database with detailed diagnostics",
                    [
                        "email" => $email,
                        "db_type" => getDbType(),
                        "db_status" => $diagnostics['status'],
                        "db_error" => $diagnostics['error'] ?? 'Unknown error',
                        "suggestions" => $diagnostics['suggestions'] ?? []
                    ],
                    "ERROR"
                );

                // Provide more helpful error message if possible
                $errorMessage = "Failed to create account. ";

                if ($diagnostics['status'] === 'error') {
                    $errorMessage .= "Database connection issue detected. ";

                    // Add administrator contact info if available
                    $adminContact = getEnvVar('ADMIN_CONTACT_EMAIL');
                    if (!empty($adminContact)) {
                        $errorMessage .= "Please contact the administrator at {$adminContact}.";
                    } else {
                        $errorMessage .= "Please try again later or contact the administrator.";
                    }
                } else {
                    $errorMessage .= "Please try again later.";
                }

                redirect_with_error($errorMessage);
            }
        } catch (Exception $e) {
            logRegistration("Exception occurred during registration: " . $e->getMessage(), null, "ERROR");
            redirect_with_error("An error occurred: " . $e->getMessage());
        }
    } else {
        // If there are validation errors, redirect back with the first error
        logRegistration("Registration validation failed", ["email" => $email, "errors" => $errors], "WARNING");
        redirect_with_error($errors[0]);
    }
} else {
    // If not a POST request, redirect to registration page (correct path)
    header('Location: ../../pages/register.php');
    exit;
}

// Helper function to redirect with error (update extension)
function redirect_with_error($message)
{
    logRegistration("Redirecting with error: " . $message, null, "WARNING");
    $encodedMessage = urlencode($message);
    header("Location: ../../pages/register.php?error=$encodedMessage");
    exit;
}

// Helper function to redirect with success (update extension)
function redirect_with_success($message)
{
    logRegistration("Redirecting with success message", null, "INFO");
    $encodedMessage = urlencode($message);
    header("Location: ../../pages/register.php?success=$encodedMessage");
    exit;
}
