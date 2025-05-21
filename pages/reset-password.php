<?php
// Include required files
require_once '../config/env_loader.php';
require_once '../vendor/autoload.php'; // Include MongoDB library
require_once '../config/database.php';
require_once '../config/config.php';
require_once '../auth-handlers/utils/validation.php';
require_once '../auth-handlers/utils/session_manager.php';
require_once '../auth-handlers/utils/recaptcha.php';

// Initialize secure session
initSecureSession();
setSecurityHeaders();

// Central function to handle password reset logging
function logPasswordResetAction($message, $data = null)
{
    // Check if logging is enabled in .env
    if (filter_var(getEnvVar('ENABLE_LOGGING', 'false'), FILTER_VALIDATE_BOOLEAN) !== true) {
        return;
    }

    $logFile = __DIR__ . '/../logs/password_reset.log';
    $timestamp = date('Y-m-d H:i:s');
    $log = "[$timestamp] $message";

    if ($data !== null) {
        $log .= " - " . json_encode($data, JSON_UNESCAPED_SLASHES);
    }

    file_put_contents($logFile, $log . PHP_EOL, FILE_APPEND);
}

// Function to check if token is expired
function isTokenExpired($tokenExpiresTimestamp)
{
    // Convert MongoDB\BSON\UTCDateTime to PHP DateTime
    $expiryDateTime = $tokenExpiresTimestamp->toDateTime();
    $currentDateTime = new DateTime();

    return $currentDateTime > $expiryDateTime;
}

// Function to check password reset token with email validation
function checkPasswordResetToken($token, $email = null)
{
    try {
        logPasswordResetAction("Looking up password reset token", [
            'token_prefix' => substr($token, 0, 5) . '...',
            'email' => $email,
            'full_token' => $token // Log full token temporarily for debugging
        ]);

        // Use the MongoDB connection from config.php instead of creating a new one
        // Get MongoDB connection from .env
        $uri = getEnvVar('MONGODB_URI');
        if (empty($uri)) {
            logPasswordResetAction("Error: MONGODB_URI not found in environment variables");
            return 'db_error';
        }

        logPasswordResetAction("Using MongoDB connection from .env");

        $options = [
            'tls' => true,
            'tlsAllowInvalidCertificates' => true,
            'retryWrites' => true,
            'w' => 'majority'
        ];

        try {
            // Create MongoDB connection
            $mongo_manager = new MongoDB\Driver\Manager($uri, $options);
            $dbName = getEnvVar('MONGODB_DATABASE', 'auth');

            logPasswordResetAction("Using MongoDB driver to search for token");

            // First, let's find if the token exists at all regardless of expiry
            $filter = ['token' => $token];
            $query = new MongoDB\Driver\Query($filter);

            logPasswordResetAction("Searching for token in database", [
                'database' => $dbName,
                'collection' => 'password_resets',
                'filter' => json_encode($filter)
            ]);

            $cursor = $mongo_manager->executeQuery("$dbName.password_resets", $query);
            $results = $cursor->toArray();

            if (count($results) === 0) {
                logPasswordResetAction("Token not found in database at all");
                return 'not_found';
            }

            // Token found, get the record
            $tokenData = $results[0];

            logPasswordResetAction("Token found in database", [
                'token_email' => $tokenData->email ?? 'unknown',
                'created_at' => isset($tokenData->created_at) ? $tokenData->created_at->toDateTime()->format('Y-m-d H:i:s') : 'N/A',
                'has_expires_at' => isset($tokenData->expires_at) ? 'yes' : 'no',
                'has_expires' => isset($tokenData->expires) ? 'yes' : 'no',
                'used' => isset($tokenData->used) ? $tokenData->used : false
            ]);

            // Check if email matches
            if ($email && isset($tokenData->email) && $tokenData->email !== $email) {
                logPasswordResetAction("Email mismatch", [
                    'token_email' => $tokenData->email,
                    'provided_email' => $email
                ]);
                return 'wrong_email';
            }

            // Check if token is used
            if (isset($tokenData->used) && $tokenData->used) {
                logPasswordResetAction("Token already used");
                return 'used';
            }

            // Check if token is expired
            $currentTime = new DateTime();
            $expireField = null;

            // Try to find which field contains expiry information
            if (isset($tokenData->expires_at)) {
                $expireField = $tokenData->expires_at;
                $fieldName = 'expires_at';
                logPasswordResetAction("Found expires_at field");
            } elseif (isset($tokenData->expires)) {
                $expireField = $tokenData->expires;
                $fieldName = 'expires';
                logPasswordResetAction("Found expires field");
            }

            if ($expireField) {
                // Convert to DateTime properly
                if ($expireField instanceof MongoDB\BSON\UTCDateTime) {
                    $expiryDateTime = $expireField->toDateTime();
                    logPasswordResetAction("Expiry date (from UTCDateTime)", [
                        'field' => $fieldName,
                        'expiry_time' => $expiryDateTime->format('Y-m-d H:i:s'),
                        'current_time' => $currentTime->format('Y-m-d H:i:s'),
                        'is_expired' => ($currentTime > $expiryDateTime) ? 'Yes' : 'No'
                    ]);

                    if ($currentTime > $expiryDateTime) {
                        return 'expired';
                    }
                } else if (is_string($expireField)) {
                    // If stored as string
                    $expiryDateTime = new DateTime($expireField);
                    logPasswordResetAction("Expiry date (from string)", [
                        'field' => $fieldName,
                        'expiry_time' => $expiryDateTime->format('Y-m-d H:i:s'),
                        'current_time' => $currentTime->format('Y-m-d H:i:s'),
                        'is_expired' => ($currentTime > $expiryDateTime) ? 'Yes' : 'No'
                    ]);

                    if ($currentTime > $expiryDateTime) {
                        return 'expired';
                    }
                }
            } else {
                logPasswordResetAction("No expiry field found in token record");
            }

            logPasswordResetAction("Token is valid");
            return $tokenData;
        } catch (Exception $e) {
            logPasswordResetAction("MongoDB error: " . $e->getMessage(), ['trace' => $e->getTraceAsString()]);
            return 'db_error';
        }
    } catch (Exception $e) {
        error_log("Error checking password reset token: " . $e->getMessage());
        return 'error';
    }
}

// Mark a token as used and then delete it
function markTokenAsUsedAndDelete($token, $email)
{
    try {
        logPasswordResetAction("Marking token as used and then deleting", [
            'token_prefix' => substr($token, 0, 5) . '...',
            'email' => $email
        ]);

        // Use the MongoDB connection string from .env
        $uri = getEnvVar('MONGODB_URI');
        if (empty($uri)) {
            logPasswordResetAction("Error: MONGODB_URI not found in environment variables");
            return false;
        }

        $options = [
            'tls' => true,
            'tlsAllowInvalidCertificates' => true,
            'retryWrites' => true,
            'w' => 'majority'
        ];

        try {
            // Create MongoDB connection
            $mongo_manager = new MongoDB\Driver\Manager($uri, $options);
            $dbName = getEnvVar('MONGODB_DATABASE', 'auth');

            // First mark as used
            $bulk = new MongoDB\Driver\BulkWrite;
            $bulk->update(
                ['token' => $token, 'email' => $email],
                ['$set' => ['used' => true]]
            );
            $result = $mongo_manager->executeBulkWrite("$dbName.password_resets", $bulk);

            logPasswordResetAction("Token marked as used", [
                'matched' => $result->getMatchedCount(),
                'modified' => $result->getModifiedCount()
            ]);

            // Then delete the token (optional)
            $bulk = new MongoDB\Driver\BulkWrite;
            $bulk->delete(['token' => $token]);
            $result = $mongo_manager->executeBulkWrite("$dbName.password_resets", $bulk);

            logPasswordResetAction("Token deleted", [
                'deleted' => $result->getDeletedCount()
            ]);

            return true;
        } catch (Exception $e) {
            logPasswordResetAction("MongoDB operation error: " . $e->getMessage(), ['trace' => $e->getTraceAsString()]);
            return false;
        }
    } catch (Exception $e) {
        error_log("Error handling token: " . $e->getMessage());
        return false;
    }
}

// Initialize variables
$error = '';
$success = '';
$token = '';
$email = '';
$validToken = false;
$tokenData = null;

// Check if token and email are provided in URL
if (isset($_GET['token']) && !empty($_GET['token'])) {
    $token = $_GET['token'];
    $email = isset($_GET['email']) ? urldecode($_GET['email']) : '';

    // Validate token format (should be 64 characters hexadecimal)
    if (!preg_match('/^[0-9a-f]{64}$/i', $token)) {
        $error = 'Invalid password reset token format.';
    } else if (empty($email)) {
        $error = 'Email is required to validate your password reset request.';
    } else {
        // Look up token in database with email validation
        $tokenData = checkPasswordResetToken($token, $email);

        // Add log entry to see what's returned
        $logFile = __DIR__ . '/../logs/password_reset.log';
        file_put_contents($logFile, "[" . date('Y-m-d H:i:s') . "] Token check result: " . (is_string($tokenData) ? $tokenData : "valid token object") . PHP_EOL, FILE_APPEND);

        if ($tokenData === 'used') {
            $error = 'This password reset link has already been used.';
        } else if ($tokenData === 'wrong_email') {
            $error = 'No password reset request found for this email address.';
        } else if ($tokenData === 'expired') {
            $error = 'Your password reset link has expired. Please request a new one.';
        } else if ($tokenData === 'not_found') {
            $error = 'The password reset token was not found in our system. Please request a new link.';
        } else if ($tokenData === 'db_error' || $tokenData === 'error') {
            $error = 'A system error occurred while processing your request. Please try again later.';
        } else if ($tokenData) {
            $validToken = true;
            // Email was provided in URL, and we found a valid token
        } else {
            $error = 'No valid password reset token found for your email address. Please request a new reset link.';
        }
    }
} else {
    $error = 'Password reset token is missing. Please use the link from your email.';
}

// Check if form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $validToken) {
    if (!validateCsrfToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $password = $_POST['password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';

        // Validate recaptcha
        $recaptcha_response = $_POST['g-recaptcha-response'] ?? '';
        if (!function_exists('validateRecaptcha')) {
            // Define the function if it doesn't exist in the included file
            function validateRecaptcha($response)
            {
                if (empty($response)) {
                    return false;
                }

                $secret = getEnvVar('RECAPTCHA_SECRET_KEY');
                if (empty($secret)) {
                    // Log this issue
                    error_log("RECAPTCHA_SECRET_KEY not found in environment variables");
                    // Return true to bypass recaptcha if not configured
                    return true;
                }

                $url = 'https://www.google.com/recaptcha/api/siteverify';
                $data = [
                    'secret' => $secret,
                    'response' => $response,
                    'remoteip' => $_SERVER['REMOTE_ADDR']
                ];

                $options = [
                    'http' => [
                        'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                        'method' => 'POST',
                        'content' => http_build_query($data)
                    ]
                ];

                $context = stream_context_create($options);
                $result = file_get_contents($url, false, $context);
                $result_json = json_decode($result, true);

                return $result_json['success'] ?? false;
            }
        }

        if (!validateRecaptcha($recaptcha_response)) {
            $error = 'Please verify that you are not a robot.';
        }
        // Validate password
        else if (empty($password)) {
            $error = 'Please enter a new password.';
        } else if (strlen($password) < 8) {
            $error = 'Password must be at least 8 characters long.';
        } else if (!preg_match('/[A-Z]/', $password)) {
            $error = 'Password must contain at least one uppercase letter.';
        } else if (!preg_match('/[a-z]/', $password)) {
            $error = 'Password must contain at least one lowercase letter.';
        } else if (!preg_match('/[0-9]/', $password)) {
            $error = 'Password must contain at least one number.';
        } else if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            $error = 'Password must contain at least one special character.';
        } else if ($password !== $confirm_password) {
            $error = 'Passwords do not match.';
        } else {
            // All validations passed, update password
            try {
                // Log the attempt
                logPasswordResetAction("Attempting to update password for email: $email");

                // Hash the new password
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                // Update the user's password - using function from config.php
                updateUserPassword($email, $hashed_password);

                // Mark token as used and delete it
                markTokenAsUsedAndDelete($token, $email);

                // Set success message
                $success = 'Your password has been reset successfully. You can now log in with your new password.';

                // Clear form data
                $token = '';
                $email = '';
                $validToken = false;
                $tokenData = null;
            } catch (Exception $e) {
                logPasswordResetAction("Error resetting password: " . $e->getMessage(), ['trace' => $e->getTraceAsString()]);
                $error = 'An error occurred while resetting your password: ' . $e->getMessage();
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - <?= APP_NAME ?></title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- reCAPTCHA API -->
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        body {
            background-color: #f8f9fa;
            padding-top: 50px;
        }

        .form-container {
            max-width: 500px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 15px rgba(0, 0, 0, 0.1);
        }

        .logo {
            text-align: center;
            margin-bottom: 30px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .password-validation {
            font-size: 0.8rem;
            margin-top: 5px;
        }

        .password-validation ul {
            padding-left: 20px;
            margin-bottom: 0;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="form-container">
            <div class="logo">
                <h2><?= APP_NAME ?></h2>
                <h4>Reset Password</h4>
            </div>

            <?php if (!empty($error)): ?>
                <div class="alert alert-danger"><?= $error ?></div>
                <div class="text-center mt-4">
                    <a href="forgot-password.php" class="btn btn-outline-primary">Request New Reset Link</a>
                </div>
            <?php endif; ?>

            <?php if (!empty($success)): ?>
                <div class="alert alert-success"><?= $success ?></div>
                <div class="text-center mt-4">
                    <a href="login.php" class=" btn btn-primary">Login</a>
                </div>
            <?php endif; ?>

            <?php if ($validToken && empty($success)): ?>
                <p class="mb-4">Please create a new password for your account.</p>

                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= getCsrfToken() ?>">
                    <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">
                    <input type="hidden" name="email" value="<?= htmlspecialchars($email) ?>">

                    <div class="form-group">
                        <label for="password">New Password</label>
                        <input type="password" class="form-control" id="password" name="password" required minlength="8">
                        <div class="password-validation text-muted">
                            Password must contain:
                            <ul>
                                <li>At least 8 characters</li>
                                <li>One uppercase letter</li>
                                <li>One lowercase letter</li>
                                <li>One number</li>
                                <li>One special character</li>
                            </ul>
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="confirm_password">Confirm New Password</label>
                        <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                    </div>

                    <div class="form-group">
                        <div class="g-recaptcha" data-sitekey="<?= htmlspecialchars(getEnvVar('RECAPTCHA_SITE_KEY')) ?>"></div>
                    </div>

                    <div class="d-grid">
                        <button type="submit" class="btn btn-primary">Reset Password</button>
                    </div>
                </form>
            <?php endif; ?>

            <div class="mt-4 text-center">
                <a href="../index.html">Back to Home</a>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>

    <script>
        // Client-side password validation
        document.getElementById('password').addEventListener('keyup', function() {
            const password = this.value;
            const validations = {
                uppercase: /[A-Z]/.test(password),
                lowercase: /[a-z]/.test(password),
                number: /[0-9]/.test(password),
                special: /[^A-Za-z0-9]/.test(password),
                length: password.length >= 8
            };

            // Update validation list visual feedback
            const validationList = document.querySelectorAll('.password-validation li');
            validationList[0].style.color = validations.length ? 'green' : '';
            validationList[1].style.color = validations.uppercase ? 'green' : '';
            validationList[2].style.color = validations.lowercase ? 'green' : '';
            validationList[3].style.color = validations.number ? 'green' : '';
            validationList[4].style.color = validations.special ? 'green' : '';
        });

        // Check if passwords match
        document.getElementById('confirm_password').addEventListener('keyup', function() {
            const password = document.getElementById('password').value;
            if (this.value === password) {
                this.setCustomValidity('');
            } else {
                this.setCustomValidity('Passwords do not match');
            }
        });
    </script>
</body>

</html>