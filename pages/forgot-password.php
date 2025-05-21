<?php
// Include required files
require_once '../config/env_loader.php';
require_once '../vendor/autoload.php'; // Include MongoDB library
require_once '../config/database.php';
require_once '../config/config.php';
require_once '../auth-handlers/utils/validation.php';
require_once '../auth-handlers/utils/session_manager.php';
require_once '../auth-handlers/utils/recaptcha.php';
require_once '../auth-handlers/utils/rate_limiter.php';

// Initialize secure session
initSecureSession();
setSecurityHeaders();

// Initialize variables
$error = '';
$success = '';
$email = '';

// DDOS protection - using rate limiter
$ip = $_SERVER['REMOTE_ADDR'];
if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && filter_var($_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP)) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
}

// Add detailed logging to a specific file for password reset operations
function logPasswordReset($message, $data = null)
{
    // Check if logging is enabled in .env
    if (filter_var(getEnvVar('ENABLE_LOGGING', 'false'), FILTER_VALIDATE_BOOLEAN) !== true) {
        return;
    }

    $logFile = __DIR__ . '/../logs/password_reset.log';
    $logDir = dirname($logFile);

    // Create logs directory if it doesn't exist
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
    }

    $timestamp = date('Y-m-d H:i:s');
    $logMessage = "[$timestamp] $message";

    if ($data !== null) {
        $logMessage .= " - " . json_encode($data, JSON_UNESCAPED_SLASHES);
    }

    file_put_contents($logFile, $logMessage . PHP_EOL, FILE_APPEND);

    // Also send to error_log for server logs
    error_log("PASSWORD RESET: $message");
}

// Enhanced error handling
function handleResetError($e, $context = '')
{
    logPasswordReset("ERROR in $context: " . $e->getMessage(), [
        'trace' => $e->getTraceAsString()
    ]);
    return 'An error occurred. Please try again later.';
}

// Function to send password reset email
function sendPasswordResetEmail($email, $name, $resetLink)
{
    try {
        // Get email configuration from .env
        $mailHost = getEnvVar('MAIL_HOST', 'localhost');
        $mailPort = getEnvVar('MAIL_PORT', 25);
        $mailUsername = getEnvVar('MAIL_USERNAME');
        $mailPassword = getEnvVar('MAIL_PASSWORD');
        $mailEncryption = getEnvVar('MAIL_ENCRYPTION', 'tls');
        $mailFromAddress = getEnvVar('MAIL_FROM_ADDRESS');
        $mailFromName = getEnvVar('MAIL_FROM_NAME');

        // Log email configuration (without sensitive data)
        logPasswordReset("Email configuration loaded", [
            'host' => $mailHost,
            'port' => $mailPort,
            'username' => !empty($mailUsername) ? substr($mailUsername, 0, 3) . '***' : 'not set',
            'password' => !empty($mailPassword) ? 'set (hidden)' : 'not set',
            'encryption' => $mailEncryption,
            'from_address' => $mailFromAddress,
            'from_name' => $mailFromName
        ]);

        $subject = APP_NAME . " - Password Reset Request";

        $message = "
        <html>
        <head>
            <title>Password Reset Request</title>
        </head>
        <body>
            <p>Hello " . ($name ? htmlspecialchars($name) : "there") . ",</p>
            <p>You recently requested to reset your password for your " . APP_NAME . " account.</p>
            <p>Please click the link below to reset your password:</p>
            <p><a href='" . $resetLink . "'>" . $resetLink . "</a></p>
            <p>This link is valid for 1 hour. After that, you'll need to submit a new request.</p>
            <p>If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
            <p>Regards,<br/>" . $mailFromName . " Team</p>
        </body>
        </html>
        ";

        logPasswordReset("Attempting to send email to: $email", [
            'recipient_name' => $name,
            'subject' => $subject,
            'link_generated' => $resetLink
        ]);

        // For Gmail specifically, we need to use PHPMailer with proper settings
        if (class_exists('PHPMailer\PHPMailer\PHPMailer')) {
            logPasswordReset("Using PHPMailer for email sending");

            // Use PHPMailer for better email delivery
            $mail = new PHPMailer\PHPMailer\PHPMailer(true);

            // Enable verbose debug output
            $mail->SMTPDebug = 3; // 3 = show connection status + all client/server messages

            // Capture SMTP debugging output
            $debugOutput = '';
            $mail->Debugoutput = function ($str, $level) use (&$debugOutput) {
                $debugOutput .= "$level: $str\n";
            };

            // Server settings
            $mail->isSMTP();
            $mail->Host = $mailHost;
            $mail->Port = $mailPort;
            $mail->SMTPAuth = !empty($mailUsername);

            if (!empty($mailUsername)) {
                $mail->Username = $mailUsername;
                $mail->Password = $mailPassword;
            }

            if ($mailEncryption === 'tls') {
                $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
            } elseif ($mailEncryption === 'ssl') {
                $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
            }

            // Gmail requires TLS
            if (strpos($mailHost, 'gmail.com') !== false) {
                $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
                $mail->SMTPOptions = [
                    'ssl' => [
                        'verify_peer' => false,
                        'verify_peer_name' => false,
                        'allow_self_signed' => true
                    ]
                ];
            }

            // Recipients
            $mail->setFrom($mailFromAddress, $mailFromName);
            $mail->addAddress($email, $name);

            // Content
            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body = $message;

            try {
                // Send
                $mail->send();
                logPasswordReset("Email sent successfully via PHPMailer");

                // Log debug output to file for troubleshooting
                logPasswordReset("SMTP Debug Output", ['output' => $debugOutput]);

                return true;
            } catch (Exception $e) {
                logPasswordReset("PHPMailer error: " . $mail->ErrorInfo, [
                    'error_details' => $e->getMessage(),
                    'debug_output' => $debugOutput
                ]);
                return false;
            }
        } else {
            logPasswordReset("PHPMailer not available, falling back to PHP mail function");

            // Set email headers
            $headers = "MIME-Version: 1.0" . "\r\n";
            $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
            $headers .= "From: " . $mailFromName . " <" . $mailFromAddress . ">" . "\r\n";

            // Send email using built-in mail function
            $mailSent = mail($email, $subject, $message, $headers);
            logPasswordReset("PHP mail function result: " . ($mailSent ? "Success" : "Failed"));
            return $mailSent;
        }
    } catch (Exception $e) {
        logPasswordReset("Email sending error: " . $e->getMessage(), ['trace' => $e->getTraceAsString()]);
        return false;
    }
}

// Function to verify MongoDB connection
function testMongoDBConnection()
{
    try {
        $uri = getEnvVar('MONGODB_URI');
        $options = [
            'tls' => true,
            'tlsAllowInvalidCertificates' => true,
            'retryWrites' => true,
            'w' => 'majority'
        ];

        logPasswordReset("Testing MongoDB connection with URI: " . preg_replace('/mongodb\+srv:\/\/([^:]+):([^@]+)@/', 'mongodb+srv://\\1:***@', $uri));

        $client = new MongoDB\Client($uri, $options);

        // Force connection to verify it works
        $databases = $client->listDatabases();
        $dbNames = [];
        foreach ($databases as $db) {
            $dbNames[] = $db->getName();
        }

        logPasswordReset("MongoDB connection successful. Available databases: " . implode(", ", $dbNames));
        return true;
    } catch (Exception $e) {
        logPasswordReset("MongoDB connection test failed: " . $e->getMessage(), ['trace' => $e->getTraceAsString()]);
        return false;
    }
}

// Test the MongoDB connection when the page loads
testMongoDBConnection();

// Function to directly save password reset token
function localSavePasswordResetToken($email, $token, $expires)
{
    try {
        $uri = getEnvVar('MONGODB_URI');
        $options = [
            'tls' => true,
            'tlsAllowInvalidCertificates' => true,
            'retryWrites' => true,
            'w' => 'majority'
        ];

        $client = new MongoDB\Client($uri, $options);
        $database = $client->selectDatabase(getEnvVar('MONGODB_DATABASE', 'auth'));
        $collection = $database->selectCollection('password_resets');

        logPasswordReset("Attempting to save token for: $email", [
            'token_prefix' => substr($token, 0, 5) . '***',
            'expires' => $expires->toDateTime()->format('Y-m-d H:i:s')
        ]);

        // Delete any existing tokens for this email
        $deleteResult = $collection->deleteMany(['email' => $email]);
        logPasswordReset("Deleted existing tokens: " . $deleteResult->getDeletedCount());

        // Insert new token
        $result = $collection->insertOne([
            'email' => $email,
            'token' => $token,
            'expires' => $expires,
            'created_at' => new MongoDB\BSON\UTCDateTime()
        ]);

        $success = $result->getInsertedCount() > 0;
        logPasswordReset("Token saved result: " . ($success ? "Success" : "Failed"), [
            'inserted_id' => (string)$result->getInsertedId()
        ]);

        return $success;
    } catch (Exception $e) {
        logPasswordReset("Error saving token: " . $e->getMessage(), ['trace' => $e->getTraceAsString()]);
        throw $e;
    }
}

// Check if form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get email from form
    $email = sanitizeInput($_POST['email'] ?? '');

    // Rate limit based on IP and email combination
    $rateLimitKey = 'password_reset_' . md5($email . '_' . $ip);
    $maxResetAttempts = getEnvVar('MAX_PASSWORD_RESET_ATTEMPTS', 3);
    $resetTimeWindow = getEnvVar('PASSWORD_RESET_TIME_WINDOW', 3600); // 1 hour

    // Check rate limit
    if (isRateLimited($rateLimitKey, $maxResetAttempts, $resetTimeWindow)) {
        $error = "Too many password reset requests. Please try again later.";
    } else {
        logPasswordReset("Password reset request initiated", ['email' => $email]);

        try {
            // Validate email
            if (!validateEmail($email)) {
                $error = 'Please enter a valid email address.';
                logPasswordReset("Invalid email format", ['email' => $email]);
            }
            // Validate CSRF token
            else if (!isset($_POST['csrf_token']) || !validateCsrfToken($_POST['csrf_token'])) {
                $error = 'Invalid request. Please try again.';
                logPasswordReset("CSRF validation failed");
            }
            // Verify reCAPTCHA 
            else if (!validateRecaptcha($_POST['g-recaptcha-response'] ?? '')) {
                $error = 'Please complete the reCAPTCHA verification.';
                logPasswordReset("reCAPTCHA verification failed");
            }
            // Process valid request
            else {
                logPasswordReset("Processing valid request", ['email' => $email]);

                try {
                    // Check if user exists with this email using the function from config.php
                    $user = findUserByEmail($email);

                    logPasswordReset("User lookup result", [
                        'email' => $email,
                        'found' => $user ? true : false,
                        'data' => $user ? [
                            'id' => (string)($user->_id ?? 'N/A'),
                            'email' => $user->email ?? 'N/A',
                            'firstName' => $user->firstName ?? 'N/A'
                        ] : null
                    ]);

                    // If email exists but in different case, normalize it
                    if ($user && $user->email !== $email) {
                        logPasswordReset("Email found but with different case, normalizing", [
                            'submitted' => $email,
                            'actual' => $user->email
                        ]);
                        $email = $user->email;
                    }

                    if ($user) {
                        // Generate unique token
                        $token = bin2hex(random_bytes(32));

                        // Set expiration time (1 hour from now)
                        $expires = new MongoDB\BSON\UTCDateTime((time() + 3600) * 1000);

                        try {
                            // Try with the local function first
                            $tokenSaved = localSavePasswordResetToken($email, $token, $expires);

                            if ($tokenSaved) {
                                // Create reset link with email parameter
                                $resetLink = SITE_URL . '/pages/reset-password.php?token=' . $token . '&email=' . urlencode($email);

                                // Get user's name if available
                                $name = '';
                                if (isset($user->name)) {
                                    $name = $user->name;
                                } elseif (isset($user->firstName)) {
                                    $name = $user->firstName . ' ' . ($user->lastName ?? '');
                                }

                                // Send password reset email with debugging
                                $emailSent = sendPasswordResetEmail($email, $name, $resetLink);

                                if ($emailSent) {
                                    $success = 'Password reset instructions have been sent to your email.';
                                    $email = ''; // Clear the form
                                } else {
                                    // For troubleshooting in development, show a more specific message
                                    if (getEnvVar('APP_DEBUG', false)) {
                                        $error = 'Failed to send the email. Please check the server logs.';
                                        logPasswordReset("Email sending failed in debug mode");
                                    } else {
                                        $error = 'Failed to send password reset email. Please try again later or contact support.';
                                    }
                                }
                            } else {
                                $error = 'Failed to create password reset token. Please try again.';
                                logPasswordReset("Failed to save token");
                            }
                        } catch (Exception $e) {
                            $error = handleResetError($e, 'saving token');
                        }
                    } else {
                        // Don't reveal that the email doesn't exist (security best practice)
                        $success = 'If an account exists with this email, password reset instructions have been sent.';
                        logPasswordReset("Security response for non-existent email", ['email' => $email]);
                    }

                    // Log the password reset request
                    logUserActivity('password_reset_request', [
                        'email' => $email,
                        'status' => !empty($error) ? 'error' : 'success',
                        'error_message' => $error
                    ]);
                } catch (Exception $e) {
                    $error = handleResetError($e, 'user lookup');
                }
            }
        } catch (Exception $e) {
            $error = handleResetError($e, 'form validation');
        }
    }
}

// Generate CSRF token
$csrfToken = getCsrfToken();

// Get reCAPTCHA site key
$recaptchaSiteKey = getEnvVar('RECAPTCHA_SITE_KEY');
error_log("reCAPTCHA site key: " . (!empty($recaptchaSiteKey) ? 'Available' : 'Missing'));
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password - <?= APP_NAME ?></title>
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
    </style>
</head>

<body>
    <div class="container">
        <div class="form-container">
            <div class="logo">
                <h2><?= APP_NAME ?></h2>
                <h4>Forgot Password</h4>
            </div>

            <?php if (!empty($error)): ?>
                <div class="alert alert-danger"><?= $error ?></div>
            <?php endif; ?>

            <?php if (!empty($success)): ?>
                <div class="alert alert-success"><?= $success ?></div>
            <?php endif; ?>

            <?php if (empty($success)): ?>
                <p class="mb-4">Enter your email address and we'll send you a link to reset your password.</p>

                <form method="POST" action="">
                    <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">

                    <div class="form-group">
                        <label for="email">Email Address</label>
                        <input type="email" class="form-control" id="email" name="email"
                            value="<?= htmlspecialchars($email) ?>" required>
                    </div>

                    <div class="form-group">
                        <div class="g-recaptcha" data-sitekey="<?= htmlspecialchars($recaptchaSiteKey) ?>"></div>
                    </div>

                    <div class="d-grid">
                        <button type="submit" class="btn btn-primary">Send Reset Link</button>
                    </div>
                </form>
            <?php endif; ?>

            <div class="mt-4 text-center">
                <a href="../index.html">Back to Home</a> |
                <a href="login.php">Login</a>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>