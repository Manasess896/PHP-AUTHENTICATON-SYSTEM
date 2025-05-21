<?php
// Include necessary files and setup
require_once __DIR__ . '/../config/env_loader.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../auth-handlers/utils/validation.php';
require_once __DIR__ . '/../auth-handlers/utils/recaptcha.php';
require_once __DIR__ . '/../auth-handlers/utils/tokens.php';
require_once __DIR__ . '/../auth-handlers/utils/rate_limiter.php';

// Enable error reporting for debugging but don't display errors
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/../auth-handlers/logs/login_errors.log');

// Start session with secure settings
ini_set('session.gc_maxlifetime', 3600); // 60 minutes
session_set_cookie_params([
    'lifetime' => 3600, // 60 minutes
    'path' => '/',
    'domain' => '',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Lax'
]);
session_start();

// Generate CSRF token if it doesn't exist
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// DDOS protection using rate limiter
$ip = $_SERVER['REMOTE_ADDR'];
if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && filter_var($_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP)) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
}

// Rate limit key based on IP
$rateLimitKey = 'login_' . $ip;
$maxLoginAttempts = getEnvVar('MAX_LOGIN_ATTEMPTS', 5);
$loginTimeWindow = getEnvVar('LOGIN_TIME_WINDOW', 900); // 15 minutes

// Check rate limit
if (isRateLimited($rateLimitKey, $maxLoginAttempts, $loginTimeWindow)) {
    $secondsLeft = getSecondsUntilRetry($rateLimitKey, $loginTimeWindow);
    $message = 'Too many failed login attempts. Please try again later.';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        header('Content-Type: application/json');
        http_response_code(429); // Too Many Requests
        echo json_encode([
            'success' => false,
            'message' => $message,
            'retry_after' => $secondsLeft
        ]);
        exit;
    }
    // For GET requests, show the error message on the form
    $loginError = $message;
}

// Function to validate and sanitize redirect URLs for security
function getValidRedirectUrl($url = null)
{
    // Default redirect location
    $defaultRedirect = '/auth/dashboard/dashboard.php';

    // If no URL provided, use default
    if (empty($url)) {
        return $defaultRedirect;
    }

    // Validate URL - only allow internal redirects
    // Remove any protocol and domain components
    $url = ltrim($url, '/');

    // Whitelist of allowed redirect destinations
    $allowedPaths = [
        'auth/dashboard/dashboard.php',

    ];

    // Check if URL starts with any allowed path
    foreach ($allowedPaths as $allowedPath) {
        if (strpos($url, $allowedPath) === 0) {
            return '/' . $url; // Add leading slash back
        }
    }

    // If not valid, return default
    return $defaultRedirect;
}

// Process only POST requests - handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get the requested redirect URL if present
    $redirectUrl = isset($_POST['redirect_to']) ? $_POST['redirect_to'] : null;
    $validRedirectUrl = getValidRedirectUrl($redirectUrl);

    // Check if this is an AJAX request
    $isAjax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';

    // Set proper content type for JSON response if AJAX
    if ($isAjax) {
        header('Content-Type: application/json');
    }

    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        error_log("CSRF token validation failed");
        http_response_code(403); // Forbidden
        echo json_encode([
            'success' => false,
            'message' => 'Invalid request. Please refresh the page and try again.'
        ]);
        exit;
    }

    // Verify reCAPTCHA
    $recaptchaResponse = $_POST['g-recaptcha-response'] ?? '';
    if (!verifyRecaptcha($recaptchaResponse)) {
        error_log("reCAPTCHA verification failed");
        http_response_code(400); // Bad Request
        echo json_encode([
            'success' => false,
            'message' => 'reCAPTCHA verification failed. Please try again.'
        ]);
        exit;
    }

    // Validate required fields
    if (empty($_POST['email']) || empty($_POST['password'])) {
        http_response_code(400); // Bad Request
        echo json_encode([
            'success' => false,
            'message' => 'Email and password are required'
        ]);
        exit;
    }

    // Sanitize inputs
    $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];
    $rememberMe = isset($_POST['remember']) && $_POST['remember'] === 'on';

    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400); // Bad Request
        echo json_encode([
            'success' => false,
            'message' => 'Invalid email format'
        ]);
        exit;
    }

    try {
        // Get database connection
        $db = getDatabaseConnection();

        // Check if the database connection was successful
        if (!$db) {
            error_log("Database connection failed completely");
            throw new Exception("Database connection failed. Please try again later.");
        }

        // Check if users collection is accessible
        try {
            $usersCollection = $db->users;

            // Verify the collection is accessible by running a test query
            $testQuery = $usersCollection->findOne([], ['limit' => 1, 'projection' => ['_id' => 1]]);
            error_log("Database connection test successful, users collection is accessible");
        } catch (Exception $e) {
            error_log("Error accessing users collection: " . $e->getMessage());
            throw new Exception("Database error: Unable to access user data. Please try again later.");
        }

        // Find user by email
        error_log("Looking up user with email: " . $email);
        $user = $usersCollection->findOne(['email' => $email]);

        if (!$user) {
            // Use rate limiter instead of local tracking
            enforceRateLimit($rateLimitKey, $maxLoginAttempts, $loginTimeWindow);
            http_response_code(401); // Unauthorized
            echo json_encode([
                'success' => false,
                'message' => 'Invalid email or password'
            ]);
            exit;
        }

        // Verify password
        if (!password_verify($password, $user->password)) {
            // Use rate limiter instead of local tracking
            enforceRateLimit($rateLimitKey, $maxLoginAttempts, $loginTimeWindow);
            http_response_code(401); // Unauthorized
            echo json_encode([
                'success' => false,
                'message' => 'Invalid email or password'
            ]);
            exit;
        }

        // Check if email is verified
        if (isset($user->email_verified) && $user->email_verified === false) {
            http_response_code(401); // Unauthorized
            echo json_encode([
                'success' => false,
                'message' => 'Please verify your email before logging in'
            ]);
            exit;
        }

        // Reset failed attempts since login is successful by removing rate limit record
        try {
            $client = getDatabaseConnection();
            // Check if the returned object is already a database object
            if ($client instanceof MongoDB\Database) {
                $collection = $client->selectCollection('rate_limits');
            } else {
                // Else get a database object first
                $collection = $client->selectDatabase('auth')->selectCollection('rate_limits');
            }
            $collection->deleteOne(['key' => $rateLimitKey]);
        } catch (\Exception $e) {
            error_log("Failed to reset rate limit: " . $e->getMessage());
        }

        // Set up session data
        $_SESSION['user_id'] = (string)$user->_id;
        $_SESSION['user_email'] = $user->email;
        $_SESSION['user_name'] = isset($user->firstName) ? $user->firstName . ' ' . ($user->lastName ?? '') : explode('@', $user->email)[0];
        $_SESSION['is_logged_in'] = true;
        $_SESSION['last_activity'] = time();

        // Check for admin status
        if ((isset($user->is_admin) && $user->is_admin) ||
            (isset($user->isAdmin) && $user->isAdmin)
        ) {
            $_SESSION['is_admin'] = true;
        }

        // Regenerate session ID for security
        session_regenerate_id(true);

        // Handle "Remember Me" functionality
        if ($rememberMe) {
            $token = bin2hex(random_bytes(32));
            $expiry = time() + (30 * 24 * 60 * 60); // 30 days

            // Store token in database
            $tokensCollection = $db->auth_tokens;
            $tokensCollection->insertOne([
                'user_id' => $user->_id,
                'token' => $token,
                'expiry' => new MongoDB\BSON\UTCDateTime($expiry * 1000),
                'created_at' => new MongoDB\BSON\UTCDateTime(time() * 1000),
                'ip_address' => $_SERVER['REMOTE_ADDR'],
                'user_agent' => $_SERVER['HTTP_USER_AGENT']
            ]);

            // Set cookie
            setcookie('remember_token', $token, [
                'expires' => $expiry,
                'path' => '/',
                'domain' => '',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Lax'
            ]);
        }

        // Log successful login
        error_log("Successful login for user: " . $email);

        // Always perform server-side redirect regardless of request type
        header("Location: $validRedirectUrl");
        exit;
    } catch (Exception $e) {
        error_log("Login exception: " . $e->getMessage());

        if ($isAjax) {
            http_response_code(500); // Internal Server Error
            echo json_encode([
                'success' => false,
                'message' => 'A system error occurred. Please try again later.'
            ]);
        } else {
            // For regular form submissions, redirect with error parameter
            header("Location: login.php?error=" . urlencode('A system error occurred. Please try again later.'));
            exit;
        }
    }
    exit; // Stop processing after handling the POST request
}

// Check if we should display a redirect parameter
$redirectTo = isset($_GET['redirect_to']) ? htmlspecialchars($_GET['redirect_to']) : '';

// If we get here, we're handling a GET request to display the login form
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - authBoost</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <!-- Google reCAPTCHA v2 -->
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        body {
            background-color: #f8f9fa;
            height: 100vh;
            display: flex;
            align-items: center;
        }

        .login-container {
            max-width: 450px;
            margin: 0 auto;
            padding: 2rem;
            background-color: #fff;
            border-radius: 12px;
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
        }

        .form-control:focus {
            border-color: #4361ee;
            box-shadow: 0 0 0 0.25rem rgba(67, 97, 238, 0.25);
        }

        .btn-primary {
            background-color: #4361ee;
            border-color: #4361ee;
        }

        .btn-primary:hover {
            background-color: #3a0ca3;
            border-color: #3a0ca3;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-12">
                <div class="login-container">
                    <div class="text-center mb-4">
                        <a href="../index.html" class="text-decoration-none">
                            <i class="bi bi-rocket-takeoff fs-1 text-primary"></i>
                            <h1 class="h3 mb-3 fw-normal text-primary">authBoost</h1>
                        </a>
                        <p class="text-muted">Sign in to your account</p>
                    </div>

                    <!-- Alert for error messages -->
                    <div id="alertBox" class="alert alert-danger <?php echo isset($loginError) ? '' : 'd-none'; ?> mb-3" role="alert">
                        <?php echo isset($loginError) ? htmlspecialchars($loginError) : ''; ?>
                    </div>

                    <!-- Login Form -->
                    <form id="loginForm">
                        <!-- CSRF Token -->
                        <input type="hidden" name="csrf_token" id="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">

                        <!-- Optional redirect URL -->
                        <?php if (!empty($redirectTo)): ?>
                            <input type="hidden" name="redirect_to" value="<?php echo $redirectTo; ?>">
                        <?php endif; ?>

                        <div class="form-floating mb-3">
                            <input type="email" class="form-control" id="email" name="email" placeholder="name@example.com" required>
                            <label for="email">Email address</label>
                        </div>
                        <div class="form-floating mb-3">
                            <input type="password" class="form-control" id="password" name="password" placeholder="Password" required>
                            <label for="password">Password</label>
                        </div>
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="remember" name="remember">
                                <label class="form-check-label" for="remember">
                                    Remember me
                                </label>
                            </div>
                            <a href="forgot-password.php" class="text-decoration-none">Forgot password?</a>
                        </div>

                        <!-- Add reCAPTCHA -->
                        <div class="mb-3 d-flex justify-content-center">
                            <div class="g-recaptcha" data-sitekey="6LfesBQrAAAAAE9kidP0bOsEsLuwRyu_BTMZi1jZ"></div>
                        </div>

                        <button class="w-100 btn btn-lg btn-primary mb-3" type="submit" id="loginButton">Sign in</button>
                        <div class="text-center">
                            <p>Don't have an account? <a href="register.html" class="text-decoration-none">Register now</a></p>
                            <a href="../index.html" class="text-decoration-none d-inline-block mt-3">
                                <i class="bi bi-arrow-left me-2"></i>Back to Home
                            </a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // No need to fetch CSRF token since we're setting it directly in the form

            // Check for URL parameters
            const urlParams = new URLSearchParams(window.location.search);
            const alertBox = document.getElementById('alertBox');

            // Show error message from URL if exists
            if (urlParams.has('error')) {
                console.log('Error parameter found in URL:', urlParams.get('error'));
                showAlert(decodeURIComponent(urlParams.get('error')));
            }

            // Show success message from URL if exists
            if (urlParams.has('success')) {
                console.log('Success parameter found in URL:', urlParams.get('success'));
                showAlert(decodeURIComponent(urlParams.get('success')), true);
            }

            // Helper function to show alert messages
            function showAlert(message, isSuccess = false) {
                alertBox.textContent = message;
                alertBox.classList.remove('d-none', 'alert-success', 'alert-danger');
                alertBox.classList.add(isSuccess ? 'alert-success' : 'alert-danger');
            }

            // Handle form submission
            const loginForm = document.getElementById('loginForm');
            const loginButton = document.getElementById('loginButton');

            loginForm.addEventListener('submit', function(e) {
                e.preventDefault();
                console.log('Login form submitted');

                // Show loading state
                loginButton.disabled = true;
                loginButton.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Signing in...';

                // Hide any previous error
                alertBox.classList.add('d-none');

                // Get reCAPTCHA response
                const recaptchaResponse = grecaptcha.getResponse();
                console.log('reCAPTCHA response length:', recaptchaResponse.length);

                if (!recaptchaResponse) {
                    console.log('reCAPTCHA not completed');
                    showAlert('Please complete the reCAPTCHA verification.');
                    loginButton.disabled = false;
                    loginButton.innerHTML = 'Sign in';
                    return;
                }

                // Get form data
                const formData = new FormData(loginForm);
                formData.append('g-recaptcha-response', recaptchaResponse);

                console.log('Sending login request...');

                // Submit the form directly to allow server-side redirect
                loginForm.method = 'post';
                loginForm.action = 'login.php';
                loginForm.submit();
            });
        });
    </script>
</body>

</html>