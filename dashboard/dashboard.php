<?php
// Include necessary files
require_once __DIR__ . '/../config/env_loader.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../auth-handlers/utils/tokens.php';

// Set secure session parameters
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

// Check for active session
$authenticated = false;
$user = null;

// Function to redirect to login page
function redirectToLogin($message = null)
{
    $redirectUrl = '/auth/pages/login.php';
    if ($message) {
        $redirectUrl .= '?error=' . urlencode($message);
    }
    header("Location: $redirectUrl");
    exit;
}

try {
    // First check if user is logged in via session
    if (isset($_SESSION['is_logged_in']) && $_SESSION['is_logged_in'] === true && isset($_SESSION['user_id'])) {
        $authenticated = true;

        // Check if session is expired (optional additional security)
        $sessionTimeout = 3600; // 1 hour
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $sessionTimeout)) {
            // Session expired
            session_unset();
            session_destroy();
            redirectToLogin('Your session has expired. Please login again.');
        }

        // Update last activity time
        $_SESSION['last_activity'] = time();

        // Get user info from session
        $user = [
            'id' => $_SESSION['user_id'],
            'email' => $_SESSION['user_email'],
            'name' => $_SESSION['user_name'],
            'is_admin' => isset($_SESSION['is_admin']) ? $_SESSION['is_admin'] : false
        ];
    }
    // If not authenticated via session, check for remember-me token
    elseif (isset($_COOKIE['remember_token'])) {
        // Get database connection
        $db = getDatabaseConnection();

        // Validate the remember-me token
        $token = $_COOKIE['remember_token'];
        $tokensCollection = $db->auth_tokens;

        // Find the token in database
        $tokenDoc = $tokensCollection->findOne([
            'token' => $token,
            'expiry' => ['$gt' => new MongoDB\BSON\UTCDateTime(time() * 1000)]
        ]);

        if ($tokenDoc) {
            // Token is valid, get user info
            $usersCollection = $db->users;
            $user = $usersCollection->findOne(['_id' => $tokenDoc->user_id]);

            if ($user) {
                // Set up session data for the user
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

                // Update user data for display
                $user = [
                    'id' => $_SESSION['user_id'],
                    'email' => $_SESSION['user_email'],
                    'name' => $_SESSION['user_name'],
                    'is_admin' => isset($_SESSION['is_admin']) ? $_SESSION['is_admin'] : false
                ];

                $authenticated = true;
            }
        } else {
            // Invalid or expired token, clear the cookie
            setcookie('remember_token', '', [
                'expires' => time() - 3600,
                'path' => '/',
                'domain' => '',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Lax'
            ]);
        }
    }

    // If not authenticated after all checks, redirect to login
    if (!$authenticated) {
        redirectToLogin('Please login to access the dashboard');
    }
} catch (Exception $e) {
    error_log("Dashboard error: " . $e->getMessage());
    redirectToLogin('A system error occurred. Please try again.');
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - authBoost</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        .sidebar {
            min-height: 100vh;
            background-color: #f8f9fa;
            border-right: 1px solid #dee2e6;
        }

        .nav-link {
            color: #495057;
        }

        .nav-link:hover {
            background-color: #e9ecef;
        }

        .nav-link.active {
            color: #4361ee;
            background-color: #e9ecef;
        }

        .main-content {
            padding: 2rem;
        }

        .welcome-card {
            border-radius: 15px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            background-color: #4361ee;
            color: white;
        }
    </style>
</head>

<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 d-md-block sidebar collapse">
                <div class="position-sticky pt-3">
                    <div class="text-center mb-4">
                        <i class="bi bi-rocket-takeoff fs-1 text-primary"></i>
                        <h5 class="mt-2">authBoost</h5>
                    </div>
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link active" href="#">
                                <i class="bi bi-speedometer2 me-2"></i>
                                Dashboard
                            </a>
                        </li>

                        <?php if (isset($user['is_admin']) && $user['is_admin']): ?>

                        <?php endif; ?>
                        <li class="nav-item mt-5">
                            <a class="nav-link text-danger" href="logout.php">
                                <i class="bi bi-box-arrow-right me-2"></i>
                                Logout
                            </a>
                        </li>
                    </ul>
                </div>
            </div>

            <!-- Main Content -->
            <div class="col-md-9 col-lg-10 main-content">
                <!-- Top Navigation Bar -->
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">Dashboard</h1>
                    <div class="dropdown">
                        <button class="btn btn-outline-secondary dropdown-toggle" type="button" id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="bi bi-person-circle me-1"></i>
                            <?php echo htmlspecialchars($user['name']); ?>
                        </button>
                        <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                            <li><a class="dropdown-item" href="#">Profile</a></li>
                            <li><a class="dropdown-item" href="#">Settings</a></li>
                            <li>
                                <hr class="dropdown-divider">
                            </li>
                            <li><a class="dropdown-item" href="logout.php">Logout</a></li>
                        </ul>
                    </div>
                </div>

                <!-- Welcome Card -->
                <div class="card welcome-card mb-4">
                    <div class="card-body p-4">
                        <h2>Welcome back, <?php echo htmlspecialchars($user['name']); ?>!</h2>
                        <p class="mb-0">You're successfully authenticated. This is your secure dashboard.</p>
                    </div>
                </div>

                <!-- Dashboard Content -->
                <div class="row">
                    <div class="col-md-6 mb-4">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title">Account Information</h5>
                                <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
                                <p><strong>User ID:</strong> <?php echo htmlspecialchars($user['id']); ?></p>
                                <p><strong>Role:</strong> <?php echo $user['is_admin'] ? 'Administrator' : 'User'; ?></p>
                                <p><strong>Last Login:</strong> <?php echo date('Y-m-d H:i:s'); ?></p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6 mb-4">
                        <div class="card h-100">
                            <div class="card-body">
                                <h5 class="card-title">Security Tips</h5>
                                <ul>
                                    <li>Keep your password secure and unique</li>
                                    <li>Enable two-factor authentication for extra security</li>
                                    <li>Logout when using shared computers</li>
                                    <li>Check your account activity regularly</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>