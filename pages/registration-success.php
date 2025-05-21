<?php
session_start();

// Load env_loader.php before any functions that use environment variables
require_once __DIR__ . '/../config/env_loader.php';

// Get email from session or URL parameter
$email = isset($_SESSION['registration_email']) ? $_SESSION['registration_email'] : (isset($_GET['email']) ? $_GET['email'] : '');

// Get messages from URL parameters
$successMessage = isset($_GET['success']) ? $_GET['success'] : "Your account has been created successfully!";
$errorMessage = isset($_GET['error']) ? $_GET['error'] : "";
$warningMessage = isset($_GET['warning']) ? $_GET['warning'] : "";

// After displaying, clear the session variables
if (isset($_SESSION['registration_email'])) {
    unset($_SESSION['registration_email']);
}
if (isset($_SESSION['registration_success'])) {
    unset($_SESSION['registration_success']);
}

// Create directory structure for logs if not exists
$logDir = __DIR__ . '/../logs';
if (!file_exists($logDir)) {
    @mkdir($logDir, 0755, true);
}

$mailLogDir = __DIR__ . '/../logs/mail';
if (!file_exists($mailLogDir)) {
    @mkdir($mailLogDir, 0755, true);
}

// Check if we have email logs for this address
$hasEmailLogs = false;
$emailStatus = null;
$emailLoggerFile = __DIR__ . '/../auth-handlers/utils/email_logger.php';

if (!empty($email)) {
    try {
        if (file_exists($emailLoggerFile)) {
            require_once $emailLoggerFile;
            // Ensure the function exists after loading the file
            if (function_exists('analyzeEmailIssues')) {
                $hasEmailLogs = true;
                $emailStatus = analyzeEmailIssues($email);
            }
        } else {
            // Use the lightweight alternative
            require_once __DIR__ . '/../auth-handlers/utils/email_status.php';
            if (function_exists('checkEmailStatus')) {
                $hasEmailLogs = true;
                $basicStatus = checkEmailStatus($email);

                // Create a compatible structure
                $emailStatus = [
                    'found' => $basicStatus['logs_exist'] || $basicStatus['mail_files_exist'],
                    'attempts' => $basicStatus['mail_files_exist'] ? count($basicStatus['mail_files']) : 0,
                    'successes' => $basicStatus['mail_driver'] === 'log' ? ($basicStatus['mail_files_exist'] ? 1 : 0) : 0,
                    'failures' => 0,
                    'issues' => [],
                    'recommendations' => []
                ];

                // Add recommendations based on environment
                if ($basicStatus['app_environment'] === 'development' && $basicStatus['mail_driver'] === 'log') {
                    $emailStatus['recommendations'][] = 'In development mode, emails are logged but not sent. Check the logs/mail directory.';
                }
            }
        }
    } catch (Exception $e) {
        // Log the error but continue with the page
        error_log("Email logger error: " . $e->getMessage());
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Success</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <!-- Animation CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
    <style>
        .fade-in {
            animation: fadeIn 0.8s ease-in-out;
        }

        @keyframes fadeIn {
            0% {
                opacity: 0;
                transform: translateY(20px);
            }

            100% {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
        }

        .btn-primary {
            background: linear-gradient(to right, #4e73df, #224abe);
            border: none;
            transition: all 0.3s ease;
        }

        .btn-primary:hover {
            background: linear-gradient(to right, #224abe, #1a3a8e);
            transform: translateY(-2px);
        }

        .email-status {
            padding: 10px;
            border-radius: 8px;
            margin-top: 15px;
            font-size: 14px;
        }

        .email-status-success {
            background-color: rgba(25, 135, 84, 0.1);
            border-left: 4px solid #198754;
        }

        .email-status-warning {
            background-color: rgba(255, 193, 7, 0.1);
            border-left: 4px solid #ffc107;
        }

        .email-status-danger {
            background-color: rgba(220, 53, 69, 0.1);
            border-left: 4px solid #dc3545;
        }
    </style>
</head>

<body class="bg-light">
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-8 col-lg-6">
                <div class="card shadow-sm animate__animated animate__fadeIn">
                    <div class="card-body p-5">
                        <div class="text-center mb-4 fade-in">
                            <?php if (empty($errorMessage) && empty($warningMessage)): ?>
                                <div class="d-flex justify-content-center">
                                    <div class="rounded-circle bg-success bg-opacity-10 p-3 mb-3">
                                        <i class="bi bi-check-circle-fill text-success" style="font-size: 2rem;"></i>
                                    </div>
                                </div>
                                <h2 class="fw-bold text-success">Registration Successful!</h2>
                            <?php elseif (!empty($warningMessage)): ?>
                                <div class="d-flex justify-content-center">
                                    <div class="rounded-circle bg-warning bg-opacity-10 p-3 mb-3">
                                        <i class="bi bi-exclamation-circle-fill text-warning" style="font-size: 2rem;"></i>
                                    </div>
                                </div>
                                <h2 class="fw-bold text-warning">Almost There!</h2>
                            <?php else: ?>
                                <div class="d-flex justify-content-center">
                                    <div class="rounded-circle bg-danger bg-opacity-10 p-3 mb-3">
                                        <i class="bi bi-exclamation-triangle-fill text-danger" style="font-size: 2rem;"></i>
                                    </div>
                                </div>
                                <h2 class="fw-bold text-danger">Attention Required</h2>
                            <?php endif; ?>
                        </div>

                        <?php if (!empty($errorMessage)): ?>
                            <div class="alert alert-danger fade-in" style="animation-delay: 0.1s;">
                                <?php echo $errorMessage; ?>
                            </div>
                        <?php endif; ?>

                        <?php if (!empty($warningMessage)): ?>
                            <div class="alert alert-warning fade-in" style="animation-delay: 0.1s;">
                                <?php echo $warningMessage; ?>
                            </div>
                        <?php endif; ?>

                        <div class="text-center mb-4 fade-in" style="animation-delay: 0.2s;">
                            <p class="fs-5"><?php echo $successMessage; ?></p>

                            <div class="card bg-light my-4 fade-in" style="animation-delay: 0.3s;">
                                <div class="card-body">
                                    <h5><i class="bi bi-envelope-check me-2"></i>Verify Your Email</h5>
                                    <p>We've sent a verification link to:<br>
                                        <strong><?php echo htmlspecialchars($email); ?></strong>
                                    </p>
                                    <p class="mb-0">Please check your inbox and spam folder.</p>

                                    <?php if ($hasEmailLogs && $emailStatus): ?>
                                        <?php if ($emailStatus['attempts'] > 0): ?>
                                            <?php if ($emailStatus['successes'] > 0): ?>
                                                <div class="email-status email-status-success mt-3">
                                                    <i class="bi bi-check-circle me-1"></i>
                                                    Email appears to have been sent successfully. Please check your inbox and spam folder.
                                                </div>
                                            <?php elseif ($emailStatus['failures'] > 0): ?>
                                                <div class="email-status email-status-danger mt-3">
                                                    <i class="bi bi-x-circle me-1"></i>
                                                    There was an issue sending your verification email. Please use the resend button below.
                                                </div>
                                            <?php else: ?>
                                                <div class="email-status email-status-warning mt-3">
                                                    <i class="bi bi-question-circle me-1"></i>
                                                    Email delivery status is uncertain. If you don't receive it soon, please try resending.
                                                </div>
                                            <?php endif; ?>
                                        <?php endif; ?>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>

                        <div class="fade-in" style="animation-delay: 0.4s;">
                            <p class="text-center mb-4">Didn't receive the email?</p>
                            <div class="d-grid gap-2">
                                <a href="resend_verification.php?email=<?php echo urlencode($email); ?>" class="btn btn-primary">
                                    <i class="bi bi-envelope me-2"></i>Resend Verification Email
                                </a>
                                <button class="btn btn-outline-secondary" type="button" data-bs-toggle="collapse" data-bs-target="#troubleshootingGuide">
                                    <i class="bi bi-tools me-2"></i>Troubleshooting Help
                                </button>
                            </div>

                            <div class="collapse mt-3" id="troubleshootingGuide">
                                <div class="card card-body bg-light">
                                    <h5>Troubleshooting Tips:</h5>
                                    <ul>
                                        <li>Check your spam or junk folder</li>
                                        <li>Add noreply@authboost.com to your contacts</li>
                                        <li>Check if you entered the correct email address</li>
                                        <li>Wait a few minutes as email delivery may be delayed</li>
                                        <li>Use the "Resend Verification Email" button above</li>
                                        <?php if ($emailStatus && !empty($emailStatus['recommendations'])): ?>
                                            <?php foreach ($emailStatus['recommendations'] as $rec): ?>
                                                <li><?php echo htmlspecialchars($rec); ?></li>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </ul>
                                </div>
                            </div>
                        </div>

                        <div class="text-center mt-4 fade-in" style="animation-delay: 0.5s;">
                            <p>Ready to sign in? <a href="login.php" class="text-decoration-none fw-bold">Login</a></p>
                        </div>
                    </div>
                </div>
                <div class="text-center mt-3 fade-in" style="animation-delay: 0.6s;">
                    <a href="../index.html" class="text-decoration-none">
                        <i class="bi bi-arrow-left"></i> Back to Home
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>