<?php
session_start();
require_once '../vendor/autoload.php';

use MongoDB\Client;
use Dotenv\Dotenv;

// Load environment variables
$dotenv = Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->safeLoad();

try {
  $uri = $_ENV['MONGODB_URI'] ?? getenv('MONGODB_URI');
  $mydatabase = $_ENV['MONGODB_DATABASE'] ?? getenv('MONGODB_DATABASE');

  $client = new Client($uri);
  $collection = $client->$mydatabase->users;
  $attemptsCollection = $client->$mydatabase->attempts;
} catch (Exception $e) {
  die("Database connection error");
}

// Helper function for AJAX responses
function respondJson($success, $message)
{
  header('Content-Type: application/json');
  echo json_encode(['success' => $success, 'message' => $message]);
  exit;
}

$error = '';
$success = '';
$token = $_GET['token'] ?? $_POST['token'] ?? '';

// Rate limiting config
$ipAddress = $_SERVER['REMOTE_ADDR'];
$maxAttempts = 4;
$timeWindow = 900;

// Check rate limit
$currentTime = time();
$attemptRecord = $attemptsCollection->findOne(['ip' => $ipAddress, 'action' => 'password_reset']);

if ($attemptRecord) {
  if ($attemptRecord['count'] >= $maxAttempts && ($currentTime - $attemptRecord['last_attempt']) < $timeWindow) {
    $error = "Too many reset attempts. Please try again later.";
    $showForm = false;
  }
}

// Handle GET token validation
$showForm = true;
$validUser = null;

if (empty($token)) {
  $error = "Invalid or missing reset token. Please request a new password reset.";
  $showForm = false;
  // Only redirect if it's not an AJAX request
  if (empty($_SERVER['HTTP_X_REQUESTED_WITH'])) {
    header('location: forgot-password');
    exit;
  }
} else {
  $validUser = $collection->findOne(['reset_token' => $token]);
  if (!$validUser) {
    $error = "Invalid reset token. Please request a new password reset.";
    $showForm = false;
    // Only redirect if it's not an AJAX request
    if (empty($_SERVER['HTTP_X_REQUESTED_WITH'])) {
      header('location: forgot-password');
      exit;
    }
  } else {
    $current_time = new DateTime();
    $token_expiry = $validUser['reset_token_expiry']->toDateTime();

    if ($token_expiry < $current_time) {
      $error = "Reset token has expired. Please request a new password reset.";
      $showForm = false;
      // Only redirect if it's not an AJAX request
      if (empty($_SERVER['HTTP_X_REQUESTED_WITH'])) {
        header('location: forgot-password');
        exit;
      }
    }
  }
}

// Handle password reset submission
// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $showForm) {
  // Check if this is an AJAX request
  $isAjax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest';

  $recaptchakey = $_ENV['RECAPTCHA_SECRET_KEY'] ?? getenv('RECAPTCHA_SECRET_KEY');
  $recaptchaResponse = $_POST['g-recaptcha-response'];
  $verifyUrl = "https://www.google.com/recaptcha/api/siteverify";
  $data = [
    'secret' => $recaptchakey,
    'response' => $recaptchaResponse,
    'remoteip' => $_SERVER['REMOTE_ADDR']
  ];

  $options = [
    "http" => [
      "header"  => "Content-type: application/x-www-form-urlencoded\r\n",
      "method"  => "POST",
      "content" => http_build_query($data)
    ]
  ];
  $context  = stream_context_create($options);
  $verify = file_get_contents($verifyUrl, false, $context);
  $captchaSuccess = json_decode($verify);


  if ($captchaSuccess->success) {
    // CSRF validation
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
      if ($isAjax) {
        respondJson(false, 'Invalid CSRF token.');
      }
      $error = 'Invalid CSRF token.';
    } else {
      $password = $_POST['password'] ?? '';
      $confirm_password = $_POST['confirm_password'] ?? '';

      if (strlen($password) < 8) {
        if ($isAjax) {
          respondJson(false, 'Password must be at least 8 characters long.');
        }
        $error = "Password must be at least 8 characters long.";
      } elseif ($password !== $confirm_password) {
        if ($isAjax) {
          respondJson(false, 'Passwords do not match.');
        }
        $error = "Passwords do not match.";
      } else {
        // Double-check token is still valid before updating (prevent race conditions)
        $currentUser = $collection->findOne(['reset_token' => $token]);
        if (!$currentUser) {
          if ($isAjax) {
            respondJson(false, 'Reset token is no longer valid. It may have been used already.');
          }
          $error = "Reset token is no longer valid. It may have been used already.";
        } else {
          // Verify token hasn't expired (double-check for security)
          $current_time = new DateTime();
          $token_expiry = $currentUser['reset_token_expiry']->toDateTime();
          
          if ($token_expiry < $current_time) {
            if ($isAjax) {
              respondJson(false, 'Reset token has expired. Please request a new password reset.');
            }
            $error = "Reset token has expired. Please request a new password reset.";
          } else {
            try {
              $hashed_password = password_hash($password, PASSWORD_DEFAULT);
              
              // Use user ID instead of token for more secure update
              $updateResult = $collection->updateOne(
                [
                  '_id' => $currentUser['_id'],
                  'reset_token' => $token  // Double-verify token matches
                ],
                [
                  '$set' => ['password' => $hashed_password],
                  '$unset' => ['reset_token' => '', 'reset_token_expiry' => '', 'reset_created_at' => '', 'reset_ip' => '', 'last_reset_request_time' => '']
                ]
              );

              if ($updateResult->getModifiedCount() > 0) {
                if ($isAjax) {
                  respondJson(true, 'Password successfully reset. Redirecting to login...');
                }
                $success = "Password successfully reset. Redirecting to login...";
                header('location:login');
              } else {
                if ($isAjax) {
                  respondJson(false, 'Failed to update password. The token may have already been used.');
                }
                $error = "Failed to update password. The token may have already been used.";
              }
            } catch (Exception $e) {
              if ($isAjax) {
                respondJson(false, 'Database error occurred. Please try again later.');
              }
              $error = "Database error occurred. Please try again later.";
            }
          }
        }
      }
    }
  } else {
    if ($isAjax) {
      respondJson(false, 'Failed reCAPTCHA verification. Please try again.');
    }
    $error = 'Failed reCAPTCHA verification. Please try again.';
  }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Password</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/@sweetalert2/theme-bootstrap-4/bootstrap-4.css" rel="stylesheet">
</head>

<body>
  <div class="container mt-5">
    <div class="row justify-content-center">
      <div class="col-md-6">
        <div class="card">
          <div class="card-header">
            <h4>Reset Password</h4>
          </div>
          <div class="card-body">
            <?php if ($showForm): ?>
            <form method="POST" id="passwordResetForm">
              <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
              <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">
              <div class="mb-3">
                <label for="password" class="form-label">New Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
              </div>
              <div class="mb-3">
                <label for="confirm_password" class="form-label">Confirm Password</label>
                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
              </div>
              <div class="mb-3 form-check">
                <input type="checkbox" class="form-check-input" id="showPassword">
                <label class="form-check-label" for="showPassword">Show Password</label>
              </div>
              <div class="g-recaptcha" data-sitekey="<?= $_ENV['RECAPTCHA_SITE_KEY'] ?? getenv('RECAPTCHA_SITE_KEY') ?>"></div>
              <button type="submit" class="btn btn-primary">Reset Password</button>
            </form>
            <?php else: ?>
            <div class="alert alert-danger">
              <h5>Access Denied</h5>
              <p><?= htmlspecialchars($error) ?></p>
              <a href="../reset.php" class="btn btn-primary">Request New Reset Link</a>
            </div>
            <?php endif; ?>
          </div>
        </div>
      </div>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script src="https://www.google.com/recaptcha/api.js" async defer></script>
  <script>
    <?php if ($showForm): ?>
    const password = document.getElementById('password');
    const confirm_password = document.getElementById('confirm_password');
    const showPassword = document.getElementById('showPassword');

    showPassword.addEventListener('click', function() {
      const type = password.type === 'password' ? 'text' : 'password';
      password.type = type;
      confirm_password.type = type;
    });

    // AJAX form submission
    document.getElementById('passwordResetForm').addEventListener('submit', function(e) {
      e.preventDefault();

      const formData = new FormData(this);
      const submitButton = this.querySelector('button[type="submit"]');
      const originalButtonText = submitButton.textContent;

      // Disable submit button and show loading state
      submitButton.disabled = true;
      submitButton.textContent = 'Resetting...';

      fetch(window.location.pathname + window.location.search, {
          method: 'POST',
          headers: {
            'X-Requested-With': 'XMLHttpRequest'
          },
          body: formData
        })
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            Swal.fire({
              icon: 'success',
              title: 'Password Reset Successful',
              text: data.message
            }).then(() => {
              // Redirect to login page after successful reset
              window.location.href = 'login';
            });
          } else {
            Swal.fire({
              icon: 'error',
              title: 'Password Reset Failed',
              text: data.message
            });
          }
        })
        .catch(error => {
          console.error('Error:', error);
          Swal.fire({
            icon: 'error',
            title: 'Network Error',
            text: 'Please check your connection and try again.'
          });
        })
        .finally(() => {
          // Re-enable submit button
          submitButton.disabled = false;
          submitButton.textContent = originalButtonText;
          // Reset reCAPTCHA
          if (typeof grecaptcha !== 'undefined') {
            grecaptcha.reset();
          }
        });
    });
    <?php endif; ?>
    
    <?php if (isset($error) && $_SERVER['REQUEST_METHOD'] === 'POST'): ?>
      Swal.fire({
        icon: 'error',
        title: 'Password Reset Failed',
        text: '<?= $error ?>'
      });

    <?php elseif (isset($success) && $_SERVER['REQUEST_METHOD'] === 'POST'): ?>
      Swal.fire({
        icon: 'success',
        title: 'Password Reset Successful',
        text: '<?= $success ?>'
      });

    <?php endif; ?>
  </script>
</body>

</html>