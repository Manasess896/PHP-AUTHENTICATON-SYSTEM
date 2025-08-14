<?php
session_start();
require_once '../vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->safeLoad();

use MongoDB\Client;
use Dotenv\Dotenv;

try {
  $url = $_ENV['MONGODB_URI'] ?? getenv('MONGODB_URI');
  $mydatabase = $_ENV['MONGODB_DATABASE'] ?? getenv('MONGODB_DATABASE');
  $client = new Client($url);
  $collection = $client->selectCollection($mydatabase, 'users');
} catch (Exception $e) {
  die('Failed to connect to the database. Please contact the developer.');
}

// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER["REQUEST_METHOD"] === 'POST') {
  //verify recaptcha 
  $recaptchakey = $_ENV['RECAPTCHA_SECRET_KEY'] ?? getenv('RECAPTCHA_SECRET_KEY');
  $recaptchaResponse = $_POST['g-recaptcha-response'] ?? '';
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
  $verify = @file_get_contents($verifyUrl, false, $context);
  $captchaSuccess = $verify ? json_decode($verify) : null;

//check if recaptcha verification was successfull if yes continue with form  submission
  if ($captchaSuccess && !empty($captchaSuccess->success)) {
    // CSRF validation
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
      die('Invalid CSRF token.');
    }

//sanitize the email 
    $email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'] ?? '';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $error = "Invalid email address.";
    } else {
      // Lookup user
      $user = $collection->findOne([
        'email' => strtolower($email)
      ]);

      if (!$user) {
        $error = "User not found.";
      } else {
        // Account locked?
        if (!empty($user['is_locked'])) {
          $error = "Your account is locked due to multiple failed login attempts.";
        }

        // Not verified? Send to verification flow
        if (!isset($error) && empty($user['is_verified'])) {
          $_SESSION['pending_verification'] = true;
          $_SESSION['user_email'] = $email;
          $_SESSION['verification_attempts'] = 0;
          $_SESSION['registration_time'] = time();
          header('Location: request-another-email');
          exit;
        }

        // Password check
        if (!isset($error) && !password_verify($password, $user['password'])) {
          $error = "Invalid password.";
        }

        // Success branches (enforce 2FA if enabled)
        if (!isset($error)) {
          $isAdmin = !empty($user['is_admin']) && ($user['is_admin'] === true || $user['is_admin'] === 1 || $user['is_admin'] === '1');

          // Always regenerate session id at privilege boundary
          session_regenerate_id(true);

          // Clean any stale role-specific session variables to avoid confusion
          unset($_SESSION['is_admin'], $_SESSION['admin_id'], $_SESSION['admin_username'], $_SESSION['user_id'], $_SESSION['username'], $_SESSION['role']);

          $has2fa = !empty($user['twofa_secret']);
          if ($has2fa) {
            // Pending 2FA state (no full role session yet)
            $_SESSION['pending_2fa_user_id'] = (string)$user['_id'];
            if ($isAdmin) {
              $_SESSION['pending_2fa_is_admin'] = true;
            }
            header('Location: 2fa-verify');
            exit;
          }

          if ($isAdmin) {
            $_SESSION['role'] = 'admin';
            $_SESSION['is_admin'] = true; 
            $_SESSION['admin_id'] = (string)$user['_id'];
            $_SESSION['admin_username'] = $user['fullname'] ?? 'Admin';
            header('Location: admin-dashboard');
            exit;
          } else {
            $_SESSION['role'] = 'user';
            $_SESSION['user_id'] = (string)$user['_id'];
            $_SESSION['username'] = $user['fullname'] ?? 'User';
            header('Location: dashboard');
            exit;
          }
        }
      }
    }
  } else {
    $error = 'Failed reCAPTCHA verification. Please try again.';
  }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/@sweetalert2/theme-bootstrap-4/bootstrap-4.css" rel="stylesheet">
</head>

<body>
  <div class="container mt-5">
    <div class="row justify-content-center">
      <div class="col-md-6">
        <div class="card">
          <div class="card-header">
            <h4>Login</h4>
          </div>
          <div class="card-body">
            <form method="POST">

              <div class="mb-3">
                <label for="email" class="form-label">Email address</label>
                <input type="email" class="form-control" id="email" name="email" required>
              </div>
              <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
              </div>
              <div class="g-recaptcha" data-sitekey="<?= $_ENV['RECAPTCHA_SITE_KEY'] ?? getenv('RECAPTCHA_SITE_KEY') ?>"></div>
              <button type="submit" name="login" class="btn btn-primary">Login</button>
            </form>
          </div>
          <div class="card-footer text-center">
            <small>Don't have an account? <a href="register">Register here</a></small>
            <small><a href="forgot-password">Forgot password?</a></small>
          </div>
        </div>
      </div>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
  <script src="https://www.google.com/recaptcha/api.js" async defer></script>
  <script>
    <?php if (isset($error)): ?>
      Swal.fire({
        icon: 'error',
        title: 'Oops...',
        text: '<?= $error ?>'
      })

    <?php elseif (isset($success)): ?>
      Swal.fire({
        icon: 'success',
        title: 'Success',
        text: '<?= $success ?>'
      })

    <?php endif; ?>
  </script>
</body>

</html>