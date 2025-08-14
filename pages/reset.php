<?php
session_start();
require_once '../vendor/autoload.php';

use MongoDB\Client;
use Dotenv\Dotenv;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Load environment variables
$dotenv = Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->safeLoad();

// Connect to MongoDB
try {
  $uri = $_ENV['MONGODB_URI'] ?? getenv('MONGODB_URI');
  $mydatabase = $_ENV['MONGODB_DATABASE'] ?? getenv('MONGODB_DATABASE');
  $client = new Client($uri);
  $collection = $client->$mydatabase->users;
  $attemptsCollection = $client->$mydatabase->attempts;
} catch (Exception $e) {
  $error = 'Database connection error. Please contact the developer!';
  // Do not exit; allow UI to render
}
// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Helper function for JSON responses
function respondJson($status, $message)
{
  header('Content-Type: application/json');
  echo json_encode(['status' => $status, 'message' => $message]);
  exit;
}

// AJAX handler for password reset
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
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
      respondJson('error', 'Invalid CSRF token.');
    }
    $email = trim($_POST['email'] ?? '');

    $email = filter_var($email, FILTER_SANITIZE_EMAIL);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      respondJson('error', 'Invalid email address format.');
    }
    $ip = $_SERVER['REMOTE_ADDR'];
    $now = time();
    $window = 60;
    $maxAttempts = 5;

    $attemptsCollection->deleteMany([
      '$or' => [
        ['email' => strtolower($email)]
      ],
      'time' => ['$lt' => new MongoDB\BSON\UTCDateTime(($now - $window) * 1000)]
    ]);

    // Count recent attempts
    $attemptCount = $attemptsCollection->countDocuments([
      '$or' => [
        ['email' => strtolower($email)]
      ]
    ]);

    if ($attemptCount >= $maxAttempts) {
      respondJson('error', 'Too many password reset attempts detected. Please wait a moment before trying again.');
    }

    // Record this attempt
    $attemptsCollection->insertOne([
      'ip' => $ip,
      'email' => strtolower($email),
      'time' => new MongoDB\BSON\UTCDateTime($now * 1000)
    ]);

    // Check if email exists
    $existingUser = $collection->findOne(['email' => strtolower($email)]);
    if ($existingUser) {

      // Check password reset count and time limitations (4 requests per 24 hours)
      $currentTime = new MongoDB\BSON\UTCDateTime();
      $twentyFourHoursAgo = new MongoDB\BSON\UTCDateTime((time() - 86400) * 1000); // 24 hours = 86400 seconds

      $currentResetCount = $existingUser['password_reset_count'] ?? 0;
      $lastResetTime = $existingUser['reset_created_at'] ?? null;

      // Reset count if 24 hours have passed since last reset request
      if ($lastResetTime && $lastResetTime < $twentyFourHoursAgo) {
        $currentResetCount = 0;
      }

      // Check if user has exceeded 4 requests in 24 hours
      if ($currentResetCount >= 4) {
        $remainingRequests = 4 - $currentResetCount;
        respondJson('error', 'For security reasons, you can only request password reset 4 times in 24 hours. You\'ve used all your attempts. Please try again after 24 hours from your first request.');
      }

      $token = bin2hex(random_bytes(32));
      $token_expiry = new MongoDB\BSON\UTCDateTime((time() + 1800) * 1000);
      $username = $existingUser['fullname'];

      try {
        $collection->updateOne(
          ['email' => strtolower($email)],
          ['$set' => [
            'reset_token' => $token,
            'reset_created_at' => new MongoDB\BSON\UTCDateTime(),
            'reset_count' => 0,
            'reset_ip' => $_SERVER['REMOTE_ADDR'],
            'reset_token_expiry' => $token_expiry,
            'password_reset_count' => $currentResetCount + 1
          ]]
        );
      } catch (Exception $e) {
        respondJson('error', 'We encountered a technical issue while processing your request. Please try again in a few moments.');
      }

      $mail = new PHPMailer(true);
      try {
        $mail->isSMTP();
        $mail->Host = $_ENV['MAIL_HOST'] ?? getenv('MAIL_HOST');
        $mail->SMTPAuth = true;
        $mail->Username = $_ENV['MAIL_USERNAME'] ?? getenv('MAIL_USERNAME');
        $mail->Password = $_ENV['MAIL_PASSWORD'] ?? getenv('MAIL_PASSWORD');
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = $_ENV['MAIL_PORT'] ?? getenv('MAIL_PORT');

        $mail->setFrom($_ENV['MAIL_FROM_ADDRESS'], $_ENV['MAIL_FROM_ADDRESS']);
        $mail->addAddress($email);
        $mail->isHTML(true);
        $mail->Subject = 'Reset you password';
        $mail->Body = "<p>Hi {$username},</p>
                     <p>You requested password reset click the link below to reset your password</p>
                     <p><a href='" . ($_ENV['PASSWORD_RESET_URL'] ?? getenv('PASSWORD_RESET_URL')) . "?token={$token}'>Reset Password</a></p>
                     <p>The link will expire after 30 minutes.</p>
                     <br>
                     <p>If you did not request this email, please ignore it.</p>";

        $mail->send();
        $remainingRequests = 4 - ($currentResetCount + 1);
        respondJson('success', 'A password reset link has been sent to your email address. Please check your inbox (and spam folder). The link will expire in 30 minutes. You have ' . $remainingRequests . ' more password reset requests available today.');
      } catch (Exception $e) {
        respondJson('error', 'We encountered an issue sending the reset email. This might be a temporary problem with our email service.');
      }
    } else {
      respondJson('error', 'We couldn\'t find an account with that email address. Please check your email and try again.');
    }
  } else {
    respondJson('error', 'You failed reCAPTCHA verification, please try again.');
  }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Password</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/@sweetalert2/theme-bootstrap-4/bootstrap-4.css" rel="stylesheet">
</head>

<body>

  <div class="container">
    <div class="row justify-content-center">
      <div class="col-md-6 col-lg-5">
        <div class="card my-5">
          <div class="card-body">
            <h3 class="card-title text-center">Reset Your Password</h3>
            <p class="text-center text-muted">An e-mail will be sent to you with instructions on how to reset your password.</p>

            <?php
            if (isset($_GET['reset']) && $_GET['reset'] == 'success') {
              echo '<div class="alert alert-success" role="alert">Check your e-mail!</div>';
            }
            ?>

            <form id="resetForm" method="post" autocomplete="off">
              <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
              <div class="mb-3">
                <label for="email" class="form-label">Email address</label>
                <input type="email" class="form-control" id="email" name="email" placeholder="Enter your email address" required>
              </div>
              <div class="g-recaptcha" data-sitekey="<?= $_ENV['RECAPTCHA_SITE_KEY'] ?? getenv('RECAPTCHA_SITE_KEY') ?>"></div>
              <div class="d-grid">
                <button type="submit" name="reset-request-submit" class="btn btn-primary">Receive new password by email</button>
              </div>
            </form>
            <div>

              <?php
              $remainingSafe = isset($remainingRequests) ? htmlspecialchars((string)$remainingRequests, ENT_QUOTES, 'UTF-8') : '';
              $attr = isset($remainingRequests) ? 'class="text-muted"' : '';
              echo '<p ' . $attr . '>' . $remainingSafe . '</p>';
              ?>
            </div>

          </div>
        </div>
      </div>
    </div>
  </div>


  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script src="https://www.google.com/recaptcha/api.js" async defer></script>
  <script>
    document.getElementById('resetForm').addEventListener('submit', async function(e) {
      e.preventDefault();
      var form = e.target;
      var formData = new FormData(form);
      // Add reCAPTCHA response
      formData.append('g-recaptcha-response', grecaptcha.getResponse());
      try {
        const response = await fetch(window.location.href, {
          method: 'POST',
          headers: {
            'X-Requested-With': 'XMLHttpRequest'
          },
          body: formData
        });
        const data = await response.json();
        if (data.status === 'success') {
          Swal.fire({
            icon: 'success',
            title: 'Success',
            text: data.message
          });
          form.reset();
          grecaptcha.reset();
        } else {
          Swal.fire({
            icon: 'error',
            title: 'Oops...',
            text: data.message
          });
          grecaptcha.reset();
        }
      } catch (err) {
        Swal.fire({
          icon: 'error',
          title: 'Error',
          text: err.message || 'An unexpected error occurred.'
        });
      }
    });
  </script>
</body>

</html>