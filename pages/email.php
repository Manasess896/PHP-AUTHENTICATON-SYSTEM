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

// Check if user is coming from registration (session-driven access)
if (!isset($_SESSION['pending_verification']) || !isset($_SESSION['user_email'])) {
  header('Location: register');
  exit();
}

// Connect to MongoDB
try {
  $uri = $_ENV['MONGODB_URI'] ?? getenv('MONGODB_URI');
  $mydatabase = $_ENV['MONGODB_DATABASE'] ?? getenv('MONGODB_DATABASE');
  $client = new Client($uri);
  $collection = $client->$mydatabase->users;
  $attemptsCollection = $client->$mydatabase->attempts;
} catch (Exception $e) {
  die('Database connection error');
}
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$user = $collection->findOne(['email' => strtolower($_SESSION['user_email'])]);
if ($user && $user['is_verified']) {
  session_destroy();
  header('Location: login?verified=true');
  exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    echo json_encode([
      "status" => "error",
      "title" => "Security Error",
      "message" => "Invalid security token. Please refresh the page and try again.",
      "icon" => "error"
    ]);
    exit;
  }

  if (isset($_POST['resend_verification'])) {
    $email = $_SESSION['user_email'];
    $verificationAttempts = $_SESSION['verification_attempts'] ?? 0;

    if ($verificationAttempts >= 3) {
      echo json_encode([
        "status" => "error",
        "title" => "Maximum Attempts Reached",
        "message" => "You have reached the maximum number of email verification requests (3) for this session. Please register again if needed.",
        "icon" => "warning",
        "showConfirmButton" => true,
        "confirmButtonText" => "Register Again",
        "footer" => "This limit helps prevent spam and abuse.",
        "redirect" => "register"
      ]);
      exit;
    }

    $existingUser = $collection->findOne(['email' => strtolower($email)]);
    if (!$existingUser) {
      echo json_encode([
        "status" => "error",
        "title" => "User Not Found",
        "message" => "User account not found. Please register again.",
        "icon" => "error",
        "redirect" => "register"
      ]);
      exit;
    }

    if ($existingUser['is_verified']) {
      session_destroy();
      echo json_encode([
        "status" => "success",
        "title" => "Already Verified",
        "message" => "Your email is already verified. Redirecting to login...",
        "icon" => "success",
        "redirect" => "login?verified=true"
      ]);
      exit;
    }

    $token = bin2hex(random_bytes(32));
    $token_expiry = new MongoDB\BSON\UTCDateTime((time() + 1800) * 1000); // 30 minutes

    try {
      $collection->updateOne(
        ['email' => strtolower($email)],
        ['$set' => [
          'token' => $token,
          'token_expiry' => $token_expiry,

          'last_verification_request' => new MongoDB\BSON\UTCDateTime()
        ]]
      );

      $mail = new PHPMailer(true);
      try {
        $mail->isSMTP();
        $mail->Host = $_ENV['MAIL_HOST'] ?? getenv('MAIL_HOST');
        $mail->SMTPAuth = true;
        $mail->Username = $_ENV['MAIL_USERNAME'] ?? getenv('MAIL_USERNAME');
        $mail->Password = $_ENV['MAIL_PASSWORD'] ?? getenv('MAIL_PASSWORD');
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = $_ENV['MAIL_PORT'] ?? getenv('MAIL_PORT');

        $mail->setFrom($_ENV['MAIL_FROM_ADDRESS'] ?? getenv('MAIL_FROM_ADDRESS'), $_ENV['MAIL_FROM_NAME'] ?? getenv('MAIL_FROM_NAME') ?? 'Authentication System');
        $mail->addAddress($email, $existingUser['fullname']);
        $mail->isHTML(true);
        $mail->Subject = 'Email Verification Required';
        $mail->Body = "
          <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
            <h2 style='color: #333;'>Hi {$existingUser['fullname']},</h2>
            <p>Thank you for registering with us. To complete your registration, please verify your email address by clicking the button below:</p>
            
            <div style='text-align: center; margin: 30px 0;'>
              <a href='" . ($_ENV['EMAIL_VERIFICATION_URL'] ?? getenv('EMAIL_VERIFICATION_URL')) . "?token={$token}' 
                 style='background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;'>
                Verify My Email
              </a>
            </div>
            
            <p><strong>Important:</strong> This verification link will expire in 30 minutes.</p>
            <p>If you didn't request this verification, please ignore this email.</p>
            
            <hr style='margin: 30px 0; border: 1px solid #eee;'>
            <p style='color: #666; font-size: 12px;'>If the button doesn't work, copy and paste this link into your browser:<br>
            " . ($_ENV['EMAIL_VERIFICATION_URL'] ?? getenv('EMAIL_VERIFICATION_URL')) . "?token={$token}</p>
          </div>";

        $mail->send();

        // Increment attempt counter
        $_SESSION['verification_attempts'] = $verificationAttempts + 1;
        $remainingAttempts = 3 - $_SESSION['verification_attempts'];

        echo json_encode([
          "status" => "success",
          "title" => "Verification Email Sent!",
          "message" => "A new verification email has been sent to your email address. Please check your inbox (and spam folder).",
          "icon" => "success",
          "showConfirmButton" => true,
          "confirmButtonText" => "Got it!",
          "footer" => $remainingAttempts > 0 ? "You have {$remainingAttempts} more verification requests available." : "This was your last verification request for this session.",
          "timer" => 6000,
          "timerProgressBar" => true
        ]);
        exit;
      } catch (Exception $e) {
        echo json_encode([
          "status" => "error",
          "title" => "Email Delivery Failed",
          "message" => "We couldn't send the verification email. This might be a temporary issue with our email service.",
          "icon" => "error",
          "showConfirmButton" => true,
          "confirmButtonText" => "Try Again",
          "footer" => "If this problem persists, please contact support."
        ]);
        exit;
      }
    } catch (Exception $e) {
      echo json_encode([
        "status" => "error",
        "title" => "Database Error",
        "message" => "We encountered a technical issue. Please try again in a few moments.",
        "icon" => "error",
        "showConfirmButton" => true,
        "confirmButtonText" => "Try Again"
      ]);
      exit;
    }
  }
}

// Get current attempt count for display
$currentAttempts = $_SESSION['verification_attempts'] ?? 0;
$remainingAttempts = 3 - $currentAttempts;
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Verification</title>
  <!-- Bootstrap CSS -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/@sweetalert2/theme-bootstrap-4/bootstrap-4.css" rel="stylesheet">
  <!-- Bootstrap Icons -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
  <style>
    .verification-card {
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      border: none;
      border-radius: 10px;
    }

    .email-icon {
      font-size: 4rem;
      color: #6c757d;
    }

    .attempts-badge {
      font-size: 0.85rem;
    }
  </style>
</head>

<body class="bg-light">
  <div class="container">
    <div class="row justify-content-center min-vh-100 align-items-center">
      <div class="col-md-6 col-lg-5">
        <div class="card verification-card">
          <div class="card-body p-5 text-center">
            <i class="bi bi-envelope-check email-icon mb-4"></i>
            <h3 class="card-title mb-3">Verify Your Email</h3>
            <p class="text-muted mb-4">
              We've sent a verification email to:<br>
              <strong><?php echo htmlspecialchars($_SESSION['user_email']); ?></strong>
            </p>

            <div class="alert alert-info mb-4">
              <i class="bi bi-info-circle me-2"></i>
              Please check your inbox and spam folder, then click the verification link.
            </div>

            <?php if ($remainingAttempts > 0): ?>
              <p class="small text-muted mb-3">
                Didn't receive the email? You can request a new one.
              </p>

              <form method="post" id="resendForm">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="resend_verification" value="1">
                <button type="submit" class="btn btn-primary mb-3" id="resendBtn">
                  <i class="bi bi-arrow-clockwise me-2"></i>Resend Verification Email
                </button>
              </form>

              <div class="d-flex justify-content-center">
                <span class="badge bg-secondary attempts-badge">
                  <?php echo htmlspecialchars((string)$remainingAttempts, ENT_QUOTES, 'UTF-8'); ?> verification request<?php echo $remainingAttempts != 1 ? 's' : ''; ?> remaining
                </span>
              </div>
            <?php else: ?>
              <div class="alert alert-warning">
                <i class="bi bi-exclamation-triangle me-2"></i>
                You have used all your verification requests for this session.
              </div>
              <a href="register" class="btn btn-secondary">
                <i class="bi bi-arrow-left me-2"></i>Register Again
              </a>
            <?php endif; ?>

            <hr class="my-4">
            <div class="d-flex justify-content-between">
              <a href="register" class="btn btn-outline-secondary">
                <i class="bi bi-arrow-left me-2"></i>Back to Register
              </a>
              <a href="login" class="btn btn-outline-primary">
                <i class="bi bi-box-arrow-in-right me-2"></i>Already Verified? Login
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>

  <script>
    document.addEventListener('DOMContentLoaded', function() {
      const form = document.getElementById('resendForm');
      const submitButton = document.getElementById('resendBtn');

      if (form && submitButton) {
        const initialButtonText = submitButton.innerHTML;

        form.addEventListener('submit', function(e) {
          e.preventDefault();

          submitButton.disabled = true;
          submitButton.innerHTML = '<i class="bi bi-hourglass-split me-2"></i>Sending...';

          const formData = new FormData(form);

          fetch('email.php', {
              method: 'POST',
              body: formData
            })
            .then(response => {
              if (!response.ok) {
                throw new Error('Network response was not ok');
              }
              return response.json();
            })
            .then(data => {

              submitButton.disabled = false;
              submitButton.innerHTML = initialButtonText;

              if (data.status === 'success') {
                Swal.fire({
                  icon: data.icon || 'success',
                  title: data.title || 'Success',
                  html: data.message,
                  confirmButtonText: data.confirmButtonText || 'OK',
                  footer: data.footer || null,
                  timer: data.timer || null,
                  timerProgressBar: data.timerProgressBar || false,
                  showConfirmButton: data.showConfirmButton !== false,
                  allowOutsideClick: false,
                  allowEscapeKey: false
                }).then(() => {
                  if (data.redirect) {
                    window.location.href = data.redirect;
                  } else {
                    window.location.reload();
                  }
                });

              } else if (data.status === 'error') {
                Swal.fire({
                  icon: data.icon || 'error',
                  title: data.title || 'Error',
                  html: data.message,
                  confirmButtonText: data.confirmButtonText || 'OK',
                  footer: data.footer || null,
                  timer: data.timer || null,
                  timerProgressBar: data.timerProgressBar || false,
                  showConfirmButton: data.showConfirmButton !== false,
                  allowOutsideClick: false,
                  allowEscapeKey: false
                }).then(() => {
                  if (data.redirect) {
                    window.location.href = data.redirect;
                  }
                });
              }
            })
            .catch(error => {

              submitButton.disabled = false;
              submitButton.innerHTML = initialButtonText;

              console.error('Error:', error);
              Swal.fire({
                icon: 'error',
                title: 'Connection Error',
                html: 'Unable to connect to the server. Please check your internet connection and try again.',
                confirmButtonText: 'Try Again',
                footer: 'If this problem persists, please refresh the page.',
                allowOutsideClick: false,
                allowEscapeKey: false
              });
            });
        });
      }
    });
  </script>
</body>

</html>