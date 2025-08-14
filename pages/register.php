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
  $collection = $client->$mydatabase->users; // "users" collection for accounts
  $attemptsCollection = $client->$mydatabase->attempts; // separate collection for login attempts
} catch (Exception $e) {
  die('Database connection error');
}

// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Handle POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

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
      // echo json_encode(["status" => "error", "message" => "Invalid CSRF token."]);
      $error = 'invalid csrf token';
      exit;
    }

    // Get and sanitize inputs
    $fullname = $_POST['fullname'] ?? '';
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    if ($password !== $confirm_password) {
      $error = 'Passwords do not match.';
      exit;
    }

    $email = filter_var($email, FILTER_SANITIZE_EMAIL);
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $error = 'Invalid email address.';
      exit;
    }

    // Name sanitization function
    function sanitizeName($name)
    {
      $name = trim($name);
      $name = strip_tags($name);
      $name = preg_replace('/\s+/', ' ', $name);
      $name = preg_replace("/[^\p{L}\s'-]/u", '', $name);
      return substr($name, 0, 100);
    }
    $full_name = sanitizeName($fullname);

    // Check rate limiting BEFORE inserting
    $ip = $_SERVER['REMOTE_ADDR'];
    $attempt = $attemptsCollection->findOne(['ip' => $ip]);
    if ($attempt && isset($attempt['count']) && $attempt['count'] > 5) {
      // echo json_encode(["status" => "error", "message" => "Too many attempts. Try later."]);
      $error = 'Too many attempts. Try later.';
      exit;
    }

    // Check if email exists
    $existingUser = $collection->findOne(['email' => strtolower($email)]);
    if ($existingUser) {
      // echo json_encode(["status" => "error", "message" => "Email already exists."]);
      $error = 'Email already exists.';

      header("Location: login");
      exit;
    }
    if (strlen($password) < 8 || strlen($password) > 64) {
      $error = "Password must be between 8 and 64 characters.";
      exit;
    }

    // insert user
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
    $token = bin2hex(random_bytes(32));
    $token_expiry = new MongoDB\BSON\UTCDateTime((time() + 1800) * 1000);

    try {
      $collection->insertOne([
        'fullname' => $full_name,
        'email' => strtolower($email),
        'password' => $hashed_password,
        'token' => $token,
        'created_at' => new MongoDB\BSON\UTCDateTime(),
        'is_verified' => false,
        'is_locked' => false, 
        'ip' => $ip,
        'token_expiry' => $token_expiry
      ]);

      // Send verification email
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
        $mail->addAddress($email, $full_name);
        $mail->isHTML(true);
        $mail->Subject = 'Registration Successful';
        $mail->Body = "Hi {$full_name},<br><br>
                 <p>  Thank you for registering. Please verify your email by clicking the link below:</p>  <br>
                <a href='" . ($_ENV['EMAIL_VERIFICATION_URL'] ?? getenv('EMAIL_VERIFICATION_URL')) . "?token={$token}'>Verify Email</a><br>
             <p>   The token will expire after 30 minutes.</p>
<br> if you did nor request this email please ignore.";

        $mail->send();

        // Set session data for email verification page access
        $_SESSION['pending_verification'] = true;
        $_SESSION['user_email'] = $email;
        $_SESSION['verification_attempts'] = 0;
        $_SESSION['registration_time'] = time();
        header('Location: request-another-email');

        $success = 'Registration successful! Please check your email to verify your account.';
        exit;
      } catch (Exception $e) {
        $error = 'regestration sucssessful but Failed to send verification email.';


        $_SESSION['pending_verification'] = true;
        $_SESSION['user_email'] = $email;
        $_SESSION['verification_attempts'] = 0;
        $_SESSION['registration_time'] = time();
        header('location: request-another-email');
        exit;
      }
    } catch (Exception $e) {
      $error = 'Registration failed. Please try again later.';
      exit;
    }
  } else {

    $error = 'verification failed,you failed recaptcha verification ,please try again';
    exit;
  }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Registration Form</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/@sweetalert2/theme-bootstrap-4/bootstrap-4.css" rel="stylesheet">
</head>

<body>
  <div class="container mt-5">
    <div class="row justify-content-center">
      <div class="col-md-6">
        <div class="card">
          <div class="card-header">
            <h3>Register</h3>
          </div>
          <div class="card-body">
            <form method="post">
              <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
              <div class="mb-3">
                <label for="fullname" class="form-label">Full Name</label>
                <input type="text" class="form-control" id="fullname" name="fullname" required>
              </div>
              <div class="mb-3">
                <label for="email" class="form-label">Email address</label>
                <input type="email" class="form-control" id="email" name="email" required>
              </div>
              <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
              </div>
              <div class="mb-3">
                <label for="confirm_password" class="form-label">Confirm Password</label>
                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
              </div>
              <div class="mb-3 form-check">
                <input type="checkbox" class="form-check-input" id="togglePassword">
                <label class="form-check-label" for="togglePassword">Show Password</label>
              </div>
              <div class="g-recaptcha" data-sitekey="<?= $_ENV['RECAPTCHA_SITE_KEY'] ?? getenv('RECAPTCHA_SITE_KEY') ?>"></div>

              <button type="submit" class="btn btn-primary w-100" id="registerBtn" name="registerBtn">Register</button>
            </form>
          </div>
        </div>
      </div>
    </div>
  </div>
  <script src="https://www.google.com/recaptcha/api.js" async defer></script>
  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>

  <script>
    document.getElementById('togglePassword').addEventListener('change', function() {
      const passwordInput = document.getElementById('password');
      const confirmPasswordInput = document.getElementById('confirm_password');
      const type = this.checked ? 'text' : 'password';
      passwordInput.type = type;
      confirmPasswordInput.type = type;
    });

    // Handle form submission with AJAX
    document.addEventListener('DOMContentLoaded', function() {

      // Disable the submit button during request
      submitButton.disabled = true;
      submitButton.innerHTML = 'Creating Account...';

    });
    <?php if (isset($error)): ?>
      Swal.fire({
          icon: 'error',
          title: 'Oops...',
          text: '<?= $error ?>'
        })
        .then(() => {
          window.location.href = 'register';
        });
    <?php elseif (isset($success)): ?>
      Swal.fire({
          icon: 'success',
          title: 'Success',
          text: '<?= $success ?>'
        })
        .then(() => {
          window.location.href = 'login?verified=1';
        });
    <?php endif; ?>
  </script>
</body>

</html>