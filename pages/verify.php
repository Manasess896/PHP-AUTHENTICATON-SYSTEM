<?php
require_once '../vendor/autoload.php';
use MongoDB\Client;
use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->safeLoad();

try {
$client = new Client($_ENV['MONGODB_URI']);
$collection = $client->{$_ENV['MONGODB_DATABASE']}->users;
} catch(Exception $e) {
die("Database connection error");
}

$token = $_GET['token'] ?? '';

if (empty($token)) {
  $error = "you are not authorized to view this page";
  header('location:login');
} else {
$user = $collection->findOne(['token' => $token]);

if (!$user) {
$error = "Token not found.";
} else {
$current_time = new DateTime();
$token_expiry = $user['token_expiry']->toDateTime();

if ($token_expiry < $current_time) {
  $error="Token expired. Please request a new verification email." ;
  } else {
  $collection->updateOne(
  ['_id' => $user['_id']],
  ['$set' => ['is_verified' => true], '$unset' => ['token' => "", 'token_expiry' => "", 'last_verification_request' => ""]]
  );
  $success = "Email verified successfully!";
  header('Location: login');
  }
  }
  }
  ?>
  <!DOCTYPE html>
  <html>

  <head>
    <meta charset="UTF-8">
    <script src="//cdn.jsdelivr.net/npm/sweetalert2@11"></script>
  </head>

  <body>
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