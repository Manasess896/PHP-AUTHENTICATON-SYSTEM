<?php
session_start();
require_once 'vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

use MongoDB\Client;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

try {
  $url = $_ENV['MONGODB_URI'] ?? getenv('MONGODB_URI');
  $mydatabase = $_ENV['MONGODB_DATABASE'] ?? getenv('MONGODB_DATABASE');
  $client = new Client($url);
  $collection = $client->selectCollection($mydatabase, 'contacts');
} catch (Exception $e) {
  die('Failed to connect to the database. Please contact the developer.');
}

// csrf token generation
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  //valifate recaptcha first before use
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

    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
      die('CSRF token validation failed');
    }
    function clean_input($data)
    {
      return htmlspecialchars(strip_tags(trim($data)), ENT_QUOTES, 'UTF-8');
    }

    $name = clean_input($_POST['name'] ?? '');
    $email = clean_input($_POST['email'] ?? '');
    $subject = clean_input($_POST['subject'] ?? '');
    $message = clean_input($_POST['message'] ?? '');
    $consent = isset($_POST['consent']);
    $ip = $_SERVER['REMOTE_ADDR'];
    $error = '';

    if (empty($name) || empty($email) || empty($subject) || empty($message)) {
      $error = 'All fields are required.';
    } elseif (!$consent) {
      $error = 'You must agree to the privacy policy.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $error = 'Invalid email address.';
    } elseif (strlen($message) > 1000) {
      $error = 'Message is too long (maximum 1000 characters).';
    } elseif (strlen($subject) > 100) {
      $error = 'Subject is too long (maximum 100 characters).';
    } elseif (strlen($name) > 100) {
      $error = 'Name is too long (maximum 100 characters).';
    }

    if (empty($error)) {
      try {
        $collection->insertOne([
          'name' => $name,
          'email' => strtolower($email),
          'subject' => $subject,
          'message' => $message,
          'ip' => $ip,
          'created_at' => new MongoDB\BSON\UTCDateTime()
        ]);

        $mail = new PHPMailer(true);
        try {
        
          $mail->isSMTP();
          $mail->Host = $_ENV['MAIL_HOST'] ?? getenv('MAIL_HOST');
          $mail->SMTPAuth = true;
          $mail->Username = $_ENV['MAIL_USERNAME'] ?? getenv('MAIL_USERNAME');
          $mail->Password = $_ENV['MAIL_PASSWORD'] ?? getenv('MAIL_PASSWORD');
          $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
          $mail->Port = $_ENV['MAIL_PORT'] ?? getenv('MAIL_PORT');

          //Recipients
          $mail->setFrom($_ENV['MAIL_FROM_ADDRESS'], $_ENV['MAIL_FROM_NAME']);
          $mail->addAddress($email, $name);  

          //Content
          $mail->isHTML(true);
          $mail->Subject = 'Thank you for contacting us';
          $mail->Body    = "<p>Hi {$name},</p>
                            <p>Thank you for your message. We have received it and will get back to you shortly.</p>
                            <p><b>Your Subject:</b> {$subject}</p>
                            <p><b>Your Message:</b></p>
                            <p>{$message}</p>
                            <br>
                            <p>Best regards,</p>
                            <p>The Team</p>";

          $mail->send();
          $success = 'Message sent successfully!';
        } catch (Exception $e) {
      
          $error = 'Message was sent , but failed to send a confirmation email.';
        }
      } catch (Exception $e) {
        $error = 'Failed to send message. Please try again later.';
      }
    }
  } else {
    $error = 'reCAPTCHA verification failed. Please try again.';
  }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Contact Us</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/@sweetalert2/theme-bootstrap-4/bootstrap-4.css" rel="stylesheet">
</head>

<body>
  <div class="container mt-5">
    <div class="row justify-content-center">
      <div class="col-md-6">
        <div class="card">
          <div class="card-header">
            <h2 class="text-center">Contact Us</h2>
          </div>
          <div class="card-body">
            <?php
            if (isset($_SESSION['message'])) {
              echo '<div class="alert alert-success">' . htmlspecialchars($_SESSION['message']) . '</div>';
              unset($_SESSION['message']);
            }
            if (isset($_SESSION['error'])) {
              echo '<div class="alert alert-danger">' . htmlspecialchars($_SESSION['error']) . '</div>';
              unset($_SESSION['error']);
            }
            ?>
            <form action="contact.php" method="POST">
              <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
              <div class="mb-3">
                <label for="name" class="form-label">Name</label>
                <input type="text" class="form-control" id="name" name="name" required>
              </div>
              <div class="mb-3">
                <label for="email" class="form-label">Email address</label>
                <input type="email" class="form-control" id="email" name="email" required>
              </div>
              <div class="mb-3">
                <label for="subject" class="form-label">Subject</label>
                <input type="text" class="form-control" id="subject" name="subject" required>
              </div>
              <div class="mb-3">
                <label for="message" class="form-label">Message</label>
                <textarea class="form-control" id="message" name="message" rows="5" required></textarea>
              </div>
              <div class="g-recaptcha" data-sitekey="<?= $_ENV['RECAPTCHA_SITE_KEY'] ?? getenv('RECAPTCHA_SITE_KEY') ?>"></div>
              <div class="mb-3">
                <input type="checkbox" name="consent" id="consent"><label for="privacy_policy" class="form-label">By sending this message you agree to our privacy policy</label>

              </div>
              <div class="d-grid">

                <button type="submit" class="btn btn-primary">Send Message</button>
              </div>
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