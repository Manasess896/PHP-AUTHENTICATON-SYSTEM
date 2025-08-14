<?php
session_start();
require_once 'vendor/autoload.php';

use MongoDB\Client;
use Dotenv\Dotenv;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as PHPMailerException;

// Load environment variables
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

// Connect to MongoDB
try {
  $uri = $_ENV['MONGODB_URI'] ?? getenv('MONGODB_URI');
  $mydatabase = $_ENV['MONGODB_DATABASE'] ?? getenv('MONGODB_DATABASE');
  $client = new Client($uri);
  $collection = $client->$mydatabase->users; // "users" collection for accounts
  $attemptsCollection = $client->$mydatabase->attempts; // separate collection for login attempts
  $newsletterCollection = $client->$mydatabase->newsletter; // newsletter collection for email subscriptions
} catch (\Throwable $e) {
  die('Database connection error');
}

// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
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

// Handle POST request for newsletter signup
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['newsletter_signup'])) {
  // Check if this is an AJAX request
  $isAjax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest';

  // Rate limiting configuration
  $ipAddress = $_SERVER['REMOTE_ADDR'];
  $maxAttempts = 3; // Max 3 newsletter signups per hour
  $timeWindow = 3600; // 1 hour in seconds
  $currentTime = time();

  // Check rate limit for newsletter signups
  $recentAttempts = $attemptsCollection->countDocuments([
    'ip' => $ipAddress,
    'type' => 'newsletter',
    'timestamp' => ['$gte' => $currentTime - $timeWindow]
  ]);

  if ($recentAttempts >= $maxAttempts) {
    if ($isAjax) {
      respondJson(false, 'Too many newsletter signup attempts. Please try again later.');
    }
    $error = 'Too many newsletter signup attempts. Please try again later.';
  } else {
    // reCAPTCHA verification
    $recaptchakey = $_ENV['RECAPTCHA_SECRET_KEY'] ?? getenv('RECAPTCHA_SECRET_KEY');
    $recaptchaResponse = $_POST['g-recaptcha-response'] ?? '';

    if (empty($recaptchaResponse)) {
      if ($isAjax) {
        respondJson(false, 'Please complete the reCAPTCHA verification.');
      }
      $error = 'Please complete the reCAPTCHA verification.';
    } else {
      $verifyUrl = 'https://www.google.com/recaptcha/api/siteverify';
      $data = [
        'secret' => $recaptchakey,
        'response' => $recaptchaResponse,
        'remoteip' => $_SERVER['REMOTE_ADDR']
      ];

      $options = [
        'http' => [
          'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
          'method'  => 'POST',
          'content' => http_build_query($data)
        ]
      ];
      $context  = stream_context_create($options);
      $verify = @file_get_contents($verifyUrl, false, $context);

      if ($verify === false) {
        if ($isAjax) {
          respondJson(false, 'Unable to reach reCAPTCHA verification service. Please try again.');
        }
        $error = 'Unable to reach reCAPTCHA verification service. Please try again.';
      } else {
        $captchaDecoded = json_decode($verify, true);
        if (!empty($captchaDecoded['success'])) {
          
          if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
            if ($isAjax) {
              respondJson(false, 'Invalid CSRF token.');
            }
            $error = 'Invalid CSRF token.';
          } else {
           
            $email = trim($_POST['email'] ?? '');

            if (empty($email)) {
              if ($isAjax) {
                respondJson(false, 'Email address is required.');
              }
              $error = 'Email address is required.';
            } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
              if ($isAjax) {
                respondJson(false, 'Please enter a valid email address.');
              }
              $error = 'Please enter a valid email address.';
            } else {
              try {
                $existingEmail = $newsletterCollection->findOne(['email' => $email]);

                if ($existingEmail) {
                  if ($isAjax) {
                    respondJson(false, 'This email address is already subscribed to our newsletter.');
                  }
                  $error = 'This email address is already subscribed to our newsletter.';
                } else {
             
                  $newsletterData = [
                    'email' => $email,
                    'subscribed_at' => new MongoDB\BSON\UTCDateTime(),
                    'ip_address' => $ipAddress,
                    'status' => 'active',
                    'source' => 'homepage_signup'
                  ];

                  $insertResult = $newsletterCollection->insertOne($newsletterData);

                  if ($insertResult->getInsertedId()) {
                  
                    $attemptsCollection->insertOne([
                      'ip' => $ipAddress,
                      'type' => 'newsletter',
                      'timestamp' => $currentTime,
                      'success' => true
                    ]);

                    if ($isAjax) {
                      respondJson(true, 'Thank you for subscribing to our newsletter!');
                    }
                    $success = 'Thank you for subscribing to our newsletter!';
                  } else {
                    if ($isAjax) {
                      respondJson(false, 'Failed to subscribe. Please try again.');
                    }
                    $error = 'Failed to subscribe. Please try again.';
                  }
                }
              } catch (\Throwable $e) {
                $attemptsCollection->insertOne([
                  'ip' => $ipAddress,
                  'type' => 'newsletter',
                  'timestamp' => $currentTime,
                  'success' => false
                ]);

                if ($isAjax) {
                  respondJson(false, 'Database error occurred. Please try again later.');
                }
                $error = 'Database error occurred. Please try again later.';
              }
            }
          }
        } else {
          if ($isAjax) {
            respondJson(false, 'reCAPTCHA verification failed. Please try again.');
          }
          $error = 'reCAPTCHA verification failed. Please try again.';
        }
      }
    }
  }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title></title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
  <style>
    body,
    html {
      height: 100%;
      margin: 0;
    }

    .loading-wrapper {
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      height: 100%;
      text-align: center;
    }
  </style>
</head>

<body>
  <main>



    <!-- Newsletter Signup Section -->
    <div class="container py-5">
      <div class="row justify-content-center">
        <div class="col-lg-6 text-center">
          <h2 class="mb-3">Subscribe to Our Newsletter</h2>
          <p>Stay up to date with the latest news, announcements, and articles.</p>
          <form id="newsletterForm" action="" method="POST">
            <div class="input-group mb-3">
              <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
              <input type="email" name="email" id="emailInput" class="form-control" placeholder="Enter your email" required>
              <button class="btn btn-primary" type="submit" name="newsletter_signup">Subscribe</button>
            </div>
            <div class="g-recaptcha mb-3" data-sitekey="<?= $_ENV['RECAPTCHA_SITE_KEY'] ?? getenv('RECAPTCHA_SITE_KEY') ?>"></div>
          </form>
        </div>
      </div>
    </div>
    <footer class="container text-center py-3">
      <hr>
      <p>
        <a href="home">Home</a> |
        <a href="login">Login</a> |
        <a href="register">Register</a>
        <a href="contact-us">Contact Us</a>
      </p>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>

    <script>
      document.addEventListener('DOMContentLoaded', function() {
        const newsletterForm = document.getElementById('newsletterForm');
        const emailInput = document.getElementById('emailInput');

        if (newsletterForm) {
          newsletterForm.addEventListener('submit', function(e) {
            e.preventDefault();

            // Check if reCAPTCHA is completed
            const recaptchaResponse = grecaptcha.getResponse();
            if (!recaptchaResponse) {
              Swal.fire({
                icon: 'warning',
                title: 'reCAPTCHA Required',
                text: 'Please complete the reCAPTCHA verification.'
              });
              return;
            }

            // Get form data
            const formData = new FormData(newsletterForm);
            // Ensure submit flag is sent for server-side condition
            formData.set('newsletter_signup', '1');

            // Disable submit button and show loading
            const submitBtn = newsletterForm.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.innerHTML = 'Subscribing...';
            submitBtn.disabled = true;

            // Make AJAX request
            fetch(window.location.href, {
                method: 'POST',
                body: formData,
                credentials: 'same-origin',
                headers: {
                  'X-Requested-With': 'XMLHttpRequest'
                }
              })
              .then(async response => {
                // Attempt JSON parse; if HTML returned (e.g., due to PHP error), throw a helpful error
                const text = await response.text();
                try {
                  return JSON.parse(text);
                } catch (e) {
                  throw new Error('Unexpected response from server.');
                }
              })
              .then(data => {
                if (data.success) {
                  Swal.fire({
                    icon: 'success',
                    title: 'Subscription Successful!',
                    text: data.message,
                    confirmButtonColor: '#198754'
                  });

                  // Reset form
                  newsletterForm.reset();
                  grecaptcha.reset();
                } else {
                  Swal.fire({
                    icon: 'error',
                    title: 'Subscription Failed',
                    text: data.message,
                    confirmButtonColor: '#dc3545'
                  });

                  // Reset reCAPTCHA
                  grecaptcha.reset();
                }
              })
              .catch(error => {
                console.error('Error:', error);
                Swal.fire({
                  icon: 'error',
                  title: 'Network Error',
                  text: 'Something went wrong. Please try again later.',
                  confirmButtonColor: '#dc3545'
                });

                // Reset reCAPTCHA
                grecaptcha.reset();
              })
              .finally(() => {
                // Re-enable submit button
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
              });
          });
        }
      });

      // Display server-side messages if any (for non-AJAX requests)
      <?php if (isset($error) && !empty($error)): ?>
        Swal.fire({
          icon: 'error',
          title: 'Newsletter Signup Failed',
          text: '<?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>'
        });
      <?php elseif (isset($success) && !empty($success)): ?>
        Swal.fire({
          icon: 'success',
          title: 'Newsletter Signup Successful!',
          text: '<?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?>'
        });
      <?php endif; ?>
    </script>
</body>

</html>