<?php
session_start();
require_once '../vendor/autoload.php';

use OTPHP\TOTP;
use MongoDB\Client;

$isAdminContext = (!empty($_SESSION['is_admin']) && !empty($_SESSION['admin_id']) && (isset($_SESSION['role']) ? $_SESSION['role'] === 'admin' : true));
$userId = null;
if ($isAdminContext) {
  if (empty($_SESSION['force2fa_email_passed'])) {
    header('Location: admin-dashboard');
    exit;
  }
  $userId = $_SESSION['admin_id'];
} else {
  // Ensure we are strictly in user role
  if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin') {
    header('Location: admin-dashboard');
    exit;
  }
  if (!isset($_SESSION['user_id'])) {
    header('Location: login');
    exit;
  }
  if (empty($_SESSION['user_2fa_reauth_passed'])) {
    header('Location: dashboard');
    exit;
  }
  $userId = $_SESSION['user_id'];
}

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->safeLoad();

if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

try {
  $url = $_ENV['MONGODB_URI'] ?? getenv('MONGODB_URI');
  $mydatabase = $_ENV['MONGODB_DATABASE'] ?? getenv('MONGODB_DATABASE');
  $client = new Client($url);
  $collection = $client->selectCollection($mydatabase, 'users');
} catch (Exception $e) {
  die('Failed to connect to the database. Please contact the developer.');
}

if (empty($_SESSION['twofa_setup_secret'])) {
  $totp = TOTP::create();
  $totp->setLabel($_SESSION['username'] ?? 'User');
  $totp->setIssuer($_ENV['APP_NAME'] ?? getenv('APP_NAME') ?? 'github.com/manases896');
  $_SESSION['twofa_setup_secret'] = $totp->getSecret();
  $_SESSION['twofa_setup_uri'] = $totp->getProvisioningUri();
}

$secret = $_SESSION['twofa_setup_secret'];
$qrUri = $_SESSION['twofa_setup_uri'];
$qrImg = 'https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=' . urlencode($qrUri);


if ($_SERVER['REQUEST_METHOD'] === 'POST') {

  if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die('Invalid CSRF token.');
  }

  $code = trim($_POST['code'] ?? '');
  $verifyTotp = TOTP::create($secret);
  $isValid = $code !== '' && $verifyTotp->verify($code);

  if ($isValid) {
    $collection->updateOne(
      ['_id' => new MongoDB\BSON\ObjectId($userId)],
      ['$set' => ['twofa_secret' => $secret]]
    );
    unset($_SESSION['twofa_setup_secret'], $_SESSION['twofa_setup_uri']);
    if ($isAdminContext) {
      unset($_SESSION['force2fa_email_passed']);
    } else {
      unset($_SESSION['user_2fa_reauth_passed']);
    }
    $success = 'Two-Factor Authentication enabled successfully.';
    // Security hardening: destroy session and force fresh login after enabling 2FA
    session_regenerate_id(true);
    session_unset();
    session_destroy();
    // Set a short-lived flag via query param for UI messaging on login
    header('Location: login?twofa_enabled=1');
    exit;
  } else {
    $error = 'Invalid code, please try again.';
  }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Set up 2FA</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
</head>

<body>
  <div class="container py-5">
    <div class="row justify-content-center">
      <div class="col-md-8 col-lg-6">
        <div class="card shadow-sm">
          <div class="card-header">
            <h4 class="mb-0">Enable Two‑Factor Authentication</h4>
          </div>
          <div class="card-body">
            <?php if (isset($success)): ?>
              <div class="alert alert-success" role="alert">
                <?php echo htmlspecialchars($success); ?>
              </div>
              <?php if ($isAdminContext): ?>
                <a class="btn btn-primary" href="admin-dashboard">Go to Admin Dashboard</a>
              <?php else: ?>
                <a class="btn btn-primary" href="dashboard">Go to Dashboard</a>
              <?php endif; ?>
            <?php else: ?>
              <p class="mb-3">Scan this QR code with Google Authenticator, Microsoft Authenticator, or any TOTP app. If you prefer, you can enter the secret manually.</p>
              <div class="text-center mb-3">
                <div id="qr-container" class="d-inline-block border rounded p-2" style="width: 220px; height: 220px;">
                  <!-- QR rendered by JS; fallback image below if JS blocked -->
                </div>
                <noscript>
                  <img src="<?php echo htmlspecialchars($qrImg); ?>" alt="2FA QR Code" class="img-fluid border rounded p-2">
                </noscript>
              </div>
              <div class="mb-3">
                <label class="form-label">Manual secret</label>
                <div class="input-group">
                  <input type="text" id="secretInput" class="form-control" value="<?php echo htmlspecialchars($secret); ?>" readonly>
                  <button type="button" id="copySecretBtn" class="btn btn-outline-secondary">
                    <i class="bi bi-clipboard"></i> Copy
                  </button>
                </div>
                <div id="copyFeedback" class="form-text"></div>
              </div>
              <form method="POST" class="mt-3">
                <div class="mb-3">
                  <label for="code" class="form-label">6‑digit code</label>
                  <input type="text" inputmode="numeric" pattern="[0-9]*" maxlength="6" class="form-control" id="code" name="code" placeholder="Enter code from your app" required>
                  <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                </div>
                <?php if (isset($error)): ?>
                  <div class="alert alert-danger" role="alert"><?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>
                <div class="d-flex gap-2">
                  <button type="submit" class="btn btn-success">Verify & Enable</button>
                  <?php if ($isAdminContext): ?>
                    <a href="admin-dashboard" class="btn btn-outline-secondary">Cancel</a>
                  <?php else: ?>
                    <a href="dashboard" class="btn btn-outline-secondary">Cancel</a>
                  <?php endif; ?>
                </div>
              </form>
            <?php endif; ?>
          </div>
        </div>
      </div>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
  <script>
    // Render QR code client-side for better reliability
    (function() {
      try {
        var uri = <?php echo json_encode($qrUri); ?>;
        var el = document.getElementById('qr-container');
        if (el && uri) {
          new QRCode(el, {
            text: uri,
            width: 220,
            height: 220,
            correctLevel: QRCode.CorrectLevel.M
          });
        }
      } catch (e) {
        // Fallback: add <img> if QR lib fails
        var el = document.getElementById('qr-container');
        if (el) {
          var img = document.createElement('img');
          img.src = <?php echo json_encode($qrImg); ?>;
          img.alt = '2FA QR Code';
          img.className = 'img-fluid';
          el.innerHTML = '';
          el.appendChild(img);
        }
      }
    })();

    // Copy manual secret to clipboard
    (function() {
      var btn = document.getElementById('copySecretBtn');
      var input = document.getElementById('secretInput');
      var feedback = document.getElementById('copyFeedback');
      if (btn && input) {
        btn.addEventListener('click', async function() {
          try {
            await navigator.clipboard.writeText(input.value);
            btn.innerHTML = '<i class="bi bi-clipboard-check"></i> Copied';
            if (feedback) {
              feedback.textContent = 'Secret copied to clipboard.';
            }
            setTimeout(function() {
              btn.innerHTML = '<i class="bi bi-clipboard"></i> Copy';
              if (feedback) {
                feedback.textContent = '';
              }
            }, 1800);
          } catch (err) {
            // Fallback select/copy
            input.removeAttribute('readonly');
            input.select();
            document.execCommand('copy');
            input.setAttribute('readonly', 'readonly');
            btn.innerHTML = '<i class="bi bi-clipboard-check"></i> Copied';
            if (feedback) {
              feedback.textContent = 'Secret copied.';
            }
            setTimeout(function() {
              btn.innerHTML = '<i class="bi bi-clipboard"></i> Copy';
              if (feedback) {
                feedback.textContent = '';
              }
            }, 1800);
          }
        });
      }
    })();
  </script>
</body>

</html>