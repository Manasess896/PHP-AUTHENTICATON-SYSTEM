<?php
session_start();
require_once '../vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->safeLoad();

use MongoDB\Client;
use Dotenv\Dotenv;
use MongoDB\BSON\ObjectId;

// Block access unless fully logged in (not just pending 2FA) and NOT admin
if (!isset($_SESSION['user_id']) || (isset($_SESSION['role']) && $_SESSION['role'] !== 'user')) {
  header('Location: login');
  exit;
}
// If stray admin markers exist, remove them (defensive)
unset($_SESSION['is_admin'], $_SESSION['admin_id'], $_SESSION['admin_username']);
$userId = $_SESSION['user_id'];
$username = $_SESSION['username'];
if (isset($_GET['logout'])) {
  session_unset();
  session_destroy();
  setcookie(session_name(), '', time() - 3600, '/');
  header('Location: login');
  exit;
}
// CSRF token (needed for AJAX password re-auth)
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

try {
  $uri = $_ENV['MONGODB_URI'] ?? getenv('MONGODB_URI');
  $mydatabase = $_ENV['MONGODB_DATABASE'] ?? getenv('MONGODB_DATABASE');
  $client = new Client($uri);
  $collection = $client->$mydatabase->users;
} catch (Exception $e) {
  die('Database connection error');
}

// Handle AJAX password re-auth request for starting 2FA setup
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'reauth_2fa') {
  header('Content-Type: application/json');
  // Basic CSRF validation
  if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], (string)$_POST['csrf_token'])) {
    echo json_encode(['ok' => false, 'error' => 'Invalid security token']);
    exit;
  }
  if (!isset($_SESSION['user_id'])) {
    echo json_encode(['ok' => false, 'error' => 'Not authenticated']);
    exit;
  }
  $attempts = (int)($_SESSION['reauth_2fa_attempts'] ?? 0);
  if ($attempts >= 5) {
    echo json_encode(['ok' => false, 'error' => 'Too many attempts. Reload page.']);
    exit;
  }
  $password = (string)($_POST['password'] ?? '');
  $userDoc = $collection->findOne(['_id' => new ObjectId($_SESSION['user_id'])]);
  if (!$userDoc || empty($userDoc['password']) || !password_verify($password, $userDoc['password'])) {
    $_SESSION['reauth_2fa_attempts'] = $attempts + 1;
    $left = max(0, 5 - ($_SESSION['reauth_2fa_attempts']));
    echo json_encode(['ok' => false, 'error' => 'Incorrect password', 'attemptsLeft' => $left]);
    exit;
  }
  // Success: set session flag allowing access to 2FA setup
  $_SESSION['user_2fa_reauth_passed'] = true;
  unset($_SESSION['reauth_2fa_attempts']);
  echo json_encode(['ok' => true, 'redirect' => '2fa-setup']);
  exit;
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>

<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container-fluid">
      <a class="navbar-brand" href="#">Dashboard</a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ms-auto">
          <li class="nav-item">
            <a class="nav-link" href="#">Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="?logout=1">Logout</a>
          </li>
        </ul>
      </div>
    </div>
  </nav>

  <div class="container mt-5">
    <div class="row">
      <div class="col-md-12">
        <div class="card">
          <div class="card-header">
            <h3>Dashboard</h3>
          </div>
          <div class="card-body">
            <h5 class="card-title">Welcome to your dashboard!</h5>
            <p class="card-text">This is a protected area. You are logged in as <?php echo htmlspecialchars($_SESSION['username']); ?>.</p>
            <?php
            // Check if user has 2FA enabled
            try {
              $userDoc = $collection->findOne(['_id' => new ObjectId($userId)]);
              $has2fa = $userDoc && !empty($userDoc['twofa_secret']);
            } catch (Exception $e) {
              $has2fa = false;
            }
            ?>
            <div class="mt-4 p-3 border rounded">
              <h6 class="mb-2">Two‑Factor Authentication (2FA)</h6>
              <?php if (!empty($has2fa)): ?>
                <div class="alert alert-success py-2" role="alert">2FA is enabled on your account.</div>
                <button type="button" class="btn btn-outline-primary btn-sm" id="btn-reconfig-2fa">Reconfigure 2FA</button>
              <?php else: ?>
                <p class="mb-2">Add an extra layer of security by enabling 2FA.</p>
                <button type="button" class="btn btn-primary" id="btn-enable-2fa">Enable 2FA</button>
              <?php endif; ?>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Password Re-auth Modal -->
  <div class="modal fade" id="reauthModal" tabindex="-1" aria-labelledby="reauthModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title" id="reauthModalLabel">Confirm Your Password</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <p class="mb-3 small text-muted">For security, please confirm your password before proceeding to set up Two‑Factor Authentication.</p>
          <form id="reauthForm">
            <div class="mb-3">
              <label for="reauthPassword" class="form-label">Password</label>
              <input type="password" class="form-control" id="reauthPassword" name="password" required autocomplete="current-password">
            </div>
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="d-flex justify-content-end gap-2">
              <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
              <button type="submit" class="btn btn-primary" id="reauthSubmitBtn">Continue</button>
            </div>
            <div class="form-text text-danger mt-2 d-none" id="reauthError"></div>
          </form>
        </div>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    (function() {
      const enableBtn = document.getElementById('btn-enable-2fa');
      const reconfigBtn = document.getElementById('btn-reconfig-2fa');
      const modalEl = document.getElementById('reauthModal');
      if (!modalEl) return;
      const modal = new bootstrap.Modal(modalEl);
      const form = document.getElementById('reauthForm');
      const passInput = document.getElementById('reauthPassword');
      const submitBtn = document.getElementById('reauthSubmitBtn');
      const errorBox = document.getElementById('reauthError');

      function openModal() {
        if (errorBox) {
          errorBox.classList.add('d-none');
          errorBox.textContent = '';
        }
        if (passInput) {
          passInput.value = '';
        }
        modal.show();
        setTimeout(() => {
          passInput && passInput.focus();
        }, 250);
      }

      function handleClick(e) {
        e.preventDefault();
        openModal();
      }

      enableBtn && enableBtn.addEventListener('click', handleClick);
      reconfigBtn && reconfigBtn.addEventListener('click', handleClick);

      form && form.addEventListener('submit', async function(e) {
        e.preventDefault();
        if (!passInput.value) return;
        submitBtn.disabled = true;
        submitBtn.textContent = 'Verifying...';
        const fd = new FormData();
        fd.append('action', 'reauth_2fa');
        fd.append('password', passInput.value);
        fd.append('csrf_token', '<?= htmlspecialchars($_SESSION['csrf_token']); ?>');
        try {
          const res = await fetch(window.location.href, {
            method: 'POST',
            body: fd,
            credentials: 'same-origin'
          });
          const data = await res.json().catch(() => ({
            ok: false,
            error: 'Invalid response'
          }));
          if (data.ok) {
            submitBtn.textContent = 'Redirecting...';
            window.location.href = data.redirect || '2fa-setup';
          } else {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Continue';
            if (errorBox) {
              errorBox.textContent = (data.error || 'Verification failed') + (data.attemptsLeft !== undefined ? ` (Attempts left: ${data.attemptsLeft})` : '');
              errorBox.classList.remove('d-none');
            }
            passInput.focus();
            passInput.select();
          }
        } catch (err) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Continue';
          if (errorBox) {
            errorBox.textContent = 'Network error. Try again.';
            errorBox.classList.remove('d-none');
          }
        }
      });
    })();
  </script>
</body>

</html>