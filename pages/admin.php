<?php
session_start();
require_once '../vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->safeLoad();

use MongoDB\Client;
use Dotenv\Dotenv;
use MongoDB\BSON\ObjectId;
use MongoDB\BSON\UTCDateTime;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as PHPMailerException;

// Require admin session (hardened)
if (empty($_SESSION['is_admin']) || empty($_SESSION['admin_id']) || (isset($_SESSION['role']) && $_SESSION['role'] !== 'admin')) {
  // Drop any mixed role artifacts
  unset($_SESSION['user_id'], $_SESSION['username'], $_SESSION['role']);
  try {
    $usersCollection->updateOne(
      ['_id' => new ObjectId($_SESSION['admin_id'])],
      ['$set' => [
        'is_locked' => true

      ]]
    );
  } catch (\Throwable $ie) {
    // continue to logout even if update fails
  }
  header('Location: login');
  exit;
}
if (!isset($error)) {
  $has2fa = !empty($user['twofa_secret']);
  if ($has2fa === null) {
  }
}
if (isset($_GET['logout'])) {
  session_unset();
  session_destroy();
  setcookie(session_name(), '', time() - 3600, '/');
  header('Location: login');
  exit;
}
try {
  $uri = $_ENV['MONGODB_URI'] ?? getenv('MONGODB_URI');
  $mydatabase = $_ENV['MONGODB_DATABASE'] ?? getenv('MONGODB_DATABASE');
  $client = new Client($uri);
  $db = $client->$mydatabase;
  $usersCollection = $db->users;
  $attemptsCollection = $db->attempts;
  $newsletterCollection = $db->newsletter;
  $contactsCollection = $db->contacts;
} catch (\Throwable $e) {
  die('Database connection error');
}
// Verify the admin exists and is still an admin
try {
  $adminUser = $usersCollection->findOne(['_id' => new ObjectId($_SESSION['admin_id'])]);
  if (!$adminUser || empty($adminUser['is_admin'])) {
    // Lock the account 
    try {
      $usersCollection->updateOne(
        ['_id' => new ObjectId($_SESSION['admin_id'])],
        ['$set' => [
          'is_locked' => true

        ]]
      );
    } catch (\Throwable $ie) {
      // continue to logout even if update fails
    }
    session_unset();
    session_destroy();
    header('Location: login');

    exit;
  }
} catch (\Throwable $e) {
  die('Failed to load admin profile');
}

// CSRF token for AJAX actions
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Forced 2FA: determine if admin must enable 2FA 
$force2FARequired = empty($adminUser['twofa_secret']);
//force admin to enroll 2fa if no 2fa enrolled
// Handle forced 2FA AJAX actions before rendering HTML
if ($force2FARequired && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['force2fa_action'])) {
  header('Content-Type: application/json');
  // Basic CSRF check
  if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], (string)$_POST['csrf_token'])) {
    echo json_encode(['ok' => false, 'error' => 'Invalid CSRF token']);
    exit;
  }
  try {
    // Refresh user document
    $adminUser = $usersCollection->findOne(['_id' => new ObjectId($_SESSION['admin_id'])]);
    if (!$adminUser) {
      echo json_encode(['ok' => false, 'error' => 'Admin not found']);
      exit;
    }
    $action = $_POST['force2fa_action'];
    if ($action === 'request_code') {
      // Limit sending attempts to 3 per not-yet-successful cycle
      $sentCount = (int)($adminUser['force2fa_code_sent'] ?? 0);
      if ($sentCount >= 3) {
        echo json_encode(['ok' => false, 'error' => 'Maximum send attempts reached. Contact support.']);
        exit;
      }
      // Generate 6-digit code
      $code = random_int(100000, 999999);
      $expiresAt = new UTCDateTime((time() + 600) * 1000); //valif for  10 minutes
      $usersCollection->updateOne(
        ['_id' => $adminUser['_id']],
        ['$set' => [
          'force2fa_code_hash' => password_hash((string)$code, PASSWORD_DEFAULT),
          'force2fa_code_expires' => $expiresAt,
          'force2fa_code_attempts' => 0,
          'force2fa_code_sent' => $sentCount + 1,
          'force2fa_required' => true
        ]]
      );
      // Send email with code
      $smtpHost = $_ENV['MAIL_HOST'] ?? getenv('MAIL_HOST') ?? '';
      $smtpPort = (int)($_ENV['MAIL_PORT'] ?? getenv('MAIL_PORT') ?? 587);
      $smtpUser = $_ENV['MAIL_USERNAME'] ?? getenv('MAIL_USERNAME') ?? '';
      $smtpPass = $_ENV['MAIL_PASSWORD'] ?? getenv('MAIL_PASSWORD') ?? '';
      $smtpSecure = $_ENV['MAIL_ENCRYPTION'] ?? getenv('MAIL_ENCRYPTION') ?? 'tls';
      $fromEmail = $_ENV['MAIL_FROM_ADDRESS'] ?? getenv('MAIL_FROM_ADDRESS') ?? $smtpUser;
      $fromName = $_ENV['MAIL_FROM_NAME'] ?? getenv('MAIL_FROM_NAME') ?? 'Security';
      $targetEmail = (string)($adminUser['email'] ?? '');
      if ($smtpHost && $smtpUser && $smtpPass && $fromEmail && filter_var($targetEmail, FILTER_VALIDATE_EMAIL)) {
        try {
          $mailer = new PHPMailer(true);
          $mailer->isSMTP();
          $mailer->Host = $smtpHost;
          $mailer->SMTPAuth = true;
          $mailer->Username = $smtpUser;
          $mailer->Password = $smtpPass;
          if ($smtpSecure) {
            $mailer->SMTPSecure = $smtpSecure;
          }
          $mailer->Port = $smtpPort;
          $mailer->CharSet = 'UTF-8';
          $mailer->setFrom($fromEmail, $fromName);
          $mailer->addAddress($targetEmail, $adminUser['fullname'] ?? 'Admin');
          $mailer->isHTML(true);
          $mailer->Subject = 'Admin 2FA Enablement Code';
          $mailer->Body = '<p>Your code to start 2FA setup is: <strong style="font-size:20px;">' . $code . '</strong></p><p>This code expires in 10 minutes.</p>';
          $mailer->AltBody = 'Your 2FA setup code is: ' . $code;
          $mailer->send();
        } catch (PHPMailerException $e) {

          echo json_encode(['ok' => false, 'error' => 'Failed to send email: ' . $e->getMessage()]);
          exit;
        }
      } else {
        echo json_encode(['ok' => false, 'error' => 'Mail server not configured']);
        exit;
      }
      echo json_encode(['ok' => true, 'message' => 'Code sent']);
      exit;
    } elseif ($action === 'verify_code') {
      $input = trim((string)($_POST['code'] ?? ''));
      if (!preg_match('/^\d{6}$/', $input)) {
        echo json_encode(['ok' => false, 'error' => 'Invalid code format']);
        exit;
      }
      // Fetch fresh user doc again for fields
      $adminUser = $usersCollection->findOne(['_id' => new ObjectId($_SESSION['admin_id'])]);
      $attempts = (int)($adminUser['force2fa_code_attempts'] ?? 0);
      if ($attempts >= 3) {
        echo json_encode(['ok' => false, 'error' => 'Maximum verification attempts reached']);
        exit;
      }
      $expires = $adminUser['force2fa_code_expires'] ?? null;
      if (!$expires || !($expires instanceof UTCDateTime) || $expires->toDateTime() < new DateTime()) {
        echo json_encode(['ok' => false, 'error' => 'Code expired. Request a new one.']);
        exit;
      }
      $hash = $adminUser['force2fa_code_hash'] ?? '';
      $ok = is_string($hash) && password_verify($input, $hash);
      if (!$ok) {
        $usersCollection->updateOne(
          ['_id' => $adminUser['_id']],
          ['$set' => ['force2fa_code_attempts' => $attempts + 1]]
        );
        $left = max(0, 3 - ($attempts + 1));
        echo json_encode(['ok' => false, 'error' => 'Incorrect code', 'attemptsLeft' => $left]);
        exit;
      }
      // Success
      $usersCollection->updateOne(
        ['_id' => $adminUser['_id']],
        ['$unset' => [
          'force2fa_code_hash' => true,
          'force2fa_code_expires' => true,
          'force2fa_code_attempts' => true,
          'force2fa_code_sent' => true
        ]]
      );
      $_SESSION['force2fa_email_passed'] = true; // allow access to setup page
      echo json_encode(['ok' => true, 'redirect' => '2fa-setup?admin=1']);
      exit;
    } else {
      echo json_encode(['ok' => false, 'error' => 'Unknown action']);
      exit;
    }
  } catch (\Throwable $e) {
    echo json_encode(['ok' => false, 'error' => 'Unexpected server error']);
    exit;
  }
}
// Mark contact as resolved
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'mark_resolved') {
  header('Content-Type: application/json');
  try {
    if (empty($_SESSION['is_admin']) || empty($_SESSION['admin_id'])) {
      echo json_encode(['ok' => false, 'error' => 'Unauthorized']);
      exit;
    }
    $contactId = $_POST['contact_id'] ?? '';
    if (!is_string($contactId) || !preg_match('/^[a-f0-9]{24}$/i', $contactId)) {
      echo json_encode(['ok' => false, 'error' => 'Invalid contact id']);
      exit;
    }
    $result = $contactsCollection->updateOne(
      ['_id' => new ObjectId($contactId)],
      ['$set' => ['is_resolved' => true, 'resolved_at' => new UTCDateTime()]]
    );
    if ($result->getModifiedCount() === 0 && $result->getMatchedCount() === 0) {
      echo json_encode(['ok' => false, 'error' => 'Contact not found']);
      exit;
    }
    echo json_encode(['ok' => true]);
  } catch (\Throwable $e) {
    echo json_encode(['ok' => false, 'error' => 'Update failed']);
  }
  exit;
}

// Send newsletter to all subscribers
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'send_newsletter') {
  header('Content-Type: application/json');
  try {
    if (empty($_SESSION['is_admin']) || empty($_SESSION['admin_id'])) {
      echo json_encode(['ok' => false, 'error' => 'Unauthorized']);
      exit;
    }

    $subject = trim($_POST['subject'] ?? '');
    $body = trim($_POST['body'] ?? '');
    if ($subject === '' || $body === '') {
      echo json_encode(['ok' => false, 'error' => 'Subject and message are required']);
      exit;
    }

    // Load SMTP configuration from environment
    $smtpHost = $_ENV['MAIL_HOST'] ?? getenv('MAIL_HOST') ?? '';
    $smtpPort = (int)($_ENV['MAIL_PORT'] ?? getenv('MAIL_PORT') ?? 587);
    $smtpUser = $_ENV['MAIL_USERNAME'] ?? getenv('MAIL_USERNAME') ?? '';
    $smtpPass = $_ENV['MAIL_PASSWORD'] ?? getenv('MAIL_PASSWORD') ?? '';
    $smtpSecure = $_ENV['MAIL_ENCRYPTION'] ?? getenv('MAIL_ENCRYPTION') ?? 'tls'; // tls|ssl|''
    $fromEmail = $_ENV['MAIL_FROM_ADDRESS'] ?? getenv('MAIL_FROM_ADDRESS') ?? $smtpUser;
    $fromName = 'newsletter';

    if ($smtpHost === '' || $smtpUser === '' || $smtpPass === '' || $fromEmail === '') {
      echo json_encode(['ok' => false, 'error' => 'Mail server is not configured']);
      exit;
    }

    // fetch newsletter subscribers
    $cursor = $newsletterCollection->find([], ['projection' => ['email' => 1]]);
    $emails = [];
    foreach ($cursor as $sub) {
      if (!empty($sub['email']) && filter_var($sub['email'], FILTER_VALIDATE_EMAIL)) {
        $emails[strtolower((string)$sub['email'])] = true; // dedupe
      }
    }
    $emails = array_keys($emails);
    if (count($emails) === 0) {
      echo json_encode(['ok' => false, 'error' => 'No subscribers found']);
      exit;
    }

    // Prepare mailer
    $mailer = new PHPMailer(true);
    try {
      $mailer->isSMTP();
      $mailer->Host = $smtpHost;
      $mailer->SMTPAuth = true;
      $mailer->Username = $smtpUser;
      $mailer->Password = $smtpPass;
      if ($smtpSecure) {
        $mailer->SMTPSecure = $smtpSecure;
      }
      $mailer->Port = $smtpPort;
      $mailer->CharSet = 'UTF-8';
      $mailer->setFrom($fromEmail, $fromName);
      $mailer->isHTML(true);
      $mailer->Subject = $subject;
      $mailer->Body = nl2br($body);
      $mailer->AltBody = $body;

      //
      $mailer->addAddress($fromEmail, $fromName);
      foreach ($emails as $em) {
        $mailer->addBCC($em);
      }
      $mailer->send();
      echo json_encode(['ok' => true, 'total' => count($emails)]);
    } catch (PHPMailerException $mex) {
      echo json_encode(['ok' => false, 'error' => 'Mailer error: ' . $mex->getMessage()]);
    }
  } catch (\Throwable $e) {
    echo json_encode(['ok' => false, 'error' => 'Unexpected error']);
  }
  exit;
}

try {
  $messages = $contactsCollection->find([], [
    'sort' => ['submitted_at' => -1] // newest first
  ]);
} catch (Exception $e) {
  die('Failed to load contact messages');
}

// Load subscribers (for UI only)
try {
  $subscribers = $newsletterCollection->find([], ['projection' => ['email' => 1], 'sort' => ['email' => 1]]);
} catch (Exception $e) {
  $subscribers = [];
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/@sweetalert2/theme-bootstrap-4/bootstrap-4.css" rel="stylesheet">
  <style>
    .stat {
      border-radius: .5rem;
    }
  </style>
</head>

<body>
  <div class="container py-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h1 class="h3 mb-0">Admin Dashboard</h1>
      <a class="btn btn-outline-danger btn-sm" href="?logout=1">Logout</a>
    </div>

    <!-- Newsletter Panel -->
    <div class="card mb-4">
      <div class="card-header d-flex justify-content-between align-items-center">
        <strong>Send Newsletter</strong>
        <div>
          <button class="btn btn-sm btn-outline-secondary" id="toggle-subscribers">Show subscribers</button>
        </div>
      </div>
      <div class="card-body">
        <form id="newsletter-form" class="row gy-3">
          <div class="col-12">
            <label class="form-label">Subject</label>
            <input type="text" name="subject" class="form-control" placeholder="Newsletter subject" required />
          </div>
          <div class="col-12">
            <label class="form-label">Message</label>
            <textarea name="body" class="form-control" rows="6" placeholder="Write your newsletter message..." required></textarea>
          </div>
          <div class="col-12" id="subscribers-wrapper" style="display:none;">
            <label class="form-label">Subscribers (read-only)</label>
            <select class="form-select" size="6" multiple disabled>
              <?php if ($subscribers): foreach ($subscribers as $s): $eml = htmlspecialchars((string)($s['email'] ?? ''), ENT_QUOTES, 'UTF-8');
                  if ($eml === '') continue; ?>
                  <option><?= $eml ?></option>
              <?php endforeach;
              endif; ?>
            </select>
            <div class="form-text">List is hidden by default to save space.</div>
          </div>
          <div class="col-12 d-flex gap-2">
            <button type="submit" class="btn btn-primary" id="btn-send-newsletter">Send to all subscribers</button>
            <span class="text-muted" id="newsletter-hint">Uses SMTP settings from .env</span>
          </div>
        </form>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <strong>Contact Messages</strong>
      </div>
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table table-striped table-hover align-middle mb-0">
            <thead class="table-light">
              <tr>
                <th>From</th>
                <th>Email</th>
                <th>Subject</th>
                <th>Message</th>
                <th>Submitted</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              <?php
              $hasRows = false;
              foreach ($messages as $msg):
                $hasRows = true;
                $id = (string)$msg['_id'];
                $name = htmlspecialchars($msg['name'] ?? 'Unknown', ENT_QUOTES, 'UTF-8');
                $email = htmlspecialchars($msg['email'] ?? 'Unknown', ENT_QUOTES, 'UTF-8');
                $subject = htmlspecialchars($msg['subject'] ?? '-', ENT_QUOTES, 'UTF-8');
                $message = htmlspecialchars($msg['message'] ?? '-', ENT_QUOTES, 'UTF-8');
                $submittedAt = isset($msg['submitted_at']) && $msg['submitted_at'] instanceof UTCDateTime
                  ? $msg['submitted_at']->toDateTime()->format('Y-m-d H:i')
                  : htmlspecialchars((string)($msg['submitted_at'] ?? '-'), ENT_QUOTES, 'UTF-8');
                $isResolved = !empty($msg['is_resolved']);
              ?>
                <tr id="row-<?= $id ?>">
                  <td><?= $name ?></td>
                  <td><a href="mailto:<?= $email ?>"><?= $email ?></a></td>
                  <td><?= $subject ?></td>
                  <td style="max-width: 360px; white-space: normal;"><?= $message ?></td>
                  <td><?= $submittedAt ?></td>
                  <td>
                    <?php if ($isResolved): ?>
                      <span class="badge bg-success" id="status-<?= $id ?>">Resolved</span>
                    <?php else: ?>
                      <span class="badge bg-warning text-dark" id="status-<?= $id ?>">Open</span>
                    <?php endif; ?>
                  </td>
                  <td>
                    <button
                      class="btn btn-sm btn-primary btn-mark-resolved"
                      data-id="<?= $id ?>"
                      <?= $isResolved ? 'disabled' : '' ?>>Mark Resolved</button>
                  </td>
                </tr>
              <?php endforeach; ?>
              <?php if (!$hasRows): ?>
                <tr>
                  <td colspan="7" class="text-center py-4">No contact messages found.</td>
                </tr>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
  <script>
    const FORCE_2FA_REQUIRED = <?= $force2FARequired ? 'true' : 'false' ?>;
    const CSRF_TOKEN = <?= json_encode($_SESSION['csrf_token']) ?>;

    async function requestForce2FACode() {
      const form = new FormData();
      form.append('force2fa_action', 'request_code');
      form.append('csrf_token', CSRF_TOKEN);
      const res = await fetch(window.location.href, {
        method: 'POST',
        body: form,
        credentials: 'same-origin'
      });
      return res.json().catch(() => ({
        ok: false,
        error: 'Invalid response'
      }));
    }

    async function verifyForce2FACode(code) {
      const form = new FormData();
      form.append('force2fa_action', 'verify_code');
      form.append('code', code);
      form.append('csrf_token', CSRF_TOKEN);
      const res = await fetch(window.location.href, {
        method: 'POST',
        body: form,
        credentials: 'same-origin'
      });
      return res.json().catch(() => ({
        ok: false,
        error: 'Invalid response'
      }));
    }

    async function startForce2FAFlow() {
      // Step 1: Inform user
      const proceed = await Swal.fire({
        title: 'Two-Factor Authentication Required',
        html: '<p>For improved security, you must enable Two-Factor Authentication before continuing to use the admin panel.</p><p>We will first send a 6-digit verification code to your registered email to confirm ownership.</p>',
        icon: 'warning',
        allowOutsideClick: false,
        showCancelButton: false,
        confirmButtonText: 'Send Code'
      });
      if (!proceed.isConfirmed) return;
      // Step 2: Request code
      let sent = await requestForce2FACode();
      if (!sent.ok) {
        await Swal.fire({
          title: 'Error',
          text: sent.error || 'Failed to send code',
          icon: 'error',
          allowOutsideClick: false
        });
        return;
      }
      // Step 3: Prompt for code input loop
      let attemptsLeft = 3; // server enforces
      while (attemptsLeft > 0) {
        const {
          value: code
        } = await Swal.fire({
          title: 'Enter Verification Code',
          input: 'text',
          inputAttributes: {
            maxlength: 6,
            inputmode: 'numeric',
            autocapitalize: 'off',
            autocorrect: 'off',
            pattern: '\\d*'
          },
          html: '<p>Enter the 6-digit code sent to your email. It expires in 10 minutes.</p>' + (attemptsLeft < 3 ? `<p><small>Attempts left: ${attemptsLeft}</small></p>` : ''),
          allowOutsideClick: false,
          showCancelButton: false,
          confirmButtonText: 'Verify',
          preConfirm: (value) => {
            if (!/^\d{6}$/.test(value || '')) {
              Swal.showValidationMessage('Enter a valid 6-digit code');
              return false;
            }
            return value;
          }
        });
        if (!code) return; // shouldn't happen without cancel
        const verify = await verifyForce2FACode(code);
        if (verify.ok) {
          await Swal.fire({
            title: 'Verified',
            text: 'Redirecting to 2FA setup...',
            icon: 'success',
            timer: 1200,
            showConfirmButton: false
          });
          window.location.href = verify.redirect || '2fa-setup?admin=1';
          return;
        } else {
          attemptsLeft = typeof verify.attemptsLeft === 'number' ? verify.attemptsLeft : attemptsLeft - 1;
          if (attemptsLeft <= 0) {
            await Swal.fire({
              title: 'Limit Reached',
              text: 'Maximum verification attempts reached. Refresh the page to try again later.',
              icon: 'error',
              allowOutsideClick: false
            });
            return;
          } else {
            await Swal.fire({
              title: 'Incorrect Code',
              text: (verify.error || 'Incorrect code') + `. Attempts left: ${attemptsLeft}`,
              icon: 'error'
            });
          }
        }
      }
    }

    if (FORCE_2FA_REQUIRED) {
      // Kick off after small delay to allow page render
      window.addEventListener('load', () => setTimeout(startForce2FAFlow, 400));
    }
    // Toggle subscribers dropdown
    document.getElementById('toggle-subscribers').addEventListener('click', (e) => {
      const w = document.getElementById('subscribers-wrapper');
      const btn = e.currentTarget;
      const visible = w.style.display !== 'none';
      w.style.display = visible ? 'none' : '';
      btn.textContent = visible ? 'Show subscribers' : 'Hide subscribers';
    });

    // Send newsletter via AJAX
    document.getElementById('newsletter-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const formEl = e.currentTarget;
      const subject = formEl.subject.value.trim();
      const body = formEl.body.value.trim();
      if (!subject || !body) {
        await Swal.fire({
          title: 'Missing fields',
          text: 'Subject and message are required.',
          icon: 'warning'
        });
        return;
      }
      const confirm = await Swal.fire({
        title: 'Send to all subscribers?',
        text: 'This will send the newsletter to all current subscribers.',
        icon: 'question',
        showCancelButton: true,
        confirmButtonText: 'Send',
      });
      if (!confirm.isConfirmed) return;

      const btn = document.getElementById('btn-send-newsletter');
      btn.disabled = true;
      btn.classList.add('disabled');
      try {
        const form = new FormData();
        form.append('action', 'send_newsletter');
        form.append('subject', subject);
        form.append('body', body);
        const res = await fetch(window.location.href, {
          method: 'POST',
          body: form,
          credentials: 'same-origin'
        });
        const data = await res.json().catch(() => ({
          ok: false,
          error: 'Invalid server response'
        }));
        if (data.ok) {
          await Swal.fire({
            title: 'Sent',
            text: `Newsletter sent to ${data.total} subscribers.`,
            icon: 'success'
          });
          formEl.reset();
        } else {
          await Swal.fire({
            title: 'Error',
            text: data.error || 'Failed to send newsletter.',
            icon: 'error'
          });
        }
      } catch (err) {
        await Swal.fire({
          title: 'Error',
          text: 'Network error. Please try again.',
          icon: 'error'
        });
      } finally {
        btn.disabled = false;
        btn.classList.remove('disabled');
      }
    });

    document.addEventListener('click', async (e) => {
      const btn = e.target.closest('.btn-mark-resolved');
      if (!btn) return;
      const id = btn.getAttribute('data-id');
      if (!id) return;

      // Confirm action
      const confirm = await Swal.fire({
        title: 'Mark as resolved?',
        text: 'This will mark the conversation as resolved.',
        icon: 'question',
        showCancelButton: true,
        confirmButtonText: 'Yes, mark resolved',
      });
      if (!confirm.isConfirmed) return;

      btn.disabled = true;
      btn.classList.add('disabled');
      try {
        const form = new FormData();
        form.append('action', 'mark_resolved');
        form.append('contact_id', id);
        const res = await fetch(window.location.href, {
          method: 'POST',
          body: form,
          credentials: 'same-origin'
        });
        const data = await res.json().catch(() => ({
          ok: false,
          error: 'Invalid server response'
        }));
        if (data.ok) {
          const statusEl = document.getElementById(`status-${id}`);
          if (statusEl) {
            statusEl.textContent = 'Resolved';
            statusEl.classList.remove('bg-warning', 'text-dark');
            statusEl.classList.add('bg-success');
          }
          await Swal.fire({
            title: 'Updated',
            text: 'Message marked as resolved.',
            icon: 'success',
            timer: 1500,
            showConfirmButton: false
          });
        } else {
          btn.disabled = false;
          btn.classList.remove('disabled');
          await Swal.fire({
            title: 'Error',
            text: data.error || 'Failed to update message.',
            icon: 'error'
          });
        }
      } catch (err) {
        btn.disabled = false;
        btn.classList.remove('disabled');
        await Swal.fire({
          title: 'Error',
          text: 'Network error. Please try again.',
          icon: 'error'
        });
      }
    });
  </script>
</body>

</html>