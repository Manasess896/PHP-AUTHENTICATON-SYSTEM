<?php
// Load environment variables
require_once __DIR__ . '/../config/env_loader.php';
require_once __DIR__ . '/../auth-handlers/utils/rate_limiter.php';

// Get reCAPTCHA site key directly from env
$recaptchaSiteKey = getEnvVar('RECAPTCHA_SITE_KEY');

// Process status and message from query string
$status = $_GET['status'] ?? '';
$message = $_GET['message'] ?? '';

// Get client IP for rate limiting
$ip = $_SERVER['REMOTE_ADDR'];
if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && filter_var($_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP)) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
}

// Apply rate limiting per IP
$rateLimitKey = 'contact_' . $ip;
$maxContactAttempts = getEnvVar('MAX_CONTACT_ATTEMPTS', 5);
$contactTimeWindow = getEnvVar('CONTACT_TIME_WINDOW', 3600); // 1 hour

// Check rate limit if form was submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !enforceRateLimit($rateLimitKey, $maxContactAttempts, $contactTimeWindow)) {
    $status = 'rate_limit';
    $message = 'Too many contact form submissions. Please try again later.';
}

// Define message styling based on status
$alertClass = '';
$alertIcon = '';

switch ($status) {
    case 'success':
        $alertClass = 'alert-success';
        $alertIcon = 'bi-check-circle-fill';
        if (empty($message)) {
            $message = 'Your message has been sent successfully! We will get back to you soon.';
        }
        break;
    case 'recaptcha_failed':
        $alertClass = 'alert-warning';
        $alertIcon = 'bi-exclamation-triangle-fill';
        if (empty($message)) {
            $message = 'reCAPTCHA verification failed. Please try again.';
        }
        break;
    case 'rate_limit':
        $alertClass = 'alert-danger';
        $alertIcon = 'bi-exclamation-octagon-fill';
        if (empty($message)) {
            $message = 'You have exceeded the allowed number of submissions. Please try again later.';
        }
        break;
    case 'missing_fields':
        $alertClass = 'alert-danger';
        $alertIcon = 'bi-x-circle-fill';
        if (empty($message)) {
            $message = 'Please fill in all required fields.';
        }
        break;
    case 'invalid_email':
        $alertClass = 'alert-danger';
        $alertIcon = 'bi-x-circle-fill';
        if (empty($message)) {
            $message = 'Please enter a valid email address.';
        }
        break;
    case 'database_error':
        $alertClass = 'alert-danger';
        $alertIcon = 'bi-x-circle-fill';
        if (empty($message)) {
            $message = 'There was an error saving your message. Please try again later.';
        }
        break;
    case 'server_error':
        $alertClass = 'alert-danger';
        $alertIcon = 'bi-x-circle-fill';
        if (empty($message)) {
            $message = 'A server error occurred. Please try again later.';
        }
        break;
    case 'invalid':
        $alertClass = 'alert-warning';
        $alertIcon = 'bi-exclamation-triangle-fill';
        if (empty($message)) {
            $message = 'Invalid form submission. Please use the contact form.';
        }
        break;
    default:
        $message = '';
        break;
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Us - authBoost</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <!-- Animation CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">
    <!-- reCAPTCHA API -->
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <!-- Custom CSS -->
    <style>
        body {
            font-family: 'Inter', sans-serif;
            color: #333;
        }

        .contact-section {
            background-color: #fff;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        }

        .contact-form {
            padding: 2rem;
        }

        .contact-form .form-control {
            border-radius: 8px;
            padding: 1rem;
        }

        .contact-form .btn-primary {
            background: var(--primary-color);
            border: none;
            padding: 0.75rem 1.5rem;
            font-weight: 600;
            border-radius: 8px;
        }

        .contact-form .btn-primary:hover {
            background: var(--secondary-color);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }

        .contact-info {
            background: var(--primary-color);
            color: white;
            padding: 2rem;
            border-radius: 16px;
        }

        .contact-info h3 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
        }

        .contact-info p {
            margin-bottom: 0.5rem;
        }

        .contact-info .icon {
            font-size: 2rem;
            margin-right: 1rem;
        }

        .status-message {
            animation: fadeIn 0.5s ease-in-out;
            margin-bottom: 20px;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
    </style>
</head>

<body class="bg-light">
    <div class="container py-5">
        <?php if (!empty($message)): ?>
            <div class="status-message animate__animated animate__fadeInDown">
                <div class="alert <?php echo $alertClass; ?> d-flex align-items-center" role="alert">
                    <i class="bi <?php echo $alertIcon; ?> me-2"></i>
                    <div><?php echo htmlspecialchars($message); ?></div>
                    <button type="button" class="btn-close ms-auto" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            </div>
        <?php endif; ?>

        <div class="row g-0 shadow-lg contact-section">
            <div class="col-lg-6 p-5 contact-form">
                <h2 class="fw-bold mb-4">Contact Us</h2>
                <p class="mb-4">Have questions about authBoost? We're here to help!</p>
                <form method="POST" action="../auth-handlers/handlers/contact_handler.php" class="contact-form needs-validation" novalidate>
                    <div class="mb-3">
                        <label for="name" class="form-label">Name</label>
                        <input type="text" class="form-control" id="name" name="name" required>
                    </div>
                    <div class="mb-3">
                        <label for="email" class="form-label">Email</label>
                        <input type="email" class="form-control" id="email" name="email" required>
                    </div>
                    <div class="mb-3 fade-in" style="animation-delay: 0.3s;">
                        <label for="subject" class="form-label">Subject</label>
                        <select class="form-select" id="subject" name="subject" required>
                            <option value="" selected disabled>Select a subject</option>
                            <option value="General Inquiry">General Inquiry</option>
                            <option value="Technical Support">Technical Support</option>
                            <option value="Feature Request">Feature Request</option>
                            <option value="Bug Report">Bug Report</option>
                            <option value="Business Inquiry">Business Inquiry</option>
                            <option value="Other">Other</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label for="message" class="form-label">Message</label>
                        <textarea class="form-control" id="message" name="message" rows="5" required></textarea>
                    </div>
                    <div class="mb-3 form-check fade-in" style="animation-delay: 0.5s;">
                        <input type="checkbox" class="form-check-input" id="consent" name="consent" required>
                        <label class="form-check-label" for="consent">I consent to having this website store my submitted information</label>
                    </div>
                    <div class="mb-3 fade-in" style="animation-delay: 0.5s;">
                        <div class="g-recaptcha" data-sitekey="<?php echo htmlspecialchars($recaptchaSiteKey); ?>"></div>
                        <div class="small text-muted mt-2">Please verify you are not a robot.</div>
                    </div>
                    <button type="submit" class="btn btn-danger fw-bold">Submit</button>
                </form>
            </div>
            <div class="col-lg-6 d-none d-lg-block bg-primary p-5 text-white contact-info">
                <h3 class="fw-bold mb-4">Get in Touch</h3>
                <p class="mb-5">Our support team is available 24/7 to answer your questions and provide assistance with any issues you might encounter.</p>

                <div class="d-flex align-items-center mb-4">
                    <div class="bg-white bg-opacity-10 p-3 rounded-circle me-3">
                        <i class="bi bi-envelope text-white"></i>
                    </div>
                    <div>
                        <h5 class="mb-1">Email Us</h5>
                        <p class="mb-0">support@authboost.com</p>
                    </div>
                </div>

                <div class="d-flex align-items-center mb-4">
                    <div class="bg-white bg-opacity-10 p-3 rounded-circle me-3">
                        <i class="bi bi-telephone text-white"></i>
                    </div>
                    <div>
                        <h5 class="mb-1">Call Us</h5>
                        <p class="mb-0">+1 (123) 456-7890</p>
                    </div>
                </div>

                <div class="d-flex align-items-center">
                    <div class="bg-white bg-opacity-10 p-3 rounded-circle me-3">
                        <i class="bi bi-geo-alt text-white"></i>
                    </div>
                    <div>
                        <h5 class="mb-1">Visit Us</h5>
                        <p class="mb-0">123 auth Media St, Digital City, CA 94103</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>

    <?php if ($status === 'success'): ?>
        <script>
            // If form was successful, reset the form for a new submission
            document.addEventListener('DOMContentLoaded', function() {
                document.querySelector('form').reset();
            });
        </script>
    <?php endif; ?>
</body>

</html>