<?php
// Start session at the very beginning of the file
session_start();

// Include CSRF protection before ANY output
require_once '../auth-handlers/utils/csrf_protection.php';

// Prepare CSRF token
$csrfToken = getCurrentCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register </title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Bootstrap Icons -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <!-- Animation CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css">

    <!-- reCAPTCHA API with onload callback -->
    <script src="https://www.google.com/recaptcha/api.js?onload=onRecaptchaLoaded&render=explicit" async defer></script>
    <style>
        .fade-in {
            animation: fadeIn 0.8s ease-in-out;
        }

        @keyframes fadeIn {
            0% {
                opacity: 0;
                transform: translateY(20px);
            }

            100% {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .card {
            border: none;
            border-radius: 12px;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
        }

        .card:hover {
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15);
        }

        .btn-primary {
            background: linear-gradient(to right, #4e73df, #224abe);
            border: none;
            transition: all 0.3s ease;
        }

        .btn-primary:hover {
            background: linear-gradient(to right, #224abe, #1a3a8e);
            transform: translateY(-2px);
        }

        .form-control:focus {
            border-color: #4e73df;
            box-shadow: 0 0 0 0.25rem rgba(78, 115, 223, 0.25);
        }

        .form-control {
            border-radius: 8px;
            padding: 10px 15px;
        }

        .password-toggle {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: #6c757d;
        }

        .password-container {
            position: relative;
        }

        .logo-area {
            margin-bottom: 2rem;
        }

        .logo {
            max-height: 60px;
            margin-bottom: 15px;
        }

        .input-group-text {
            background-color: transparent;
            border-left: none;
        }

        .form-floating label {
            padding-left: 15px;
        }
    </style>
</head>

<body class="bg-light">
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-8 col-lg-6">
                <div class="card shadow-sm animate__animated animate__fadeIn">
                    <div class="card-body p-5">
                        <div class="text-center mb-4 logo-area fade-in">
                            <!-- You can add your logo here -->
                            <div class="d-flex justify-content-center">
                                <div class="rounded-circle bg-primary bg-opacity-10 p-3 mb-3">
                                    <i class="bi bi-rocket-takeoff text-primary" style="font-size: 2rem;"></i>
                                </div>
                            </div>
                            <h2 class="fw-bold text-primary">Create Your Account</h2>
                            <p class="text-muted">Join authBoost to automate your auth media presence</p>
                        </div>

                        <!-- Alert for displaying messages -->
                        <div id="alertMessage" class="alert alert-dismissible fade show d-none" role="alert">
                            <span id="alertText"></span>
                            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                        </div>

                        <form id="registerForm" class="needs-validation" novalidate action="../auth-handlers/handlers/register_handler.php" method="POST">
                            <!-- CSRF Token - Use pre-generated token from PHP, not by calling csrfField() inline -->
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">

                            <div class="row fade-in" style="animation-delay: 0.1s;">
                                <div class="col-md-6 mb-3">
                                    <div class="form-floating">
                                        <input type="text" class="form-control" id="firstName" name="firstName"
                                            placeholder="Enter first name" autocomplete="given-name" required>
                                        <label for="firstName">First Name</label>
                                        <div class="invalid-feedback">Please enter your first name.</div>
                                    </div>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <div class="form-floating">
                                        <input type="text" class="form-control" id="lastName" name="lastName"
                                            placeholder="Enter last name" autocomplete="family-name" required>
                                        <label for="lastName">Last Name</label>
                                        <div class="invalid-feedback">Please enter your last name.</div>
                                    </div>
                                </div>
                            </div>

                            <div class="mb-3 fade-in" style="animation-delay: 0.2s;">
                                <div class="form-floating">
                                    <input type="email" class="form-control" id="email" name="email"
                                        placeholder="name@example.com" autocomplete="email" required>
                                    <label for="email">Email address</label>
                                    <div class="invalid-feedback">Please enter a valid email address.</div>
                                </div>
                            </div>

                            <div class="mb-3 fade-in" style="animation-delay: 0.3s;">
                                <div class="form-floating password-container">
                                    <input type="password" class="form-control" id="password" name="password"
                                        placeholder="Create a password" autocomplete="new-password" required>
                                    <label for="password">Password</label>
                                    <span class="password-toggle" onclick="togglePasswordVisibility('password')">
                                        <i class="bi bi-eye-slash" id="password-toggle-icon"></i>
                                    </span>
                                    <div class="invalid-feedback">Please create a password.</div>
                                </div>
                                <!-- Password strength meter -->
                                <div class="password-strength-meter mt-1">
                                    <div id="password-strength-bar"></div>
                                </div>
                                <small id="passwordHelp" class="form-text text-muted">Use at least 8 characters, including uppercase, lowercase, numbers, and special characters.</small>
                            </div>

                            <div class="mb-3 fade-in" style="animation-delay: 0.4s;">
                                <div class="form-floating password-container">
                                    <input type="password" class="form-control" id="confirmPassword" name="confirmPassword"
                                        placeholder="Confirm your password" autocomplete="new-password" required>
                                    <label for="confirmPassword">Confirm Password</label>
                                    <span class="password-toggle" onclick="togglePasswordVisibility('confirmPassword')">
                                        <i class="bi bi-eye-slash" id="confirmPassword-toggle-icon"></i>
                                    </span>
                                    <div class="invalid-feedback">Please confirm your password.</div>
                                </div>
                            </div>

                            <!-- reCAPTCHA -->
                            <div class="recaptcha-container fade-in" style="animation-delay: 0.5s;">
                                <div id="recaptcha-widget"></div>
                            </div>

                            <div class="mb-3 form-check fade-in" style="animation-delay: 0.6s;">
                                <input type="checkbox" class="form-check-input" id="termsAgreement" name="termsAgreement" required>
                                <label class="form-check-label" for="termsAgreement">I agree to the <a href="#" class="text-decoration-none">Terms of Service</a> and <a href="#" class="text-decoration-none">Privacy Policy</a></label>
                                <div class="invalid-feedback">You must agree to the terms and conditions.</div>
                            </div>

                            <div class="d-grid gap-2 mt-4 fade-in" style="animation-delay: 0.7s;">
                                <button type="submit" class="btn btn-primary py-3 fw-bold" id="submitBtn">Create Account</button>
                            </div>
                        </form>

                        <div class="text-center mt-4 fade-in" style="animation-delay: 0.7s;">
                            <p>Already have an account? <a href="login.php" class="text-decoration-none fw-bold">Login</a></p>
                        </div>
                    </div>
                </div>
                <div class="text-center mt-3 fade-in" style="animation-delay: 0.8s;">
                    <a href="../index.html" class="text-decoration-none">
                        <i class="bi bi-arrow-left"></i> Back to Home
                    </a>
                    <div class="mt-2 small">
                        <a href="faq.html" class="text-decoration-none me-2">
                            <i class="bi bi-question-circle"></i> FAQ
                        </a>
                        <a href="troubleshooting.html" class="text-decoration-none">
                            <i class="bi bi-tools"></i> Troubleshooting
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>

    <!-- Custom JS -->
    <script>
        // reCAPTCHA callback handler
        var recaptchaWidget;

        function onRecaptchaLoaded() {
            recaptchaWidget = grecaptcha.render('recaptcha-widget', {
                'sitekey': '6LfesBQrAAAAAE9kidP0bOsEsLuwRyu_BTMZi1jZ',
                'callback': function(response) {
                    // Enable submit button when reCAPTCHA is completed
                    document.getElementById('submitBtn').disabled = false;
                },
                'expired-callback': function() {
                    // Disable submit button when reCAPTCHA expires
                    document.getElementById('submitBtn').disabled = true;
                }
            });
        }

        // Set CSRF token on page load
        window.addEventListener('DOMContentLoaded', () => {
            // Initially disable submit button until reCAPTCHA is solved
            document.getElementById('submitBtn').disabled = true;

            // Check for URL parameters to display success/error messages
            const urlParams = new URLSearchParams(window.location.search);
            const alertBox = document.getElementById('alertMessage');
            const alertText = document.getElementById('alertText');

            if (urlParams.has('error')) {
                alertBox.classList.remove('d-none', 'alert-success');
                alertBox.classList.add('alert-danger');
                alertText.textContent = decodeURIComponent(urlParams.get('error'));
            } else if (urlParams.has('success')) {
                alertBox.classList.remove('d-none', 'alert-danger');
                alertBox.classList.add('alert-success');
                alertText.textContent = decodeURIComponent(urlParams.get('success'));
            }
        });

        // Function to toggle password visibility
        function togglePasswordVisibility(inputId) {
            const passwordInput = document.getElementById(inputId);
            const toggleIcon = document.getElementById(inputId + '-toggle-icon');

            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                toggleIcon.classList.replace('bi-eye-slash', 'bi-eye');
            } else {
                passwordInput.type = 'password';
                toggleIcon.classList.replace('bi-eye', 'bi-eye-slash');
            }
        }

        // Password strength checker
        document.getElementById('password').addEventListener('input', function() {
            const password = this.value;
            const strengthBar = document.getElementById('password-strength-bar');
            const passwordHelp = document.getElementById('passwordHelp');

            // Calculate strength
            let strength = 0;
            if (password.length >= 8) strength += 1;
            if (password.match(/[A-Z]/)) strength += 1;
            if (password.match(/[a-z]/)) strength += 1;
            if (password.match(/[0-9]/)) strength += 1;
            if (password.match(/[^A-Za-z0-9]/)) strength += 1;

            // Update UI
            strengthBar.className = '';
            if (password.length === 0) {
                strengthBar.style.width = '0';
                passwordHelp.textContent = 'Use at least 8 characters, including uppercase, lowercase, numbers, and special characters.';
            } else if (strength < 3) {
                strengthBar.classList.add('strength-weak');
                strengthBar.style.width = '33%';
                passwordHelp.textContent = 'Weak password: Add more variety of characters.';
            } else if (strength < 5) {
                strengthBar.classList.add('strength-medium');
                strengthBar.style.width = '66%';
                passwordHelp.textContent = 'Medium password: Consider adding more variety.';
            } else {
                strengthBar.classList.add('strength-strong');
                strengthBar.style.width = '100%';
                passwordHelp.textContent = 'Strong password!';
            }
        });

        // Form validation and submission
        document.getElementById('registerForm').addEventListener('submit', function(event) {
            if (!this.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }

            // Check if passwords match
            const password = document.getElementById('password');
            const confirmPassword = document.getElementById('confirmPassword');

            if (password.value !== confirmPassword.value) {
                confirmPassword.setCustomValidity('Passwords do not match');
                event.preventDefault();
            } else {
                confirmPassword.setCustomValidity('');
            }

            // Check reCAPTCHA
            const recaptchaResponse = grecaptcha.getResponse(recaptchaWidget);
            if (recaptchaResponse.length === 0) {
                event.preventDefault();

                // Show alert for reCAPTCHA
                const alertBox = document.getElementById('alertMessage');
                const alertText = document.getElementById('alertText');
                alertBox.classList.remove('d-none', 'alert-success');
                alertBox.classList.add('alert-danger');
                alertText.textContent = 'Please complete the reCAPTCHA verification.';

                return false;
            }

            this.classList.add('was-validated');
        });
    </script>
</body>

</html>