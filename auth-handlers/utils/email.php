<?php

/**
 * Email utility functions
 * Handles sending various types of emails for the auth system
 */

// Check if email_logger is already included to prevent circular dependencies
if (!function_exists('logEmailActivity')) {
    // Define a minimalist version of logEmailActivity if email_logger is not loaded
    function logEmailActivity($action, $data = [], $result = 'INFO', $message = '')
    {
        // Define log directory and ensure it exists
        $logDir = __DIR__ . '/../logs';
        if (!file_exists($logDir)) {
            mkdir($logDir, 0755, true);
        }

        // Define log file path
        $logFile = $logDir . '/email.log';

        // Format timestamp
        $timestamp = date('Y-m-d H:i:s');

        // Format data as JSON
        $dataJson = json_encode($data);

        // Build log entry
        $logEntry = sprintf(
            "[%s] [%s] %s: %s | Data: %s\n",
            $timestamp,
            $result,
            $action,
            $message,
            $dataJson
        );

        // Write to log file
        return file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX) !== false;
    }
}

if (!function_exists('sendVerificationEmail')) {
    /**
     * Send a verification email to a user
     * 
     * @param string $to Email address of recipient
     * @param string $name Name of recipient
     * @param string $verificationLink Link for email verification
     * @return bool Whether email was sent successfully
     */
    function sendVerificationEmail($to, $name, $verificationLink)
    {
        // Get email configuration from environment with correct variable names
        $fromEmail = getEnvVar('MAIL_FROM_ADDRESS', 'noreply@authboost.com');
        $fromName = getEnvVar('MAIL_FROM_NAME', 'AuthBoost');

        // Correctly map the environment variables to match what's in .env
        $mailDriver = getEnvVar('MAIL_MAILER', 'smtp');
        $smtpHost = getEnvVar('MAIL_HOST', 'smtp.gmail.com'); // Default to Gmail SMTP
        $smtpPort = getEnvVar('MAIL_PORT', '587');
        $smtpUser = getEnvVar('MAIL_USERNAME', '');
        $smtpPass = getEnvVar('MAIL_PASSWORD', '');
        $smtpSecure = getEnvVar('MAIL_ENCRYPTION', 'tls');

        // Debug log the actual configuration being used
        logEmailActivity(
            'EMAIL_CONFIG',
            [
                'driver' => $mailDriver,
                'host' => $smtpHost,
                'port' => $smtpPort,
                'username' => $smtpUser ? 'SET' : 'NOT SET',
                'password' => $smtpPass ? 'SET' : 'NOT SET',
                'encryption' => $smtpSecure,
                'from_email' => $fromEmail,
                'from_name' => $fromName
            ],
            'INFO',
            "Email configuration loaded"
        );

        try {
            // Log email attempt
            logEmailActivity(
                'VERIFICATION_EMAIL_REQUEST',
                ['recipient' => $to, 'name' => $name],
                'INFO',
                "Attempting to send verification email"
            );

            // For development/testing when no SMTP server is available
            if (getEnvVar('APP_ENV', 'development') === 'development' && $mailDriver === 'log') {
                // Log the email instead of sending
                logEmailActivity(
                    'VERIFICATION_EMAIL_LOG',
                    [
                        'recipient' => $to,
                        'name' => $name,
                        'verification_link' => $verificationLink,
                        'mail_driver' => 'log'
                    ],
                    'SUCCESS',
                    "Email logged (not sent) - development mode"
                );

                $debugEmailDir = __DIR__ . '/../logs/mail';
                if (!file_exists($debugEmailDir)) {
                    mkdir($debugEmailDir, 0755, true);
                }

                $emailFilename = $debugEmailDir . '/' . time() . '_' . md5($to . microtime()) . '.html';
                file_put_contents(
                    $emailFilename,
                    "To: $to\nFrom: $fromName <$fromEmail>\nSubject: Verify your email address\n\n" .
                        generateVerificationEmailBody($name, $verificationLink)
                );

                return true;
            }

            $subject = "Verify your email address for AuthBoost";
            $body = generateVerificationEmailBody($name, $verificationLink);
            require_once __DIR__ . '/../../vendor/autoload.php';

            if (!class_exists('PHPMailer\PHPMailer\PHPMailer')) {
                throw new Exception('PHPMailer is not installed. Run: composer require phpmailer/phpmailer');
            }

            $mail = new \PHPMailer\PHPMailer\PHPMailer(true);

            // Set debug level if in development
            if (getEnvVar('APP_ENV', 'development') === 'development') {
                $mail->SMTPDebug = getEnvVar('MAIL_DEBUG_LEVEL', 2);
                $mail->Debugoutput = function ($str, $level) {
                    logEmailActivity('PHPMAILER_DEBUG', ['debug' => $str, 'level' => $level], 'DEBUG', "PHPMailer debug info");
                };
            }

            // Always use SMTP if credentials are provided
            if (!empty($smtpUser) && !empty($smtpPass)) {
                $mail->isSMTP();
                $mail->Host = $smtpHost;
                $mail->SMTPAuth = true;
                $mail->Username = $smtpUser;
                $mail->Password = $smtpPass;
                $mail->SMTPSecure = $smtpSecure;
                $mail->Port = intval($smtpPort);

                // Additional options for common SMTP providers
                if (
                    strpos($smtpHost, 'gmail.com') !== false ||
                    strpos($smtpHost, 'outlook.com') !== false ||
                    strpos($smtpHost, 'office365.com') !== false
                ) {
                    $mail->SMTPOptions = array(
                        'ssl' => array(
                            'verify_peer' => true,
                            'verify_peer_name' => true,
                            'allow_self_signed' => false
                        )
                    );
                }
            } else {
                // If no SMTP credentials, try sendmail first, then fall back to mail()
                if (@is_executable('/usr/sbin/sendmail') || @is_executable('/usr/lib/sendmail')) {
                    $mail->isSendmail();
                } else {
                    $mail->isMail();
                }
            }

            // Test SMTP connection before attempting to send
            if ($mail->SMTPAuth) {
                try {
                    $mail->smtpConnect();
                    logEmailActivity('SMTP_CONNECTION', [], 'SUCCESS', 'SMTP connection test successful');
                } catch (\Exception $e) {
                    logEmailActivity('SMTP_CONNECTION', ['error' => $e->getMessage()], 'ERROR', 'SMTP connection test failed');
                    throw $e;
                }
            }

            // Recipients
            $mail->setFrom($fromEmail, $fromName);
            $mail->addAddress($to, $name);
            $mail->addReplyTo($fromEmail, $fromName);

            // Content
            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body = $body;
            $mail->AltBody = strip_tags(str_replace(['<br>', '<br/>', '<br />'], "\n", $body));

            // Send the email
            $mailSuccess = $mail->send();

            if ($mailSuccess) {
                logEmailActivity(
                    'VERIFICATION_EMAIL_SENT',
                    ['recipient' => $to],
                    'SUCCESS',
                    "Email sent successfully"
                );
                return true;
            } else {
                throw new Exception("Mailer Error: " . $mail->ErrorInfo);
            }
        } catch (Exception $e) {
            logEmailActivity(
                'VERIFICATION_EMAIL_ERROR',
                [
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString(),
                    'recipient' => $to
                ],
                'ERROR',
                "Failed to send verification email"
            );
            return false;
        }
    }
}

/**
 * Generate the HTML body for verification emails
 * 
 * @param string $name Recipient's name
 * @param string $verificationLink The verification link
 * @return string HTML email body
 */
function generateVerificationEmailBody($name, $verificationLink)
{
    return "
    <html>
    <head>
        <title>Verify your email address</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #4e73df; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9f9f9; }
            .button { display: inline-block; padding: 10px 20px; background-color: #4e73df; color: white; 
                    text-decoration: none; border-radius: 4px; margin-top: 20px; }
            .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #777; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h1>Verify your email address</h1>
            </div>
            <div class='content'>
                <p>Hello " . htmlspecialchars($name) . ",</p>
                
                <p>Thank you for registering with AuthBoost. To complete your registration, please verify your email address by clicking the button below:</p>
                
                <p style='text-align: center;'>
                    <a href='$verificationLink' class='button'>Verify Email Address</a>
                </p>
                
                <p>Or copy and paste this link into your browser:</p>
                <p>$verificationLink</p>
                
                <p>This link will expire in 24 hours.</p>
                
                <p>If you did not create this account, please ignore this email.</p>
                
                <p>Having trouble? Contact our support team for assistance.</p>
            </div>
            <div class='footer'>
                <p>&copy; " . date('Y') . " AuthBoost. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    ";
}

/**
 * Check mail system configuration and availability
 * 
 * @return array Configuration status information
 */
function checkMailConfiguration()
{
    $status = [];

    // Check mail driver configuration using the correct variable name
    $mailDriver = getEnvVar('MAIL_MAILER', 'smtp'); // Changed from MAIL_DRIVER to MAIL_MAILER
    $status['driver'] = $mailDriver;

    // Check if mail function is available
    $status['mail_function_available'] = function_exists('mail');

    // Use the correct env variable names
    $status['mail_host'] = getEnvVar('MAIL_HOST', 'localhost');
    $status['mail_port'] = getEnvVar('MAIL_PORT', '587');
    $status['mail_username'] = getEnvVar('MAIL_USERNAME');
    $status['mail_password'] = getEnvVar('MAIL_PASSWORD') ? 'SET' : 'NOT SET';
    $status['mail_encryption'] = getEnvVar('MAIL_ENCRYPTION', 'tls');
    $status['mail_from_address'] = getEnvVar('MAIL_FROM_ADDRESS');
    $status['mail_from_name'] = getEnvVar('MAIL_FROM_NAME');

    // Check SMTP settings if using SMTP
    if ($mailDriver === 'smtp') {
        $status['smtp_host'] = getEnvVar('MAIL_HOST', 'localhost');
        $status['smtp_port'] = getEnvVar('MAIL_PORT', '587');

        // Try connecting to SMTP server
        try {
            $socket = @fsockopen(
                getEnvVar('MAIL_HOST', 'localhost'),
                intval(getEnvVar('MAIL_PORT', '587')),
                $errno,
                $errstr,
                5
            );
            $status['smtp_accessible'] = $socket !== false;
            if ($socket) {
                fclose($socket);
            } else {
                $status['smtp_error'] = "$errno: $errstr";
            }
        } catch (Exception $e) {
            $status['smtp_accessible'] = false;
            $status['smtp_error'] = $e->getMessage();
        }
    }

    return $status;
}

if (!function_exists('sendEmail')) {
    /**
     * Generic email sending function that handles both PHPMailer and mail() fallback
     * 
     * @param string $to Email address of recipient
     * @param string $toName Name of recipient
     * @param string $subject Email subject
     * @param string $htmlBody HTML body of the email
     * @param string $altBody Plain text alternative (optional)
     * @param array $options Additional options (optional)
     * @return bool Whether email was sent successfully
     */
    function sendEmail($to, $toName, $subject, $htmlBody, $altBody = '', $options = [])
    {
        // Get email configuration
        $mailHost = getEnvVar('MAIL_HOST');
        $mailPort = getEnvVar('MAIL_PORT');
        $mailUsername = getEnvVar('MAIL_USERNAME');
        $mailPassword = getEnvVar('MAIL_PASSWORD');
        $mailFromAddress = getEnvVar('MAIL_FROM_ADDRESS');
        $mailFromName = getEnvVar('MAIL_FROM_NAME');
        $mailEncryption = getEnvVar('MAIL_ENCRYPTION', 'tls');

        // Try to use PHPMailer if available
        if (file_exists(__DIR__ . '/../../vendor/autoload.php')) {
            require_once __DIR__ . '/../../vendor/autoload.php';

            if (class_exists('PHPMailer\PHPMailer\PHPMailer')) {
                try {
                    $mail = new \PHPMailer\PHPMailer\PHPMailer(true);

                    // Enable debug mode if specified in .env
                    $debugLevel = (int)getEnvVar('MAIL_DEBUG_LEVEL', '0');
                    if ($debugLevel > 0) {
                        $mail->SMTPDebug = $debugLevel;
                        $debugOutput = '';
                        $mail->Debugoutput = function ($str, $level) use (&$debugOutput) {
                            $debugOutput .= "$level: $str\n";
                        };
                    }

                    // Server settings
                    $mail->isSMTP();
                    $mail->Host = $mailHost;
                    $mail->SMTPAuth = true;
                    $mail->Username = $mailUsername;
                    $mail->Password = $mailPassword;
                    $mail->SMTPSecure = $mailEncryption;
                    $mail->Port = $mailPort;

                    // For Gmail, set additional options
                    if (strpos($mailHost, 'gmail.com') !== false) {
                        $mail->SMTPOptions = [
                            'ssl' => [
                                'verify_peer' => false,
                                'verify_peer_name' => false,
                                'allow_self_signed' => true
                            ]
                        ];
                    }

                    // Recipients
                    $mail->setFrom($mailFromAddress, $mailFromName);
                    $mail->addAddress($to, $toName);

                    // Set Reply-To if specified in options
                    if (isset($options['replyTo'])) {
                        $mail->addReplyTo(
                            $options['replyTo']['email'] ?? $mailFromAddress,
                            $options['replyTo']['name'] ?? $mailFromName
                        );
                    } else {
                        $mail->addReplyTo($mailFromAddress, $mailFromName);
                    }

                    // Content
                    $mail->isHTML(true);
                    $mail->Subject = $subject;
                    $mail->Body = $htmlBody;
                    $mail->AltBody = $altBody ?: strip_tags(str_replace(
                        ['<br>', '<br/>', '<br />', '</p>'],
                        "\n",
                        $htmlBody
                    ));

                    // Add custom headers if specified
                    if (isset($options['headers']) && is_array($options['headers'])) {
                        foreach ($options['headers'] as $header) {
                            $mail->addCustomHeader($header);
                        }
                    }

                    // Send the email
                    $success = $mail->send();

                    // Log debug output if enabled
                    if (isset($debugOutput) && !empty($debugOutput)) {
                        error_log("Email Debug Output:\n$debugOutput");
                    }

                    return $success;
                } catch (\Exception $e) {
                    error_log("PHPMailer Error: " . $e->getMessage());
                    if (isset($debugOutput)) {
                        error_log("Debug Output before error:\n$debugOutput");
                    }
                    // Fall back to regular mail if PHPMailer fails
                }
            }
        }

        // Fallback to regular mail() function
        $headers = [
            'MIME-Version: 1.0',
            'Content-type: text/html; charset=UTF-8',
            'From: ' . $mailFromName . ' <' . $mailFromAddress . '>',
            'Reply-To: ' . ($options['replyTo']['email'] ?? $mailFromAddress)
        ];

        // Add custom headers if specified
        if (isset($options['headers']) && is_array($options['headers'])) {
            $headers = array_merge($headers, $options['headers']);
        }

        return mail($to, $subject, $htmlBody, implode("\r\n", $headers));
    }
}
