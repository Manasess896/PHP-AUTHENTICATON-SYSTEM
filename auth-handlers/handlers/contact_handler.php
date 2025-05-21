<?php
// Include required files
require_once __DIR__ . '/../../config/env_loader.php';
require_once __DIR__ . '/../utils/email.php';
require_once __DIR__ . '/../utils/email_logger.php';

// Check if the form is submitted via POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ../../pages/contact.php?status=invalid&message=' . urlencode('Invalid request method. Please use the contact form.'));
    exit;
}

// Get real IP address - handles proxy servers and load balancers
function getRealIpAddr()
{
    $ipAddress = '';

    // Check for shared internet/ISP IP
    if (!empty($_SERVER['HTTP_CLIENT_IP']) && filter_var($_SERVER['HTTP_CLIENT_IP'], FILTER_VALIDATE_IP)) {
        $ipAddress = $_SERVER['HTTP_CLIENT_IP'];
    }
    // Check for IPs passing through proxies
    elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // Can include multiple IPs separated with comma
        $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        foreach ($ipList as $ip) {
            if (filter_var(trim($ip), FILTER_VALIDATE_IP)) {
                $ipAddress = trim($ip);
                break;
            }
        }
    }
    // Check for the remote address
    elseif (!empty($_SERVER['REMOTE_ADDR']) && filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP)) {
        $ipAddress = $_SERVER['REMOTE_ADDR'];
    }

    // If we couldn't get a valid IP, default to a placeholder
    if (empty($ipAddress)) {
        $ipAddress = 'UNKNOWN';
    }

    return $ipAddress;
}

// Get the IP address
$ipAddress = getRealIpAddr();

// Check submission rate before proceeding
$rateLimit = checkSubmissionRate($ipAddress);
if ($rateLimit !== true) {
    header('Location: ../../pages/contact.php?status=rate_limit&message=' . urlencode($rateLimit));
    exit;
}

// Validate reCAPTCHA
$recaptchaSecret = getEnvVar('RECAPTCHA_SECRET_KEY');
$recaptchaResponse = $_POST['g-recaptcha-response'] ?? '';

// If reCAPTCHA verification fails, redirect back with error
if (!verifyRecaptcha($recaptchaSecret, $recaptchaResponse)) {
    header('Location: ../../pages/contact.php?status=recaptcha_failed&message=' . urlencode('reCAPTCHA verification failed. Please try again.'));
    exit;
}

// Validate and sanitize form inputs
$name = filter_input(INPUT_POST, 'name', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
$email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
$subject = filter_input(INPUT_POST, 'subject', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
$message = filter_input(INPUT_POST, 'message', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
$consent = isset($_POST['consent']) ? true : false;

// Check if required fields are filled
if (!$name || !$email || !$subject || !$message || !$consent) {
    header('Location: ../../pages/contact.php?status=missing_fields&message=' . urlencode('Please fill all required fields.'));
    exit;
}

// Validate email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    header('Location: ../../pages/contact.php?status=invalid_email&message=' . urlencode('Please provide a valid email address.'));
    exit;
}

// Check if MongoDB extension is loaded
if (!extension_loaded('mongodb')) {
    error_log('MongoDB extension not loaded');
    header('Location: ../../pages/contact.php?status=server_error&message=' . urlencode('Server configuration error. Please try again later or contact support.'));
    exit;
}

// Get IP geolocation data
$geoData = getIpGeolocation($ipAddress);

// Check if MongoDB library is available
$mongoLibraryPath = __DIR__ . '/../vendor/autoload.php';
if (file_exists($mongoLibraryPath)) {
    // If using Composer, include the autoloader
    require_once $mongoLibraryPath;
} elseif (!class_exists('MongoDB\Client')) {
    // If MongoDB library is not available via Composer or directly
    error_log('MongoDB PHP library not found. Please install it via Composer.');
    header('Location: ../../pages/contact.php?status=server_error&message=' . urlencode('Server configuration error. Please try again later or contact support.'));
    exit;
}

// Connect to MongoDB and store contact data
try {
    // Get MongoDB connection string from environment variables
    $mongoUri = getEnvVar('MONGODB_URI');

    // Use the MongoDB\Driver\Manager directly if MongoDB\Client is not available
    if (class_exists('MongoDB\Client')) {
        // Create MongoDB client using the library
        $client = new MongoDB\Client($mongoUri);

        // Select database and collection
        $database = $client->selectDatabase('auth');
        $collection = $database->selectCollection('contacts');

        // Prepare document to insert
        $document = [
            'name' => $name,
            'email' => $email,
            'subject' => $subject,
            'message' => $message,
            'consent' => $consent,
            'ip_address' => $ipAddress,
            'ip_geolocation' => $geoData,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'created_at' => new MongoDB\BSON\UTCDateTime(microtime(true) * 1000)
        ];

        // Insert document
        $result = $collection->insertOne($document);
        $success = $result->getInsertedCount() > 0;

        // Also record this submission for rate limiting purposes
        recordSubmission($ipAddress, $client);
    } else {
        // Fallback to using the MongoDB extension directly
        $manager = new MongoDB\Driver\Manager($mongoUri);

        // Prepare the document
        $document = [
            'name' => $name,
            'email' => $email,
            'subject' => $subject,
            'message' => $message,
            'consent' => $consent,
            'ip_address' => $ipAddress,
            'ip_geolocation' => $geoData,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'created_at' => time()
        ];

        // Create a write concern
        $writeConcern = new MongoDB\Driver\WriteConcern(MongoDB\Driver\WriteConcern::MAJORITY, 1000);

        // Create a bulk write object
        $bulk = new MongoDB\Driver\BulkWrite();
        $bulk->insert($document);

        // Execute the bulk write
        $result = $manager->executeBulkWrite('auth.contacts', $bulk, $writeConcern);
        $success = $result->getInsertedCount() > 0;

        // Record this submission for rate limiting
        recordSubmissionDirect($ipAddress, $manager);
    }

    // Send email notification
    if ($success) {
        // Send email notification about the new contact submission
        $adminEmailSent = sendEmailNotification($name, $email, $subject, $message, $geoData);

        // Send confirmation email to the user
        $confirmationEmailSent = sendConfirmationEmail($name, $email, $subject, $message);

        // Set success message based on email sending status
        $successMessage = "Thank you, $name! Your message has been successfully sent.";
        if ($confirmationEmailSent) {
            $successMessage .= " We will get back to you soon .";
        }

        // Redirect with success message
        header('Location: ../../pages/contact.php?status=success&message=' . urlencode($successMessage));
        exit;
    } else {
        throw new Exception('Failed to insert document');
    }
} catch (Exception $e) {
    // Log the error
    error_log('MongoDB Error: ' . $e->getMessage());
    header('Location: ../../pages/contact.php?status=database_error&message=' . urlencode('Database error occurred. Please try again later.'));
    exit;
}

/**
 * Check submission rate to prevent DDOS attacks
 * 
 * @param string $ipAddress The IP address to check
 * @return true|string Returns true if within limits, otherwise returns error message
 */
function checkSubmissionRate($ipAddress)
{
    try {
        // Skip rate limiting for certain testing scenarios
        if ($ipAddress === 'UNKNOWN') {
            return true;
        }

        // Define rate limits
        $maxSubmissionsPerHour = 5;
        $maxSubmissionsPerDay = 20;

        // Connect to MongoDB using environment variables
        $mongoUri = getEnvVar('MONGODB_URI');

        if (class_exists('MongoDB\Client')) {
            $client = new MongoDB\Client($mongoUri);
            $collection = $client->auth->submission_logs;

            // Current time in seconds
            $now = time();
            $oneHourAgo = $now - 3600;
            $oneDayAgo = $now - 86400;

            // Count submissions in the last hour
            $hourlyCount = $collection->countDocuments([
                'ip_address' => $ipAddress,
                'timestamp' => ['$gte' => $oneHourAgo]
            ]);

            // Count submissions in the last day
            $dailyCount = $collection->countDocuments([
                'ip_address' => $ipAddress,
                'timestamp' => ['$gte' => $oneDayAgo]
            ]);

            // Check if rate limits are exceeded
            if ($hourlyCount >= $maxSubmissionsPerHour) {
                return "You've reached the limit of $maxSubmissionsPerHour submissions per hour. Please try again later.";
            }

            if ($dailyCount >= $maxSubmissionsPerDay) {
                return "You've reached the limit of $maxSubmissionsPerDay submissions per day. Please try again tomorrow.";
            }
        } else {
            // Fallback to file-based rate limiting if MongoDB client is not available
            $rateFile = sys_get_temp_dir() . '/contact_rate_' . md5($ipAddress) . '.json';

            $submissions = [];
            if (file_exists($rateFile)) {
                $submissions = json_decode(file_get_contents($rateFile), true) ?: [];
            }

            // Clean up old submissions
            $now = time();
            $submissions = array_filter($submissions, function ($timestamp) use ($now) {
                return $timestamp > ($now - 86400); // Keep only submissions from the last 24 hours
            });

            // Count recent submissions
            $hourlyCount = count(array_filter($submissions, function ($timestamp) use ($now) {
                return $timestamp > ($now - 3600); // Submissions in the last hour
            }));

            $dailyCount = count($submissions);

            // Check limits
            if ($hourlyCount >= $maxSubmissionsPerHour) {
                return "You've reached the limit of $maxSubmissionsPerHour submissions per hour. Please try again later.";
            }

            if ($dailyCount >= $maxSubmissionsPerDay) {
                return "You've reached the limit of $maxSubmissionsPerDay submissions per day. Please try again tomorrow.";
            }
        }

        return true;
    } catch (Exception $e) {
        error_log('Rate limiting error: ' . $e->getMessage());
        // If there's an error, allow the submission but log it
        return true;
    }
}

/**
 * Record a submission for rate limiting purposes using MongoDB Client
 * 
 * @param string $ipAddress The IP address to record
 * @param MongoDB\Client $client MongoDB client instance
 */
function recordSubmission($ipAddress, $client)
{
    try {
        $collection = $client->auth->submission_logs;

        $document = [
            'ip_address' => $ipAddress,
            'timestamp' => time(),
            'date' => new MongoDB\BSON\UTCDateTime(microtime(true) * 1000)
        ];

        $collection->insertOne($document);

        // Clean up old records (keep only last 30 days)
        $thirtyDaysAgo = time() - (30 * 86400);
        $collection->deleteMany([
            'timestamp' => ['$lt' => $thirtyDaysAgo]
        ]);
    } catch (Exception $e) {
        error_log('Failed to record submission: ' . $e->getMessage());
    }
}

/**
 * Record a submission using MongoDB Driver directly
 * 
 * @param string $ipAddress The IP address to record
 * @param MongoDB\Driver\Manager $manager MongoDB manager instance
 */
function recordSubmissionDirect($ipAddress, $manager)
{
    try {
        $document = [
            'ip_address' => $ipAddress,
            'timestamp' => time(),
            'date' => new MongoDB\BSON\UTCDateTime(microtime(true) * 1000)
        ];

        $bulk = new MongoDB\Driver\BulkWrite();
        $bulk->insert($document);

        $manager->executeBulkWrite('auth.submission_logs', $bulk);

        // Clean up older records using a command
        $command = new MongoDB\Driver\Command([
            'delete' => 'submission_logs',
            'deletes' => [
                [
                    'q' => ['timestamp' => ['$lt' => time() - (30 * 86400)]],
                    'limit' => 0
                ]
            ]
        ]);

        $manager->executeCommand('auth', $command);
    } catch (Exception $e) {
        error_log('Failed to record submission direct: ' . $e->getMessage());
    }
}

/**
 * Get IP geolocation data from an external API
 * 
 * @param string $ipAddress The IP address to look up
 * @return array Geolocation data
 */
function getIpGeolocation($ipAddress)
{
    // Skip lookup for localhost or private IPs
    if (
        $ipAddress == '127.0.0.1' || $ipAddress == '::1' ||
        preg_match('/^192\.168\./', $ipAddress) ||
        preg_match('/^10\./', $ipAddress)
    ) {
        return [
            'status' => 'success',
            'country' => 'Local',
            'countryCode' => 'LO',
            'region' => 'Local',
            'regionName' => 'Local Network',
            'city' => 'Local',
            'zip' => 'N/A',
            'lat' => 0,
            'lon' => 0,
            'timezone' => 'Local',
            'isp' => 'Local Network',
            'org' => 'Local',
            'as' => 'Local',
            'query' => $ipAddress
        ];
    }

    try {
        // Use ip-api.com (no API key required for basic usage)
        $url = "http://ip-api.com/json/{$ipAddress}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query";

        $options = [
            'http' => [
                'method' => 'GET',
                'header' => 'Content-type: application/json',
                'timeout' => 5 // 5 seconds timeout to avoid slowing down the page
            ]
        ];

        $context = stream_context_create($options);
        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            // If request fails, return basic info
            return ['status' => 'fail', 'query' => $ipAddress];
        }

        $data = json_decode($response, true);
        return $data ?: ['status' => 'fail', 'query' => $ipAddress];
    } catch (Exception $e) {
        error_log('IP Geolocation Error: ' . $e->getMessage());
        return ['status' => 'error', 'query' => $ipAddress, 'message' => $e->getMessage()];
    }
}

/**
 * Verify reCAPTCHA response
 *
 * @param string $secret The reCAPTCHA secret key
 * @param string $response The reCAPTCHA response from the form
 * @return bool Whether verification was successful
 */
function verifyRecaptcha($secret, $response)
{
    if (empty($response)) {
        return false;
    }

    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = [
        'secret' => $secret,
        'response' => $response,
        'remoteip' => $_SERVER['REMOTE_ADDR']
    ];

    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        ]
    ];

    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);

    if ($result === false) {
        return false;
    }

    $json = json_decode($result, true);
    return isset($json['success']) && $json['success'] === true;
}

/**
 * Send email notification about new contact form submission
 *
 * @param string $name Sender's name
 * @param string $email Sender's email
 * @param string $subject Email subject
 * @param string $message Email message
 * @param array $geoData IP geolocation data
 * @return bool Whether email was sent successfully
 */
function sendEmailNotification($name, $email, $subject, $message, $geoData = [])
{
    // Get email configuration from environment
    $mailHost = getEnvVar('MAIL_HOST');
    $mailPort = getEnvVar('MAIL_PORT');
    $mailUsername = getEnvVar('MAIL_USERNAME');
    $mailPassword = getEnvVar('MAIL_PASSWORD');
    $mailFromAddress = getEnvVar('MAIL_FROM_ADDRESS');
    $mailFromName = getEnvVar('MAIL_FROM_NAME');

    $to = $mailUsername;
    $emailSubject = "New Contact Form Submission: $subject";

    $emailBody = "<html><body>";
    $emailBody .= "<h2>New Contact Form Submission</h2>";
    $emailBody .= "<p><strong>Name:</strong> " . htmlspecialchars($name) . "</p>";
    $emailBody .= "<p><strong>Email:</strong> " . htmlspecialchars($email) . "</p>";
    $emailBody .= "<p><strong>Subject:</strong> " . htmlspecialchars($subject) . "</p>";
    $emailBody .= "<p><strong>Message:</strong></p>";
    $emailBody .= "<p>" . nl2br(htmlspecialchars($message)) . "</p>";

    // Add geolocation data if available
    if (!empty($geoData) && isset($geoData['status']) && $geoData['status'] === 'success') {
        $emailBody .= "<h3>User Location Information</h3>";
        $emailBody .= "<p><strong>IP Address:</strong> " . htmlspecialchars($geoData['query'] ?? 'Unknown') . "</p>";
        $emailBody .= "<p><strong>Location:</strong> " .
            htmlspecialchars($geoData['city'] ?? 'Unknown') . ", " .
            htmlspecialchars($geoData['regionName'] ?? 'Unknown') . ", " .
            htmlspecialchars($geoData['country'] ?? 'Unknown') . " (" .
            htmlspecialchars($geoData['countryCode'] ?? 'Unknown') . ")</p>";
        $emailBody .= "<p><strong>ISP:</strong> " . htmlspecialchars($geoData['isp'] ?? 'Unknown') . "</p>";
        $emailBody .= "<p><strong>Timezone:</strong> " . htmlspecialchars($geoData['timezone'] ?? 'Unknown') . "</p>";

        // Add a map link if coordinates are available
        if (isset($geoData['lat']) && isset($geoData['lon'])) {
            $mapUrl = "https://www.google.com/maps?q={$geoData['lat']},{$geoData['lon']}";
            $emailBody .= "<p><a href=\"{$mapUrl}\" target=\"_blank\">View on Google Maps</a></p>";
        }
    }

    $emailBody .= "<p><em>Submitted on: " . date('Y-m-d H:i:s') . "</em></p>";
    $emailBody .= "</body></html>";

    // Headers
    $headers = "MIME-Version: 1.0\r\n";
    $headers .= "Content-type: text/html; charset=UTF-8\r\n";
    $headers .= "From: " . $mailFromName . " <" . $mailFromAddress . ">\r\n";
    $headers .= "Reply-To: " . $email . "\r\n";

    // Send email
    return mail($to, $emailSubject, $emailBody, $headers);
}

// Include email utility functions
require_once __DIR__ . '/../../auth-handlers/utils/email.php';

/**
 * Send confirmation email to the person who submitted the contact form
 *
 * @param string $name Recipient's name
 * @param string $email Recipient's email
 * @param string $subject Original subject from the form
 * @param string $originalMessage Original message from the form
 * @return bool Whether email was sent successfully
 */
function sendConfirmationEmail($name, $email, $subject, $originalMessage)
{
    // Get email configuration
    $mailFromName = getEnvVar('MAIL_FROM_NAME');
    $mailFromAddress = getEnvVar('MAIL_FROM_ADDRESS');

    $emailSubject = "Thank you for contacting us - " . $subject;

    // Create the email body
    $emailBody = "<html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { text-align: center; padding: 20px; }
            .content { background-color: #f9f9f9; padding: 20px; border-radius: 5px; }
            .message-box { background-color: #fff; padding: 15px; border-radius: 5px; margin: 15px 0; }
            .footer { text-align: center; padding: 20px; font-size: 0.9em; color: #666; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h2>Message Received</h2>
            </div>
            <div class='content'>
                <p>Dear " . htmlspecialchars($name) . ",</p>
                <p>Thank you for reaching out to us. We have received your message and will respond as soon as possible.</p>
                <p>Here's a copy of the message you submitted:</p>
                <div class='message-box'>
                    <p><strong>Subject:</strong> " . htmlspecialchars($subject) . "</p>
                    <p><strong>Message:</strong><br>" . nl2br(htmlspecialchars($originalMessage)) . "</p>
                </div>
                <p>If you have any additional information to share, please reply to this email.</p>
                <p>Best regards,<br>The " . htmlspecialchars($mailFromName) . " Team</p>
            </div>
            <div class='footer'>
                <p>This is an automated confirmation. Your message has been received and we will get back to you soon.</p>
            </div>
        </div>
    </body>
    </html>";

    // Log the email attempt
    logEmailActivity(
        "CONTACT_CONFIRMATION_EMAIL",
        [
            'to' => $email,
            'name' => $name,
            'subject' => $subject
        ],
        'INFO',
        'Attempting to send contact form confirmation email'
    );

    // Send the email using the standardized email function
    $emailSent = sendEmail(
        $email,
        $name,
        $emailSubject,
        $emailBody
    );

    // Log the result
    if ($emailSent) {
        logEmailActivity(
            "CONTACT_CONFIRMATION_EMAIL",
            ['to' => $email],
            'SUCCESS',
            'Contact form confirmation email sent successfully'
        );
    } else {
        logEmailActivity(
            "CONTACT_CONFIRMATION_EMAIL",
            ['to' => $email],
            'ERROR',
            'Failed to send contact form confirmation email'
        );
    }

    return $emailSent;
}
