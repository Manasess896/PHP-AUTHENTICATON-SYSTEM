<?php

/**
 * Rate Limiter Utility
 * 
 * A MongoDB-based rate limiting implementation with configuration.
 */

// Include required files
require_once __DIR__ . '/../../config/env_loader.php';
require_once __DIR__ . '/../../config/database.php';

// Rate limiting configuration
$RATE_LIMITS = [
    // Registration rate limits (attempts per window)
    'registration' => [
        'max_attempts' => getEnvVar('MAX_REGISTRATION_ATTEMPTS', 5),
        'window' => getEnvVar('REGISTRATION_TIME_WINDOW', 3600), // 1 hour in seconds
    ],

    // Login rate limits
    'login' => [
        'max_attempts' => getEnvVar('MAX_LOGIN_ATTEMPTS', 10),
        'window' => getEnvVar('LOGIN_TIME_WINDOW', 900), // 15 minutes
        // More restrictive rate limit after failed attempts
        'throttle' => [
            'max_attempts' => 3,
            'window' => 1800, // 30 minutes
        ]
    ],

    // Password reset rate limits
    'password_reset' => [
        'max_attempts' => getEnvVar('MAX_PASSWORD_RESET_ATTEMPTS', 3),
        'window' => getEnvVar('PASSWORD_RESET_TIME_WINDOW', 3600), // 1 hour
    ],

    // Verification email resend rate limits
    'resend_verification' => [
        'max_attempts' => getEnvVar('MAX_RESEND_ATTEMPTS', 3),
        'window' => getEnvVar('RESEND_TIME_WINDOW', 1800), // 30 minutes
    ],

    // API rate limits (if applicable)
    'api' => [
        'max_attempts' => getEnvVar('API_MAX_REQUESTS', 60),
        'window' => getEnvVar('API_TIME_WINDOW', 60), // 1 minute (60 req/min)
    ],

    // Global IP-based rate limit to prevent DoS
    'global' => [
        'max_attempts' => getEnvVar('GLOBAL_MAX_REQUESTS', 300),
        'window' => getEnvVar('GLOBAL_TIME_WINDOW', 60), // 1 minute
    ],
];

/**
 * Get rate limit configuration for a specific action
 * 
 * @param string $action The action to get rate limits for (e.g., 'login', 'registration')
 * @return array Rate limit configuration with max_attempts and window
 */
function getRateLimitConfig($action)
{
    global $RATE_LIMITS;
    return $RATE_LIMITS[$action] ?? [
        'max_attempts' => 5,
        'window' => 60
    ];
}

/**
 * Ensure rate limits collection exists with proper indexes
 * 
 * @param MongoDB\Database $db Database instance
 * @return MongoDB\Collection The rate limits collection
 */
function ensureRateLimitsCollection($db)
{
    try {
        $collection = $db->selectCollection('rate_limits');

        // Create TTL index if it doesn't exist
        $collection->createIndex(
            ['last_attempt' => 1],
            [
                'expireAfterSeconds' => 86400, // Clean up after 24 hours
                'background' => true
            ]
        );

        // Create index on key field
        $collection->createIndex(
            ['key' => 1],
            ['background' => true]
        );

        return $collection;
    } catch (Exception $e) {
        error_log('Failed to ensure rate limits collection: ' . $e->getMessage());
        throw $e;
    }
}

/**
 * Check if a rate limit has been exceeded
 * 
 * @param string $key Unique identifier for the rate limit (e.g., IP address, username)
 * @param int $maxAttempts Maximum allowed attempts within the time window
 * @param int $timeWindowSeconds Time window in seconds
 * @return bool True if rate limit exceeded, false otherwise
 */
function isRateLimited($key, $maxAttempts = 5, $timeWindowSeconds = 60)
{
    try {
        $db = getDatabaseConnection();
        if (!$db) {
            error_log('Failed to get database connection in rate limiter');
            return false; // Allow operation if DB is down
        }
        $now = time();
        $collection = $db->selectCollection('rate_limits');

        // Create indexes if they don't exist
        try {
            $collection->createIndex(['key' => 1], ['background' => true]);
            $collection->createIndex(
                ['last_attempt' => 1],
                ['expireAfterSeconds' => 86400, 'background' => true]
            );
        } catch (Exception $e) {
            error_log('Failed to create indexes: ' . $e->getMessage());
            // Continue even if index creation fails
        }

        // First, find or create the document
        $doc = $collection->findOne(['key' => $key]);

        if (!$doc) {
            // If document doesn't exist, create it with an empty attempts array
            $collection->insertOne([
                'key' => $key,
                'attempts' => [],
                'created_at' => $now,
                'last_attempt' => $now
            ]);
        }        // Check if attempts field is an integer and convert it to array if needed
        $collection->updateOne(
            [
                'key' => $key,
                'attempts' => ['$exists' => true, '$type' => 'int']
            ],
            [
                '$set' => ['attempts' => []]
            ]
        );

        // First clean up old attempts - only if attempts exists and is an array
        $collection->updateOne(
            [
                'key' => $key,
                'attempts' => ['$exists' => true, '$type' => 'array']
            ],
            [
                '$pull' => [
                    'attempts' => ['$lt' => $now - $timeWindowSeconds]
                ]
            ]
        );

        // Then add new attempt in a separate operation
        $result = $collection->findOneAndUpdate(
            ['key' => $key],
            [
                '$push' => ['attempts' => $now],
                '$set' => ['last_attempt' => $now]
            ],
            [
                'returnDocument' => MongoDB\Operation\FindOneAndUpdate::RETURN_DOCUMENT_AFTER,
                'upsert' => false
            ]
        );

        if (!$result) {
            error_log("Rate limit check failed for key: $key");
            return false;
        }

        $attemptCount = count($result['attempts'] ?? []);
        $isLimited = $attemptCount > $maxAttempts;

        if ($isLimited) {
            error_log("Rate limit exceeded for key: $key. Attempts: $attemptCount, Max: $maxAttempts");
        }

        return $isLimited;
    } catch (Exception $e) {
        error_log("Rate limit error: " . $e->getMessage() . "\nTrace: " . $e->getTraceAsString());
        return false; // Fail open to not block users if there's an error
    }
}

/**
 * Get remaining attempts for a rate limited resource
 * 
 * @param string $key Unique identifier for the rate limit
 * @param int $maxAttempts Maximum allowed attempts within the time window
 * @param int $timeWindowSeconds Time window in seconds
 * @return int Number of attempts remaining
 */
function getRemainingAttempts($key, $maxAttempts = 5, $timeWindowSeconds = 60)
{
    try {
        $db = getDatabaseConnection();
        if (!$db) {
            error_log('Failed to get database connection in getRemainingAttempts');
            return 0;
        }
        // Check if the returned object is already a database object
        if ($db instanceof MongoDB\Database) {
            $collection = $db->selectCollection('rate_limits');
        } else {
            // Else get a database object first
            $collection = $db->selectDatabase('auth')->selectCollection('rate_limits');
        }
        $now = time();

        // Find document and clean up expired attempts
        $result = $collection->findOneAndUpdate(
            ['key' => $key],
            ['$pull' => ['attempts' => ['$lt' => $now - $timeWindowSeconds]]],
            ['returnDocument' => MongoDB\Operation\FindOneAndUpdate::RETURN_DOCUMENT_AFTER]
        );

        if (!$result) {
            return $maxAttempts;
        }

        $validAttempts = count($result['attempts'] ?? []);
        return max(0, $maxAttempts - $validAttempts);
    } catch (Exception $e) {
        error_log("Rate limit error in getRemainingAttempts: " . $e->getMessage());
        return 0; // Conservative approach on error
    }
}

/**
 * Get the number of seconds until a user can try again
 * 
 * @param string $key Unique identifier for the rate limit
 * @param int $timeWindowSeconds Time window in seconds
 * @return int Number of seconds until retry is allowed
 */
function getSecondsUntilRetry($key, $timeWindowSeconds = 60)
{
    try {
        $db = getDatabaseConnection();
        if (!$db) {
            error_log('Failed to get database connection in getSecondsUntilRetry');
            return 0;
        }
        // Check if the returned object is already a database object
        if ($db instanceof MongoDB\Database) {
            $collection = $db->selectCollection('rate_limits');
        } else {
            // Else get a database object first
            $collection = $db->selectDatabase('auth')->selectCollection('rate_limits');
        }
        $result = $collection->findOne(['key' => $key]);
        if (!$result || empty($result['attempts'])) {
            return 0;
        }
        $now = time();
        $oldestAttempt = min($result['attempts']);
        $resetTime = $oldestAttempt + $timeWindowSeconds;
        return max(0, $resetTime - $now);
    } catch (\Exception $e) {
        error_log("Rate limit error: " . $e->getMessage());
        return 0;
    }
}

/**
 * Enforce rate limit and return appropriate HTTP response if limit is exceeded
 * 
 * @param string $key Unique identifier for the rate limit
 * @param int $maxAttempts Maximum allowed attempts within the time window
 * @param int $timeWindowSeconds Time window in seconds
 * @param string $message Custom message for rate limit exceeded (optional)
 * @return bool True if rate limit is not exceeded, false if exceeded and response sent
 */
function enforceRateLimit($key, $maxAttempts = 5, $timeWindowSeconds = 60, $message = null)
{
    if (isRateLimited($key, $maxAttempts, $timeWindowSeconds)) {
        $secondsLeft = getSecondsUntilRetry($key, $timeWindowSeconds);

        // Set rate limit headers
        header('HTTP/1.1 429 Too Many Requests');
        header('Retry-After: ' . $secondsLeft);
        header('X-RateLimit-Limit: ' . $maxAttempts);
        header('X-RateLimit-Remaining: 0');
        header('X-RateLimit-Reset: ' . (time() + $secondsLeft));

        // Output rate limit message
        if ($message === null) {
            $message = "Rate limit exceeded. Please try again in {$secondsLeft} seconds.";
        }

        // Return JSON if the request accepts JSON
        if (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
            header('Content-Type: application/json');
            echo json_encode([
                'error' => 'too_many_requests',
                'message' => $message,
                'retry_after' => $secondsLeft
            ]);
        } else {
            // HTML response
            echo '<!DOCTYPE html>
            <html>
            <head>
                <title>Rate Limit Exceeded</title>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; padding: 20px; max-width: 600px; margin: 0 auto; }
                    .error-container { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 20px; border-radius: 5px; }
                    h1 { margin-top: 0; font-size: 24px; }
                </style>
            </head>
            <body>
                <div class="error-container">
                    <h1>Rate Limit Exceeded</h1>
                    <p>' . htmlspecialchars($message) . '</p>
                    <p>You can try again in <span id="countdown">' . $secondsLeft . '</span> seconds.</p>
                </div>
                <script>
                    // Simple countdown timer
                    let seconds = ' . $secondsLeft . ';
                    const countdownEl = document.getElementById("countdown");
                    const timer = setInterval(() => {
                        seconds--;
                        countdownEl.textContent = seconds;
                        if (seconds <= 0) {
                            clearInterval(timer);
                            location.reload();
                        }
                    }, 1000);
                </script>
            </body>
            </html>';
        }

        return false;
    }

    // Set informational rate limit headers
    header('X-RateLimit-Limit: ' . $maxAttempts);
    header('X-RateLimit-Remaining: ' . getRemainingAttempts($key, $maxAttempts, $timeWindowSeconds));

    return true;
}

/**
 * Enforce rate limit for a specific action using its configuration
 * 
 * @param string $action The action to rate limit (e.g., 'login', 'registration')
 * @param string $key Unique identifier for the rate limit
 * @param string $message Custom message for rate limit exceeded (optional)
 * @return bool True if rate limit is not exceeded, false if exceeded and response sent
 */
function enforceActionRateLimit($action, $key, $message = null)
{
    $config = getRateLimitConfig($action);
    return enforceRateLimit(
        "{$action}:{$key}",
        $config['max_attempts'],
        $config['window'],
        $message
    );
}
