<?php

/**
 * reCAPTCHA Logger
 * 
 * Utility for logging reCAPTCHA verification details to help with troubleshooting
 */

/**
 * Log reCAPTCHA verification details to a dedicated log file
 * 
 * @param string $message The message to log
 * @param mixed $data Optional data to include in the log
 * @return bool Success status
 */
function logRecaptcha($message, $data = null)
{
    // Check if logging is enabled
    if (!isLoggingEnabled()) {
        return true;
    }

    // Ensure logs directory exists
    $logsDir = __DIR__ . '/../logs';
    if (!is_dir($logsDir)) {
        mkdir($logsDir, 0755, true);
    }

    // Path to the log file
    $logFile = $logsDir . '/recaptcha.log';

    // Format the log entry
    $timestamp = date('Y-m-d H:i:s');
    $remoteIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

    // Start building log entry
    $logEntry = "[{$timestamp}] [{$remoteIp}] {$message}";

    // Add data if provided
    if ($data !== null) {
        if (is_array($data) || is_object($data)) {
            // Mask any sensitive data before logging
            $sanitizedData = maskSensitiveData($data);
            $logEntry .= " - Data: " . json_encode($sanitizedData, JSON_UNESCAPED_SLASHES);
        } else {
            $logEntry .= " - Data: {$data}";
        }
    }

    // Add user agent at the end
    $logEntry .= " - UA: {$userAgent}";

    // Append to log file
    $result = file_put_contents($logFile, $logEntry . PHP_EOL, FILE_APPEND | LOCK_EX);

    return ($result !== false);
}

/**
 * Mask sensitive data in arrays or objects
 * 
 * @param mixed $data Data to sanitize
 * @return mixed Sanitized data
 */
function maskSensitiveData($data)
{
    if (!is_array($data) && !is_object($data)) {
        return $data;
    }

    $sensitiveKeys = ['token', 'key', 'secret', 'password', 'pwd', 'auth', 'credential'];
    $result = is_object($data) ? clone $data : $data;

    foreach ($result as $key => &$value) {
        // Check if the key contains any sensitive words
        $isKeySensitive = false;
        foreach ($sensitiveKeys as $sensitiveKey) {
            if (stripos($key, $sensitiveKey) !== false) {
                $isKeySensitive = true;
                break;
            }
        }

        if ($isKeySensitive && is_string($value)) {
            // Mask the value if the key is sensitive
            $value = strlen($value) > 4 ? '***' . substr($value, -4) : '******';
        } elseif (is_array($value) || is_object($value)) {
            // Recursively mask nested arrays/objects
            $value = maskSensitiveData($value);
        }
    }

    return $result;
}

/**
 * Clean up old log entries to prevent the log file from growing too large
 * 
 * @param int $maxLines Maximum number of lines to keep
 * @return bool Success status
 */
function cleanRecaptchaLogs($maxLines = 1000)
{
    $logFile = __DIR__ . '/../logs/recaptcha.log';

    // Check if file exists and is larger than 1MB
    if (file_exists($logFile) && filesize($logFile) > (1 * 1024 * 1024)) {
        // Read the last N lines
        $lines = file($logFile);
        if (count($lines) > $maxLines) {
            $lines = array_slice($lines, -$maxLines);
            file_put_contents($logFile, implode('', $lines), LOCK_EX);
        }
    }

    return true;
}
