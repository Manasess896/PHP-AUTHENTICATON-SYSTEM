<?php

/**
 * Email Logger
 * 
 * This utility provides specialized logging for email operations
 * allowing for better debugging of email verification issues.
 */

// Ensure config is loaded
if (!function_exists('getEnvVar')) {
    require_once __DIR__ . '/../../config/env_loader.php';
}

// Include email.php for checkMailConfiguration function
if (!function_exists('checkMailConfiguration')) {
    require_once __DIR__ . '/email.php';
}

// Only define logEmailActivity if it doesn't already exist
if (!function_exists('logEmailActivity')) {
    /**
     * Log email activity to a dedicated log file
     * 
     * @param string $action The email action being performed
     * @param array $data Associated data (recipient, subject, etc.)
     * @param string $result The outcome of the email operation
     * @param string $message Additional message details
     * @return bool Whether logging was successful
     */    function logEmailActivity($action, $data = [], $result = 'INFO', $message = '')
    {
        // Check if logging is enabled
        if (!isLoggingEnabled()) {
            return true;
        }

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
        $success = file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);

        return ($success !== false);
    }
}

/**
 * Get the most recent email log entries
 * 
 * @param int $lines Number of recent lines to retrieve
 * @param string $email Optional filter for specific email address
 * @return array Array of log entries
 */
function getRecentEmailLogs($lines = 20, $email = null)
{
    $logFile = __DIR__ . '/../logs/email.log';
    if (!file_exists($logFile)) {
        return ['No email logs found'];
    }

    // Get log content
    $logContent = file($logFile);

    // Filter by email if provided
    if ($email) {
        $filteredLogs = [];
        foreach ($logContent as $line) {
            if (strpos($line, $email) !== false) {
                $filteredLogs[] = $line;
            }
        }
        $logContent = $filteredLogs;
    }

    // Get the last X lines
    $logContent = array_slice($logContent, -$lines);

    return $logContent;
}

/**
 * Analyze email logs for issues related to a specific email
 * 
 * @param string $email The email address to analyze
 * @return array Analysis results with potential issues and recommendations
 */
function analyzeEmailIssues($email)
{
    $logs = getRecentEmailLogs(50, $email);
    $result = [
        'found' => !empty($logs),
        'attempts' => 0,
        'successes' => 0,
        'failures' => 0,
        'last_attempt' => null,
        'issues' => [],
        'recommendations' => []
    ];

    if (empty($logs) || (count($logs) === 1 && $logs[0] === 'No email logs found')) {
        $result['issues'][] = 'No email logs found for this address';
        $result['recommendations'][] = 'Check if the correct email address was entered during registration';
        return $result;
    }

    // Process logs
    foreach ($logs as $log) {
        if (strpos($log, 'Attempting to send') !== false) {
            $result['attempts']++;
            $result['last_attempt'] = extractTimestamp($log);
        }

        if (strpos($log, 'successfully sent') !== false || strpos($log, 'SUCCESS') !== false) {
            $result['successes']++;
        }

        if (strpos($log, 'Failed to send') !== false || strpos($log, 'ERROR') !== false) {
            $result['failures']++;

            // Extract specific error types
            if (strpos($log, 'smtp') !== false) {
                $result['issues'][] = 'SMTP configuration issue detected';
                $result['recommendations'][] = 'Check SMTP server settings in .env file';
            } elseif (strpos($log, 'mail function') !== false) {
                $result['issues'][] = 'PHP mail() function issue detected';
                $result['recommendations'][] = 'Ensure PHP mail function is enabled on the server';
            }
        }
    }

    // Add default recommendations if no specific issues found
    if (empty($result['issues']) && $result['failures'] > 0) {
        $result['issues'][] = 'General email delivery failures detected';
        $result['recommendations'][] = 'Check server mail configuration or use an SMTP service';
    }

    // Use the email.php checkMailConfiguration function if available
    // But avoid requiring that file to prevent circular inclusion
    if (function_exists('checkMailConfiguration')) {
        $mailConfig = checkMailConfiguration();
        if (!empty($mailConfig)) {
            $driver = $mailConfig['driver'] ?? null;

            if (isset($mailConfig['mail_function_available']) && !$mailConfig['mail_function_available']) {
                $result['issues'][] = 'PHP mail() function is not available';
                $result['recommendations'][] = 'Configure an SMTP service in .env file';
            }

            if (isset($mailConfig['smtp_accessible']) && !$mailConfig['smtp_accessible']) {
                $result['issues'][] = 'SMTP server is not accessible';
                $result['recommendations'][] = 'Check SMTP server address and port in .env file';
            }
        }
    }

    return $result;
}

/**
 * Extract timestamp from log entry
 */
function extractTimestamp($logEntry)
{
    if (preg_match('/\[([\d-]+ [\d:]+)\]/', $logEntry, $matches)) {
        return $matches[1];
    }
    return null;
}
