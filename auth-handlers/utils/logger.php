<?php

/**
 * Logger utility
 * Provides consistent logging functionality across the application
 */

// Function to check if logging is enabled
if (!function_exists('isLoggingEnabled')) {
    function isLoggingEnabled()
    {
        // Default to false if not set
        return filter_var(getEnvVar('ENABLE_LOGGING', 'false'), FILTER_VALIDATE_BOOLEAN);
    }
}

if (!function_exists('logMessage')) {
    /**
     * Log a message to a specific log file with timestamp
     *
     * @param string $message Message to log
     * @param string $logFile Path to log file
     * @param array|null $data Additional data to include in JSON format
     * @param string $level Log level (INFO, WARNING, ERROR, DEBUG)
     * @return bool Whether log was successful
     */
    function logMessage($message, $logFile = null, $data = null, $level = 'INFO')
    {
        // If logging is disabled, return true without doing anything
        if (!isLoggingEnabled()) {
            return true;
        }

        // Create logs directory if it doesn't exist
        $logDir = __DIR__ . '/../logs';
        if (!file_exists($logDir)) {
            mkdir($logDir, 0755, true);
        }

        // Default log file
        if ($logFile === null) {
            $logFile = $logDir . '/app.log';
        } else if (!preg_match('~^/|^[a-zA-Z]:~', $logFile)) {
            // If not an absolute path, prepend logs directory
            $logFile = $logDir . '/' . $logFile;
        }

        // Format timestamp
        $timestamp = date('Y-m-d H:i:s');

        // Format log entry
        $logEntry = "[$timestamp] [$level] $message";

        // Add data if provided
        if ($data !== null) {
            if (is_array($data) || is_object($data)) {
                try {
                    // Mask sensitive data
                    $dataCopy = json_decode(json_encode($data), true); // Convert to array
                    if (is_array($dataCopy)) {
                        foreach ($dataCopy as $key => $value) {
                            if (in_array(strtolower($key), ['password', 'token', 'secret', 'key'])) {
                                $dataCopy[$key] = '[REDACTED]';
                            }
                        }
                    }
                    $logEntry .= " - " . json_encode($dataCopy, JSON_UNESCAPED_SLASHES);
                } catch (Exception $e) {
                    $logEntry .= " - Error encoding data: " . $e->getMessage();
                }
            } else {
                $logEntry .= " - $data";
            }
        }

        // Add newline
        $logEntry .= PHP_EOL;

        // Write to log file
        $result = file_put_contents($logFile, $logEntry, FILE_APPEND);

        // Also log to PHP error log for critical items
        if (in_array($level, ['ERROR', 'WARNING'])) {
            error_log("$level: $message");
        }

        return $result !== false;
    }
}

if (!function_exists('logError')) {
    /**
     * Log an error message
     *
     * @param string $message Error message
     * @param array|null $data Additional data
     * @param string $logFile Path to log file
     * @return bool Whether log was successful
     */
    function logError($message, $data = null, $logFile = 'errors.log')
    {
        return logMessage($message, $logFile, $data, 'ERROR');
    }
}

if (!function_exists('logInfo')) {
    /**
     * Log an info message
     *
     * @param string $message Info message
     * @param array|null $data Additional data
     * @param string $logFile Path to log file
     * @return bool Whether log was successful
     */
    function logInfo($message, $data = null, $logFile = 'app.log')
    {
        return logMessage($message, $logFile, $data, 'INFO');
    }
}

if (!function_exists('logDebug')) {
    /**
     * Log a debug message
     *
     * @param string $message Debug message
     * @param array|null $data Additional data
     * @param string $logFile Path to log file
     * @return bool Whether log was successful
     */
    function logDebug($message, $data = null, $logFile = 'debug.log')
    {
        if (getEnvVar('APP_DEBUG', 'false') !== 'true') {
            return true; // Skip debug logging if not in debug mode
        }
        return logMessage($message, $logFile, $data, 'DEBUG');
    }
}

if (!function_exists('logRegistration')) {
    /**
     * Log registration related activities
     * 
     * @param string $message Log message
     * @param array|null $data Additional data to log
     * @param string $level Log level (INFO, WARNING, ERROR)
     * @return bool Whether log was successful
     */
    function logRegistration($message, $data = null, $level = 'INFO')
    {
        return logMessage(
            $message,
            'registration.log',
            $data,
            $level
        );
    }
}

// Add new function for auth logging
if (!function_exists('logAuth')) {
    /**
     * Log authentication related messages (login, logout, password reset)
     *
     * @param string $message Message to log
     * @param array|null $data Additional data
     * @param string $level Log level
     * @return bool Whether log was successful
     */
    function logAuth($message, $data = null, $level = 'INFO')
    {
        return logMessage($message, 'authentication.log', $data, $level);
    }
}

if (!function_exists('logDatabase')) {
    /**
     * Log database related messages
     *
     * @param string $message Message to log
     * @param array|null $data Additional data
     * @param string $level Log level
     * @return bool Whether log was successful
     */
    function logDatabase($message, $data = null, $level = 'INFO')
    {
        return logMessage($message, 'database.log', $data, $level);
    }
}
