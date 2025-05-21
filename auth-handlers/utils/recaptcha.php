<?php

/**
 * reCAPTCHA verification utilities
 */

if (!function_exists('verifyRecaptcha')) {
    /**
     * Verify reCAPTCHA response
     * 
     * @param string $recaptchaResponse The g-recaptcha-response from the form
     * @return bool Whether verification was successful
     * @throws Exception If there's an error in the verification process
     */
    function verifyRecaptcha($recaptchaResponse)
    {
        // Get the reCAPTCHA secret key from environment
        $secretKey = getEnvVar('RECAPTCHA_SECRET_KEY');

        // Log debug info with better masking
        $maskedKey = !empty($secretKey) ? substr($secretKey, 0, 3) . '...' . substr($secretKey, -3) : 'MISSING';
        error_log("Verifying reCAPTCHA with secret key: $maskedKey");
        error_log("reCAPTCHA response length: " . strlen($recaptchaResponse));

        // If no secret key is set or response is empty, fail verification
        if (empty($secretKey)) {
            error_log("reCAPTCHA verification failed: No secret key provided");

            // If we're in development mode, allow bypass of reCAPTCHA
            if (getEnvVar('APP_ENV', 'development') === 'development' && getEnvVar('RECAPTCHA_BYPASS', 'true') === 'true') {
                error_log("reCAPTCHA bypassed in development mode");
                return true;
            }

            throw new Exception("reCAPTCHA configuration error: No secret key");
        }

        if (empty($recaptchaResponse)) {
            error_log("reCAPTCHA verification failed: Empty response");

            // Development bypass
            if (getEnvVar('APP_ENV', 'development') === 'development' && getEnvVar('RECAPTCHA_BYPASS', 'true') === 'true') {
                error_log("reCAPTCHA bypassed in development mode");
                return true;
            }

            return false;
        }

        // Prepare the request data
        $verifyUrl = 'https://www.google.com/recaptcha/api/siteverify';
        $data = [
            'secret' => $secretKey,
            'response' => $recaptchaResponse,
            'remoteip' => $_SERVER['REMOTE_ADDR'] ?? null
        ];

        error_log("Sending reCAPTCHA verification request to Google");

        // Use cURL if available, otherwise use file_get_contents
        if (function_exists('curl_version')) {
            $ch = curl_init($verifyUrl);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
            curl_setopt($ch, CURLOPT_USERAGENT, 'PHP reCAPTCHA Client');
            $response = curl_exec($ch);

            if ($response === false) {
                $error = curl_error($ch);
                curl_close($ch);
                error_log("cURL error in reCAPTCHA verification: $error");
                throw new Exception("Error contacting reCAPTCHA server: $error");
            }

            curl_close($ch);
        } else {
            $options = [
                'http' => [
                    'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                    'method' => 'POST',
                    'content' => http_build_query($data),
                    'timeout' => 10
                ]
            ];
            $context = stream_context_create($options);

            $response = @file_get_contents($verifyUrl, false, $context);

            if ($response === false) {
                $error = error_get_last();
                error_log("file_get_contents error in reCAPTCHA verification: " . ($error ? $error['message'] : "Unknown error"));
                throw new Exception("Error contacting reCAPTCHA server. Please try again later.");
            }
        }

        // Parse the response
        $result = json_decode($response, true);

        error_log("reCAPTCHA verification response received: " . json_encode($result));

        // Log verification result
        if (isset($result['success'])) {
            if ($result['success']) {
                error_log("reCAPTCHA verification successful");
            } else {
                $errorCodes = isset($result['error-codes']) ? implode(', ', $result['error-codes']) : 'unknown';
                error_log("reCAPTCHA verification failed: $errorCodes");
            }
        } else {
            error_log("reCAPTCHA verification failed: Invalid response format");
            return false;
        }

        // For development environments, allow bypass if enabled
        if (!isset($result['success']) || $result['success'] !== true) {
            if (getEnvVar('APP_ENV', 'development') === 'development' && getEnvVar('RECAPTCHA_BYPASS', 'true') === 'true') {
                error_log("reCAPTCHA verification bypassed in development mode despite failure");
                return true;
            }
        }

        return isset($result['success']) && $result['success'] === true;
    }
}

/**
 * Get the site key for embedding reCAPTCHA in forms
 * 
 * @return string The reCAPTCHA site key
 */
function getRecaptchaSiteKey()
{
    return getEnvVar('RECAPTCHA_SITE_KEY', '');
}

// If getEnvVar function doesn't exist yet, define it
if (!function_exists('getEnvVar')) {
    /**
     * Get environment variable from .env file or system environment
     * 
     * @param string $key The environment variable name
     * @param string $default Default value if not found
     * @return string The environment variable value
     */
    function getEnvVar($key, $default = '')
    {
        // Check if the function is already defined elsewhere
        if (function_exists('getEnvVar') && !function_exists('_getEnvVar')) {
            return getEnvVar($key, $default);
        }

        // Try to load from environment variables
        if (isset($_ENV[$key])) {
            return $_ENV[$key];
        }

        if (isset($_SERVER[$key])) {
            return $_SERVER[$key];
        }

        // Check .env file if it exists
        $envFile = __DIR__ . '/../.env';
        if (file_exists($envFile)) {
            $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                if (strpos(trim($line), '#') === 0) continue; // Skip comments

                if (strpos($line, '=') !== false) {
                    list($envKey, $envValue) = explode('=', $line, 2);
                    $envKey = trim($envKey);
                    $envValue = trim($envValue);

                    // Remove quotes if present
                    $envValue = trim($envValue, '"\'');

                    if ($envKey === $key) {
                        return $envValue;
                    }
                }
            }
        }

        return $default;
    }
}

/**
 * reCAPTCHA Validation Utility
 * 
 * Functions for validating Google reCAPTCHA responses
 */

/**
 * Validate reCAPTCHA response
 * @param string $recaptchaResponse The g-recaptcha-response from the form
 * @return bool True if validation passes, false otherwise
 */
function validateRecaptcha($recaptchaResponse)
{
    // Skip validation if in development mode and reCAPTCHA is disabled
    if (getEnvVar('RECAPTCHA_DISABLED', false) === 'true') {
        error_log('reCAPTCHA validation skipped: RECAPTCHA_DISABLED is set to true');
        return true;
    }

    // Return false if response is empty
    if (empty($recaptchaResponse)) {
        error_log('reCAPTCHA validation failed: Empty response');
        return false;
    }

    // Get reCAPTCHA secret key from environment
    $secretKey = getEnvVar('RECAPTCHA_SECRET_KEY');

    // If secret key is not set, log error and fail validation
    if (empty($secretKey)) {
        error_log('reCAPTCHA validation failed: Missing secret key');
        return false;
    }

    try {
        // Prepare request to Google reCAPTCHA API
        $url = 'https://www.google.com/recaptcha/api/siteverify';
        $data = [
            'secret' => $secretKey,
            'response' => $recaptchaResponse,
            'remoteip' => $_SERVER['REMOTE_ADDR']
        ];

        // Use cURL if available
        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

            $response = curl_exec($ch);
            $error = curl_error($ch);
            curl_close($ch);

            if ($error) {
                error_log('reCAPTCHA cURL error: ' . $error);
                return false;
            }
        } else {
            // Fall back to file_get_contents if cURL is not available
            $options = [
                'http' => [
                    'header' => "Content-type: application/x-www-form-urlencoded\r\n",
                    'method' => 'POST',
                    'content' => http_build_query($data)
                ]
            ];

            $context = stream_context_create($options);
            $response = file_get_contents($url, false, $context);

            if ($response === false) {
                error_log('reCAPTCHA validation failed: Could not connect to API');
                return false;
            }
        }

        // Decode response
        $responseData = json_decode($response, true);

        // Log validation result for debugging
        error_log('reCAPTCHA validation result: ' . ($responseData['success'] ? 'Success' : 'Failed') .
            (isset($responseData['score']) ? ' (Score: ' . $responseData['score'] . ')' : '') .
            (isset($responseData['error-codes']) ? ' Errors: ' . implode(', ', $responseData['error-codes']) : ''));

        // Return success status
        return isset($responseData['success']) && $responseData['success'] === true;
    } catch (Exception $e) {
        error_log('reCAPTCHA validation error: ' . $e->getMessage());
        return false;
    }
}

/**
 * Check if reCAPTCHA is properly configured
 * @return bool True if reCAPTCHA is configured, false otherwise
 */
function isRecaptchaConfigured()
{
    $siteKey = getEnvVar('RECAPTCHA_SITE_KEY');
    $secretKey = getEnvVar('RECAPTCHA_SECRET_KEY');

    if (empty($siteKey) || empty($secretKey)) {
        error_log('reCAPTCHA not properly configured. Missing keys.');
        return false;
    }

    return true;
}
