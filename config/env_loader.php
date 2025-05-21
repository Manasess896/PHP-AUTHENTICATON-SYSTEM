<?php

/**
 * Environment Variable Loader
 * 
 * Loads environment variables from .env file and sets up project paths
 */

// Include Composer autoloader if available
if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php';

    // Load environment variables from .env file
    $dotenv = \Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
    $dotenv->load();

    // Optional: Set which variables are required
    $dotenv->required([
        'DB_USERNAME',
        'DB_PASSWORD',
        'MONGODB_URI',
        'MONGODB_DATABASE'
    ]);
}

// Setup path constants
define('BASE_PATH', realpath(__DIR__ . '/..'));
define('CONFIG_PATH', BASE_PATH . '/config');
define('LOGS_PATH', BASE_PATH . '/auth-handlers/logs');
define('STORAGE_PATH', BASE_PATH . '/storage');

/**
 * Get environment variable with optional default value
 * 
 * @param string $key The environment variable name
 * @param mixed $default Default value if not set
 * @return mixed
 */
function getEnvVar($key, $default = null)
{
    return isset($_ENV[$key]) ? $_ENV[$key] : (isset($_SERVER[$key]) ? $_SERVER[$key] : $default);
}

// Create logs directory with proper permissions if logging is enabled
if (getEnvVar('ENABLE_LOGGING', 'true') === 'true') {
    $directories = [
        LOGS_PATH,
        LOGS_PATH . '/mail'
    ];

    foreach ($directories as $directory) {
        if (!is_dir($directory)) {
            // Create directory with limited permissions
            mkdir($directory, 0750, true);

            // Create .htaccess to deny web access if it doesn't exist
            $htaccess = $directory . '/.htaccess';
            if (!file_exists($htaccess)) {
                file_put_contents($htaccess, "Require all denied\nOptions -Indexes");
            }
        }
    }
}

// Set environment based on .env or default to development
define('APP_ENV', getenv('APP_ENV') ?: 'development');
define('APP_DEBUG', filter_var(getenv('APP_DEBUG') ?: true, FILTER_VALIDATE_BOOLEAN));

// Configure error reporting based on environment
if (APP_DEBUG) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
    ini_set('log_errors', 1);
    ini_set('error_log', LOGS_PATH . '/error.log');
} else {
    error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', LOGS_PATH . '/error.log');
}

// Set memory limit if needed
ini_set('memory_limit', '256M');
