<?php

/**
 * Database diagnostics utility
 * Provides tools for checking and troubleshooting database connections
 */

require_once __DIR__ . '/../../config/env_loader.php';
require_once __DIR__ . '/logger.php';

/**
 * Check MongoDB connection and diagnose issues
 * 
 * @return array Diagnostic information
 */
function checkMongoDbConnection()
{
    $diagnostics = [
        'status' => 'unknown',
        'type' => 'mongodb',
        'host' => getEnvVar('DB_HOST', 'localhost'),
        'port' => getEnvVar('DB_PORT', '27017'),
        'database' => getEnvVar('DB_NAME', 'auth'),
        'extension_loaded' => extension_loaded('mongodb'),
        'driver_version' => phpversion('mongodb') ?: 'not installed',
        'can_connect' => false,
        'can_ping' => false,
        'can_write' => false,
        'can_read' => false,
        'error' => null,
        'detailed_error' => null,
        'connection_string' => null,
        'suggestions' => []
    ];

    // Check if MongoDB extension is loaded
    if (!$diagnostics['extension_loaded']) {
        $diagnostics['status'] = 'error';
        $diagnostics['error'] = 'MongoDB PHP extension not loaded';
        $diagnostics['suggestions'][] = 'Install the MongoDB PHP extension using PECL or package manager';
        $diagnostics['suggestions'][] = 'Add "extension=mongodb.so" to php.ini';
        return $diagnostics;
    }

    // Build connection string (mask password in logs)
    $connectionString = 'mongodb://';
    $username = getEnvVar('DB_USER');
    $password = getEnvVar('DB_PASSWORD');

    if (!empty($username)) {
        $connectionString .= $username;
        if (!empty($password)) {
            $connectionString .= ':***'; // Password masked for logging
        }
        $connectionString .= '@';
    }

    $connectionString .= $diagnostics['host'] . ':' . $diagnostics['port'] . '/' . $diagnostics['database'];
    $diagnostics['connection_string'] = $connectionString;

    // Try to connect
    try {
        $client = new MongoDB\Client(
            str_replace('***', $password, $connectionString),
            [],
            ['typeMap' => ['root' => 'array', 'document' => 'array']]
        );
        $diagnostics['can_connect'] = true;

        // Try to ping the server
        try {
            $client->getManager()->selectServer(new MongoDB\Driver\ReadPreference(MongoDB\Driver\ReadPreference::RP_PRIMARY))->executeCommand('admin', new MongoDB\Driver\Command(['ping' => 1]));
            $diagnostics['can_ping'] = true;
        } catch (Exception $e) {
            $diagnostics['ping_error'] = $e->getMessage();
            $diagnostics['suggestions'][] = 'Check if MongoDB server is running on ' . $diagnostics['host'] . ':' . $diagnostics['port'];
            $diagnostics['suggestions'][] = 'Check MongoDB server logs for connection issues';
        }

        // Try to read from database
        try {
            $database = $client->selectDatabase($diagnostics['database']);
            $collections = [];
            foreach ($database->listCollections() as $collectionInfo) {
                $collections[] = $collectionInfo->getName();
            }
            $diagnostics['collections_accessible'] = $collections;
            $diagnostics['can_read'] = true;
        } catch (Exception $e) {
            $diagnostics['collections_error'] = $e->getMessage();
            $diagnostics['suggestions'][] = 'Check if database "' . $diagnostics['database'] . '" exists';
            $diagnostics['suggestions'][] = 'Verify user has read permissions on the database';
        }

        // Try to write to database
        try {
            $testCollection = $database->selectCollection('connection_test');
            $result = $testCollection->insertOne(['test' => 'Connection test', 'timestamp' => new MongoDB\BSON\UTCDateTime()]);
            $diagnostics['can_write'] = $result->getInsertedCount() === 1;

            // Clean up test document
            $testCollection->deleteOne(['_id' => $result->getInsertedId()]);
        } catch (Exception $e) {
            $diagnostics['write_error'] = $e->getMessage();
            $diagnostics['suggestions'][] = 'Verify user has write permissions on the database';
        }

        // Set overall status
        if ($diagnostics['can_connect'] && $diagnostics['can_ping'] && $diagnostics['can_read'] && $diagnostics['can_write']) {
            $diagnostics['status'] = 'ok';
        } elseif ($diagnostics['can_connect']) {
            $diagnostics['status'] = 'partial';
        } else {
            $diagnostics['status'] = 'error';
        }
    } catch (Exception $e) {
        $diagnostics['error'] = 'Connection failed: ' . $e->getMessage();
        $diagnostics['detailed_error'] = $e->getTraceAsString();
        $diagnostics['status'] = 'error';

        // Add suggestions based on error message
        if (strpos($e->getMessage(), 'No suitable servers found') !== false) {
            $diagnostics['suggestions'][] = 'Verify MongoDB server is running on ' . $diagnostics['host'] . ':' . $diagnostics['port'];
            $diagnostics['suggestions'][] = 'Check if there is a firewall blocking the connection';
            $diagnostics['suggestions'][] = 'Run "mongo ' . $diagnostics['host'] . ':' . $diagnostics['port'] . '" from command line to test direct connection';
        } elseif (strpos($e->getMessage(), 'Authentication failed') !== false) {
            $diagnostics['suggestions'][] = 'Verify username and password in environment variables';
            $diagnostics['suggestions'][] = 'Check if the user exists in MongoDB and has appropriate permissions';
        }
    }

    return $diagnostics;
}

/**
 * Run database diagnostics and log results
 * 
 * @param string $context Context information for the log
 * @return array Diagnostic results
 */
function runDatabaseDiagnostics($context = '')
{
    $diagnostics = [
        'status' => 'unknown',
        'type' => 'mongodb',
        'host' => 'mongodb+srv://cluster0.mz6be.mongodb.net',
        'database' => getEnvVar('MONGODB_DATABASE', 'auth'),
        'extension_loaded' => extension_loaded('mongodb'),
        'driver_version' => phpversion('mongodb'),
        'can_connect' => false,
        'can_ping' => false,
        'can_write' => false,
        'can_read' => false,
        'error' => null,
        'detailed_error' => null,
        'connection_string' => getEnvVar('MONGODB_URI', '')
    ];

    try {
        // Check MongoDB extension
        if (!$diagnostics['extension_loaded']) {
            throw new Exception('MongoDB extension not loaded');
        }

        // Initialize MongoDB client
        $client = new MongoDB\Client(getEnvVar('MONGODB_URI'));
        $diagnostics['can_connect'] = true;

        // Try to ping the server
        $client->selectDatabase('admin')->command(['ping' => 1]);
        $diagnostics['can_ping'] = true;

        // Try to access the database
        $db = $client->selectDatabase(getEnvVar('MONGODB_DATABASE', 'auth'));

        // Try to read collections
        $collections = $db->listCollections();
        foreach ($collections as $collection) {
            $diagnostics['can_read'] = true;
            break;
        }

        // Try to write to a test collection
        $testCollection = $db->selectCollection('_diagnostics_test');
        $testDoc = ['test' => true, 'timestamp' => new MongoDB\BSON\UTCDateTime()];
        $result = $testCollection->insertOne($testDoc);
        if ($result->getInsertedCount() > 0) {
            $diagnostics['can_write'] = true;
            // Clean up test document
            $testCollection->deleteOne(['_id' => $result->getInsertedId()]);
        }

        $diagnostics['status'] = 'ok';
    } catch (Exception $e) {
        $diagnostics['status'] = 'error';
        $diagnostics['error'] = $e->getMessage();
        $diagnostics['detailed_error'] = $e->getTraceAsString();
    }

    return $diagnostics;
}
