<?php

/**
 * MongoDB Helper Functions
 * 
 * This file contains helper functions for MongoDB operations.
 */

// Load environment variables if not already loaded
if (!function_exists('getEnvVar')) {
    /**
     * Get environment variable with optional default value
     * 
     * @param string $name Name of the environment variable
     * @param mixed $default Default value if variable is not set
     * @return mixed Value of the environment variable or default
     */
    function getEnvVar($name, $default = '')
    {
        // First check .env file if it exists
        static $env = null;
        if ($env === null) {
            $envFile = __DIR__ . '/../../.env';
            if (file_exists($envFile)) {
                $env = parse_ini_file($envFile);
            } else {
                $env = [];
            }
        }

        // Check if variable exists in .env file
        if (isset($env[$name])) {
            return $env[$name];
        }

        // Fall back to getenv() which checks $_ENV, $_SERVER
        $value = getenv($name);
        return $value !== false ? $value : $default;
    }
}

/**
 * Get MongoDB connection manager
 * 
 * @return MongoDB\Driver\Manager MongoDB connection manager
 */
function getMongoManager()
{
    static $manager = null;

    if ($manager === null) {
        try {
            // Get connection parameters - check .env first, then fall back to config
            $uri = getEnvVar('MONGODB_URI');
            if (empty($uri)) {
                // Fallback to explicit connection parameters
                global $mongo_host, $mongo_port, $mongo_user, $mongo_pass;

                // Create MongoDB connection string
                if (!empty($mongo_user) && !empty($mongo_pass)) {
                    $uri = "mongodb://$mongo_user:$mongo_pass@$mongo_host:$mongo_port";
                } else {
                    $uri = "mongodb://$mongo_host:$mongo_port";
                }
            }

            $options = [
                'tls' => true,
                'tlsAllowInvalidCertificates' => true,
                'retryWrites' => true,
                'w' => 'majority'
            ];

            $manager = new MongoDB\Driver\Manager($uri, $options);

            // Log success
            error_log("MongoDB connection established successfully");
        } catch (Exception $e) {
            error_log("MongoDB Connection Error: " . $e->getMessage());
            throw $e; // Re-throw to be handled by calling code
        }
    }

    return $manager;
}

/**
 * Get MongoDB database name
 * 
 * @return string Database name from environment or config
 */
function getMongoDatabaseName()
{
    $dbName = getEnvVar('MONGODB_DATABASE');
    if (empty($dbName)) {
        global $mongo_db;
        $dbName = $mongo_db ?? 'auth';
    }
    return $dbName;
}

/**
 * Execute a MongoDB query
 * 
 * @param string $collection Collection name
 * @param array $filter Query filter
 * @param array $options Query options
 * @return array Results as PHP array
 */
function mongoFind($collection, $filter = [], $options = [])
{
    try {
        $manager = getMongoManager();
        $dbName = getMongoDatabaseName();

        $query = new MongoDB\Driver\Query($filter, $options);
        $cursor = $manager->executeQuery("$dbName.$collection", $query);

        return $cursor->toArray();
    } catch (Exception $e) {
        error_log("MongoDB Find Error: " . $e->getMessage());
        throw $e;
    }
}

/**
 * Execute a MongoDB command
 * 
 * @param array $command Command to execute
 * @return object Command result
 */
function mongoCommand($command)
{
    try {
        $manager = getMongoManager();
        $command = new MongoDB\Driver\Command($command);
        return $manager->executeCommand(getMongoDatabaseName(), $command);
    } catch (Exception $e) {
        error_log("MongoDB Command Error: " . $e->getMessage());
        throw $e;
    }
}

/**
 * Execute a MongoDB bulk write operation
 * 
 * @param string $collection Collection name
 * @param MongoDB\Driver\BulkWrite $bulk Bulk write operation
 * @return MongoDB\Driver\WriteResult Write result
 */
function mongoBulkWrite($collection, $bulk)
{
    try {
        $manager = getMongoManager();
        $dbName = getMongoDatabaseName();
        return $manager->executeBulkWrite("$dbName.$collection", $bulk);
    } catch (Exception $e) {
        error_log("MongoDB Bulk Write Error: " . $e->getMessage());
        throw $e;
    }
}

// Add convenience functions for CRUD operations

/**
 * Insert a single document
 * 
 * @param string $collection Collection name
 * @param array $document Document to insert
 * @return mixed Inserted ID or false on failure
 */
function mongoInsert($collection, $document)
{
    try {
        $bulk = new MongoDB\Driver\BulkWrite();
        $id = $bulk->insert($document);
        $result = mongoBulkWrite($collection, $bulk);

        return $result->getInsertedCount() > 0 ? $id : false;
    } catch (Exception $e) {
        error_log("MongoDB Insert Error: " . $e->getMessage());
        return false;
    }
}

/**
 * Update documents
 * 
 * @param string $collection Collection name
 * @param array $filter Filter criteria
 * @param array $update Update operations
 * @param array $options Update options
 * @return array [matchedCount, modifiedCount]
 */
function mongoUpdate($collection, $filter, $update, $options = ['multi' => false, 'upsert' => false])
{
    try {
        $bulk = new MongoDB\Driver\BulkWrite();
        $bulk->update($filter, $update, $options);
        $result = mongoBulkWrite($collection, $bulk);

        return [
            'matchedCount' => $result->getMatchedCount(),
            'modifiedCount' => $result->getModifiedCount()
        ];
    } catch (Exception $e) {
        error_log("MongoDB Update Error: " . $e->getMessage());
        return ['matchedCount' => 0, 'modifiedCount' => 0];
    }
}

/**
 * Delete documents
 * 
 * @param string $collection Collection name
 * @param array $filter Filter criteria
 * @param array $options Delete options
 * @return int Number of documents deleted
 */
function mongoDelete($collection, $filter, $options = ['limit' => 0])
{
    try {
        $bulk = new MongoDB\Driver\BulkWrite();
        $bulk->delete($filter, $options);
        $result = mongoBulkWrite($collection, $bulk);

        return $result->getDeletedCount();
    } catch (Exception $e) {
        error_log("MongoDB Delete Error: " . $e->getMessage());
        return 0;
    }
}

/**
 * Find a single document
 * 
 * @param string $collection Collection name
 * @param array $filter Filter criteria
 * @return object|null Document or null if not found
 */
function mongoFindOne($collection, $filter)
{
    $results = mongoFind($collection, $filter, ['limit' => 1]);
    return !empty($results) ? $results[0] : null;
}

/**
 * Run MongoDB diagnostics to check setup and configuration
 * 
 * @return array Diagnostic results
 */
function runMongoDbDiagnostics()
{
    $diagnostics = [
        'php_version' => PHP_VERSION,
        'mongodb_ext_version' => '',
        'server_running' => false,
        'server_version' => '',
        'can_connect' => false,
        'suggestions' => []
    ];

    // Check MongoDB extension
    if (extension_loaded('mongodb')) {
        $diagnostics['mongodb_ext_version'] = phpversion('mongodb');
    } else {
        $diagnostics['suggestions'][] = 'MongoDB PHP extension is not installed.';
    }

    // Try to establish connection and check server
    try {
        $manager = getMongoManager();
        $command = new MongoDB\Driver\Command(['ping' => 1]);
        $result = $manager->executeCommand('admin', $command);

        $diagnostics['server_running'] = true;
        $diagnostics['can_connect'] = true;

        // Get server version
        $command = new MongoDB\Driver\Command(['buildInfo' => 1]);
        $result = $manager->executeCommand('admin', $command);
        $buildInfo = current($result->toArray());
        $diagnostics['server_version'] = $buildInfo->version;
    } catch (Exception $e) {
        $diagnostics['suggestions'][] = 'Could not connect to MongoDB server: ' . $e->getMessage();
    }

    return $diagnostics;
}

/**
 * Create a reliable MongoDB connection with error handling
 * 
 * @param string $uri MongoDB connection URI
 * @return bool True if connection successful, false otherwise
 */
function createReliableMongoDBConnection($uri)
{
    try {
        $options = [
            'serverSelectionTimeoutMS' => 5000,
            'connectTimeoutMS' => 5000
        ];

        $manager = new MongoDB\Driver\Manager($uri, $options);

        // Test connection with ping command
        $command = new MongoDB\Driver\Command(['ping' => 1]);
        $manager->executeCommand('admin', $command);

        return true;
    } catch (Exception $e) {
        error_log("MongoDB Connection Test Error: " . $e->getMessage());
        return false;
    }
}
