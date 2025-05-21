<?php

/**
 * Database configuration and connection functions
 */

// Load environment variables if not already loaded
if (!function_exists('getEnvVar')) {
    require_once __DIR__ . '/env_loader.php';
}

/**
 * Get MongoDB database connection
 * 
 * @return MongoDB\Database|null MongoDB database instance or null on failure
 */
function getDatabaseConnection()
{
    try {
        // Get MongoDB connection string from environment variables
        $mongoUri = getEnvVar('MONGODB_URI');
        $database = getEnvVar('MONGODB_DATABASE', 'auth');

        // Check if MongoDB extension is loaded
        if (!extension_loaded('mongodb')) {
            error_log('MongoDB extension not loaded');
            return null;
        }

        // Check if MongoDB library is available
        if (!class_exists('MongoDB\Client')) {
            // Try to load via autoloader if available
            $autoloadPath = __DIR__ . '/../vendor/autoload.php';
            if (file_exists($autoloadPath)) {
                require_once $autoloadPath;
            }

            // If still not available, use direct MongoDB driver
            if (!class_exists('MongoDB\Client')) {
                return createDirectConnection($mongoUri, $database);
            }
        }

        // Create MongoDB client and return database
        $client = new MongoDB\Client($mongoUri);
        return $client->selectDatabase($database);
    } catch (Exception $e) {
        error_log('MongoDB Connection Error: ' . $e->getMessage());
        return null;
    }
}

/**
 * Create a direct MongoDB connection using the MongoDB driver
 * 
 * @param string $mongoUri MongoDB connection string
 * @param string $database Database name
 * @return object A simple object with connection manager
 */
function createDirectConnection($mongoUri, $database)
{
    try {
        // Create a MongoDB manager for direct driver usage
        $manager = new MongoDB\Driver\Manager($mongoUri);

        // Return a simple object with the manager and database name
        return (object) [
            'manager' => $manager,
            'dbName' => $database,
            'users' => new MongoDBCollection($manager, $database, 'users')
        ];
    } catch (Exception $e) {
        error_log('Direct MongoDB Connection Error: ' . $e->getMessage());
        return null;
    }
}

/**
 * Simple MongoDB collection wrapper for direct driver usage
 */
class MongoDBCollection
{
    private $manager;
    private $namespace;

    public function __construct($manager, $database, $collection)
    {
        $this->manager = $manager;
        $this->namespace = $database . '.' . $collection;
    }

    public function findOne(array $filter = [], array $options = [])
    {
        try {
            $query = new MongoDB\Driver\Query($filter, $options);
            $cursor = $this->manager->executeQuery($this->namespace, $query);
            $result = current($cursor->toArray());
            return $result ? $result : null;
        } catch (Exception $e) {
            error_log('MongoDB findOne Error: ' . $e->getMessage());
            return null;
        }
    }

    public function updateOne(array $filter, array $update, array $options = [])
    {
        try {
            $bulk = new MongoDB\Driver\BulkWrite;
            $bulk->update($filter, $update, $options);
            $result = $this->manager->executeBulkWrite($this->namespace, $bulk);
            return (object) ['modifiedCount' => $result->getModifiedCount()];
        } catch (Exception $e) {
            error_log('MongoDB updateOne Error: ' . $e->getMessage());
            return null;
        }
    }
}

/**
 * Find a user by email address
 * 
 * @param string $email Email address
 * @return object|null User object or null if not found
 */
if (!function_exists('findUserByEmail')) {
    function findUserByEmail($email)
    {
        $db = getDatabaseConnection();
        if (!$db) {
            return null;
        }

        try {
            if (is_object($db) && get_class($db) === 'MongoDB\Database') {
                // Using MongoDB library
                return $db->users->findOne(['email' => $email]);
            } else {
                // Using direct MongoDB driver
                return $db->users->findOne(['email' => $email]);
            }
        } catch (Exception $e) {
            error_log('Find User Error: ' . $e->getMessage());
            return null;
        }
    }
}

/**
 * Update user verification token and expiry
 * 
 * @param string $email User email
 * @param string $token New verification token
 * @param string $expiry Expiry timestamp
 * @return bool Success status
 */
if (!function_exists('updateUserVerificationToken')) {
    function updateUserVerificationToken($email, $token, $expiry)
    {
        $db = getDatabaseConnection();
        if (!$db) {
            return false;
        }

        try {
            $update = [
                '$set' => [
                    'verificationToken' => $token,
                    'tokenExpiry' => $expiry,
                    'updated_at' => (new DateTime())->format('Y-m-d H:i:s')
                ]
            ];

            if (is_object($db) && get_class($db) === 'MongoDB\Database') {
                // Using MongoDB library
                $result = $db->users->updateOne(['email' => $email], $update);
                return $result->getModifiedCount() > 0;
            } else {
                // Using direct MongoDB driver
                $result = $db->users->updateOne(['email' => $email], $update);
                return $result && $result->modifiedCount > 0;
            }
        } catch (Exception $e) {
            error_log('Update Token Error: ' . $e->getMessage());
            return false;
        }
    }
}

/**
 * Get database type
 * 
 * @return string Database type (mongodb or other)
 */
if (!function_exists('getDbType')) {
    function getDbType()
    {
        return 'mongodb';
    }
}

/**
 * Insert a new user into the database
 * 
 * @param array $userData User data
 * @return object|bool Insert result or false on failure
 */
if (!function_exists('insertUser')) {
    function insertUser($userData)
    {
        $db = getDatabaseConnection();
        if (!$db) {
            return false;
        }

        try {
            if (is_object($db) && get_class($db) === 'MongoDB\Database') {
                // Using MongoDB library
                return $db->users->insertOne($userData);
            } else {
                // Using direct MongoDB driver
                $bulk = new MongoDB\Driver\BulkWrite;
                $userData['_id'] = new MongoDB\BSON\ObjectId();
                $id = $bulk->insert($userData);
                $result = $db->manager->executeBulkWrite($db->dbName . '.users', $bulk);

                // Create a mock result object
                return (object) [
                    'getInsertedCount' => function () use ($result) {
                        return $result->getInsertedCount();
                    },
                    'getInsertedId' => function () use ($userData) {
                        return $userData['_id'];
                    }
                ];
            }
        } catch (Exception $e) {
            error_log('Insert User Error: ' . $e->getMessage());
            return false;
        }
    }
}
