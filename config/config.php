<?php
/**
 * Database Configuration
 * 
 * Using MongoDB database for the application.
 * 
 * Note for IDE/Editor users: If your IDE doesn't recognize MongoDB classes,
 * add 'mongodb' to the intelephense.stubs in your editor settings.
 * See .vscode/settings.json for an example configuration.
 */

// Check if MongoDB extension is loaded
if (!extension_loaded('mongodb')) {
    die("MongoDB extension not loaded. Please install and enable the MongoDB extension for PHP. 
    <br>
    <b>For Windows/XAMPP:</b> 
    <ol>
        <li>Download the MongoDB PHP extension from <a href='https://pecl.php.net/package/mongodb' target='_blank'>https://pecl.php.net/package/mongodb</a></li>
        <li>Extract the DLL file to the PHP extensions directory (php/ext)</li>
        <li>Add 'extension=mongodb' to your php.ini file</li>
        <li>Restart your web server</li>
    </ol>");
}

// MongoDB configuration
$mongo_host = 'localhost';
$mongo_port = 27017;
$mongo_db = 'auth';
$mongo_user = '';  // If authentication is required
$mongo_pass = '';  // If authentication is required

// Add debug logging to help troubleshoot MongoDB connection issues
error_log("MongoDB configuration: Host=$mongo_host, Port=$mongo_port, DB=$mongo_db");

// MongoDB connection
try {
    // Create MongoDB connection string
    $mongo_conn_string = "mongodb://$mongo_host:$mongo_port";
    
    // If authentication is required
    if (!empty($mongo_user) && !empty($mongo_pass)) {
        $mongo_conn_string = "mongodb://$mongo_user:$mongo_pass@$mongo_host:$mongo_port";
    }
    
    // Log connection attempt
    error_log("Attempting to connect to MongoDB with connection string: " . $mongo_conn_string);
    
    // Use the MongoDB\Driver classes directly since we don't have the MongoDB library
    $mongo_manager = new MongoDB\Driver\Manager($mongo_conn_string);
    
    // Log successful connection
    error_log("Successfully connected to MongoDB");
    
    /**
     * Find a user by email
     * 
     * @param string $email The email to search for
     * @return mixed The user document or null if not found
     */
    if (!function_exists('findUserByEmail')) {
        function findUserByEmail($email) {
            try {
                // Detailed logging
                $logFile = __DIR__ . '/../logs/user_lookup.log';
                
                // Create function to log messages
                $logMessage = function($message, $data = null) use ($logFile) {
                    $timestamp = date('Y-m-d H:i:s');
                    $log = "[$timestamp] $message";
                    if ($data !== null) {
                        $log .= " - " . json_encode($data, JSON_UNESCAPED_SLASHES);
                    }
                    file_put_contents($logFile, $log . PHP_EOL, FILE_APPEND);
                    error_log("USER_LOOKUP: $message");
                };
                
                $logMessage("Looking for user with email: $email");

                // Get MongoDB connection
                $uri = getEnvVar('MONGODB_URI');
                $options = [
                    'tls' => true,
                    'tlsAllowInvalidCertificates' => true,
                    'retryWrites' => true,
                    'w' => 'majority'
                ];

                $logMessage("Connecting to MongoDB");
                $client = new MongoDB\Client($uri, $options);
                $dbName = getEnvVar('MONGODB_DATABASE');
                $logMessage("Using database: $dbName");
                
                $database = $client->selectDatabase($dbName);
                $collection = $database->selectCollection('users');
                
                $logMessage("Searching for user", ['email' => $email]);
                
                // Important: Make sure we're using case insensitive search
                // MongoDB is case sensitive by default
                $filter = ['email' => ['$regex' => '^' . preg_quote($email) . '$', '$options' => 'i']];
                $logMessage("Using filter", ['filter' => json_encode($filter)]);
                
                $user = $collection->findOne($filter);
                
                if ($user) {
                    $logMessage("User found", [
                        'id' => (string)$user->_id,
                        'email' => $user->email,
                        'firstName' => $user->firstName ?? 'N/A',
                        'lastName' => $user->lastName ?? 'N/A'
                    ]);
                    return $user;
                } else {
                    // Try with direct comparison as fallback
                    $logMessage("User not found with regex search, trying direct comparison");
                    $user = $collection->findOne(['email' => $email]);
                    
                    if ($user) {
                        $logMessage("User found with direct comparison", [
                            'id' => (string)$user->_id,
                            'email' => $user->email
                        ]);
                        return $user;
                    }
                    
                    $logMessage("User not found with any search method");
                    return null;
                }
            } catch (Exception $e) {
                error_log("Error finding user by email: " . $e->getMessage());
                error_log("Stack trace: " . $e->getTraceAsString());
                return null;
            }
        }
    }
    
    // Define a function to save or update password reset token
    if (!function_exists('savePasswordResetToken')) {
        function savePasswordResetToken($email, $token, $expires) {
            global $mongo_manager, $mongo_db;
            
            error_log("Saving password reset token for email: $email");
            
            try {
                // Check if record exists
                $filter = ['email' => $email];
                $query = new MongoDB\Driver\Query($filter);
                $cursor = $mongo_manager->executeQuery("$mongo_db.password_resets", $query);
                $exists = count($cursor->toArray()) > 0;
                
                // Create document
                $doc = [
                    'email' => $email,
                    'token' => $token,
                    'expires_at' => $expires,
                    'created_at' => new MongoDB\BSON\UTCDateTime(time() * 1000)
                ];
                
                $bulk = new MongoDB\Driver\BulkWrite;
                
                if ($exists) {
                    // Update existing document
                    error_log("Updating existing token for: $email");
                    $bulk->update(
                        ['email' => $email],
                        ['$set' => $doc],
                        ['multi' => false, 'upsert' => false]
                    );
                } else {
                    // Insert new document
                    error_log("Creating new token for: $email");
                    $bulk->insert($doc);
                }
                
                $result = $mongo_manager->executeBulkWrite("$mongo_db.password_resets", $bulk);
                error_log("Token saved successfully. Inserted: {$result->getInsertedCount()}, Updated: {$result->getModifiedCount()}");
                
                return true;
            } catch (Exception $e) {
                error_log("Error saving password reset token: " . $e->getMessage());
                error_log($e->getTraceAsString());
                throw $e; // Re-throw to allow proper handling upstream
            }
        }
    }
    
    // Define a function to find password reset token
    if (!function_exists('findPasswordResetToken')) {
        function findPasswordResetToken($token) {
            global $mongo_manager, $mongo_db;
            // Log token lookup attempt
            error_log("Looking for password reset token: " . substr($token, 0, 5) . "...");
            
            try {
                // Create a MongoDB UTC DateTime for comparison with current time
                $currentTime = new MongoDB\BSON\UTCDateTime(time() * 1000);
                
                // First approach - if expires_at is stored as MongoDB UTCDateTime
                $filter = [
                    'token' => $token,
                    'expires_at' => ['$gt' => $currentTime]
                ];
                $query = new MongoDB\Driver\Query($filter);
                $cursor = $mongo_manager->executeQuery("$mongo_db.password_resets", $query);
                $result = $cursor->toArray();
                
                if (count($result) > 0) {
                    error_log("Token found (UTCDateTime format)");
                    return $result[0];
                }
                
                // Second approach - if expires_at is stored as string
                // We'll get all tokens first, then filter by expiration
                $filter = ['token' => $token];
                $query = new MongoDB\Driver\Query($filter);
                $cursor = $mongo_manager->executeQuery("$mongo_db.password_resets", $query);
                $result = $cursor->toArray();
                
                foreach ($result as $record) {
                    error_log("Found token record, checking expiration");
                    
                    // Check if expires_at is a string date
                    if (isset($record->expires_at) && is_string($record->expires_at)) {
                        $expiryTime = strtotime($record->expires_at);
                        if ($expiryTime > time()) {
                            error_log("Token is valid (string date format)");
                            return $record;
                        }
                    } else if (isset($record->expires_at) && $record->expires_at instanceof MongoDB\BSON\UTCDateTime) {
                        // Should be caught by first query, but double-check here
                        $expiryTime = $record->expires_at->toDateTime()->getTimestamp();
                        if ($expiryTime > time()) {
                            error_log("Token is valid (UTC DateTime format)");
                            return $record;
                        }
                    }
                }
                
                error_log("No valid token found or token expired");
                return null;
            } catch (Exception $e) {
                error_log("Error finding password reset token: " . $e->getMessage());
                return null;
            }
        }
    }
    
    // Define a function to update user password
    if (!function_exists('updateUserPassword')) {
        function updateUserPassword($email, $password) {
            try {
                $logFile = __DIR__ . '/../logs/password_reset.log';
                $logMessage = function($message, $data = null) use ($logFile) {
                    $timestamp = date('Y-m-d H:i:s');
                    $log = "[$timestamp] $message";
                    if ($data !== null) {
                        $log .= " - " . json_encode($data, JSON_UNESCAPED_SLASHES);
                    }
                    file_put_contents($logFile, $log . PHP_EOL, FILE_APPEND);
                };
                
                $logMessage("Updating password for user", ['email' => $email]);
                
                // Use the MongoDB connection from .env
                $uri = getEnvVar('MONGODB_URI');
                if (empty($uri)) {
                    $logMessage("Error: MONGODB_URI not found in environment variables");
                    throw new Exception("MongoDB URI not configured");
                }
                
                $options = [
                    'tls' => true,
                    'tlsAllowInvalidCertificates' => true,
                    'retryWrites' => true,
                    'w' => 'majority'
                ];
                
                // Create MongoDB connection using MongoDB\Driver\Manager
                $mongo_manager = new MongoDB\Driver\Manager($uri, $options);
                $dbName = getEnvVar('MONGODB_DATABASE', 'auth');
                
                $logMessage("Executing password update", ['database' => $dbName]);
                
                // Update the password using MongoDB\Driver\BulkWrite
                $bulk = new MongoDB\Driver\BulkWrite();
                $bulk->update(
                    ['email' => $email],
                    ['$set' => [
                        'password' => $password, 
                        'updated_at' => new MongoDB\BSON\UTCDateTime(time() * 1000)
                    ]],
                    ['multi' => false, 'upsert' => false]
                );
                
                $result = $mongo_manager->executeBulkWrite("$dbName.users", $bulk);
                
                $logMessage("Password update result", [
                    'matched' => $result->getMatchedCount(),
                    'modified' => $result->getModifiedCount()
                ]);
                
                if ($result->getModifiedCount() === 0) {
                    if ($result->getMatchedCount() === 0) {
                        $logMessage("User not found", ['email' => $email]);
                        throw new Exception("User not found");
                    } else {
                        $logMessage("Password not changed (might be the same as before)");
                    }
                }
                
                return true;
            } catch (Exception $e) {
                $logMessage("Error updating password: " . $e->getMessage(), ['trace' => $e->getTraceAsString()]);
                throw $e; // Re-throw to be handled by calling code
            }
        }
    }
    
    // Define a function to delete password reset token
    if (!function_exists('deletePasswordResetToken')) {
        function deletePasswordResetToken($token) {
            global $mongo_manager, $mongo_db;
            $bulk = new MongoDB\Driver\BulkWrite;
            $bulk->delete(['token' => $token], ['limit' => 1]);
            $mongo_manager->executeBulkWrite("$mongo_db.password_resets", $bulk);
        }
    }
    
    // Define a function to insert a new user
    if (!function_exists('insertUser')) {
        function insertUser($userData) {
            try {
                // Log insertion attempt
                error_log("Attempting to insert new user: " . $userData['email']);
                
                // Get MongoDB connection
                $uri = getEnvVar('MONGODB_URI');
                if (empty($uri)) {
                    global $mongo_conn_string;
                    $uri = $mongo_conn_string;
                }
                
                $options = [
                    'tls' => true,
                    'tlsAllowInvalidCertificates' => true,
                    'retryWrites' => true,
                    'w' => 'majority'
                ];
                
                $client = new MongoDB\Client($uri, $options);
                $dbName = getEnvVar('MONGODB_DATABASE', 'auth');
                
                $database = $client->selectDatabase($dbName);
                $collection = $database->selectCollection('users');
                
                // Insert the user data
                $result = $collection->insertOne($userData);
                
                if ($result->getInsertedCount() > 0) {
                    error_log("User inserted successfully with ID: " . $result->getInsertedId());
                    return $result;
                } else {
                    error_log("Failed to insert user");
                    return false;
                }
            } catch (Exception $e) {
                error_log("Error inserting user: " . $e->getMessage());
                error_log("Stack trace: " . $e->getTraceAsString());
                return false;
            }
        }
    }
    
    // Define a function to update user verification token
    if (!function_exists('updateUserVerificationToken')) {
        function updateUserVerificationToken($email, $token, $expiry) {
            global $mongo_manager, $mongo_db;
            $bulk = new MongoDB\Driver\BulkWrite;
            $bulk->update(
                ['email' => $email],
                ['$set' => [
                    'verificationToken' => $token,
                    'tokenExpiry' => $expiry,
                    'updated_at' => date('Y-m-d H:i:s')
                ]],
                ['multi' => false, 'upsert' => false]
            );
            $mongo_manager->executeBulkWrite("$mongo_db.users", $bulk);
        }
    }
    
    // Helper function to determine database type
    if (!function_exists('getDbType')) {
        function getDbType() {
            return 'mongodb'; // Currently we only support MongoDB
        }
    }
    
} catch (Exception $e) {
    // Log detailed connection error
    error_log("MongoDB Connection Error: " . $e->getMessage());
    
    // Customize error handling based on your needs
    die("Database Connection Failed: " . $e->getMessage());
}

// Constants
define('APP_NAME', 'authBoost');
define('SITE_URL', 'http://localhost/auth');
define('EMAIL_FROM', 'noreply@authboost.com');
?>
