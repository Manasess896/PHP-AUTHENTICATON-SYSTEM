<?php
// Start session
session_start();

// Load environment variables
require_once __DIR__ . '/../config/env_loader.php';

// Require MongoDB and other dependencies
require_once __DIR__ . '/../config/database.php';
// Include Composer autoloader if available
if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php';
}

// Security measure - validate and sanitize input
$token = isset($_GET['token']) ? htmlspecialchars(trim($_GET['token']), ENT_QUOTES, 'UTF-8') : '';
$userId = isset($_GET['id']) ? htmlspecialchars(trim($_GET['id']), ENT_QUOTES, 'UTF-8') : '';

// Check if token and ID are provided
if (empty($token) || empty($userId)) {
    die("Invalid verification link. Please check your email for the correct link.");
}

try {
    // Connect to MongoDB using the existing function
    $db = getDatabaseConnection();

    if (!$db) {
        throw new Exception("Failed to connect to database");
    }

    // Ensure MongoDB\BSON\ObjectId class exists
    if (!class_exists('MongoDB\BSON\ObjectId')) {
        die("MongoDB PHP extension is not installed or enabled. Please install/enable it to proceed.");
    }

    // Validate that the ID is a valid MongoDB ObjectId
    if (!preg_match('/^[a-f\d]{24}$/i', $userId)) {
        die("Invalid user identifier format.");
    }

    // Convert string ID to MongoDB ObjectId
    $objId = new MongoDB\BSON\ObjectId($userId);

    // Find user with the given ID and token
    $user = null;

    // Check if we have a MongoDB\Database object or our custom wrapper
    if (is_object($db) && method_exists($db, 'selectCollection')) {
        $collection = $db->selectCollection('users');
        $user = $collection->findOne([
            '_id' => $objId,
            'verificationToken' => $token,
            'verified' => false
        ]);
    } else {
        // Using our custom wrapper or direct driver
        $user = $db->users->findOne([
            '_id' => $objId,
            'verificationToken' => $token,
            'verified' => false
        ]);
    }

    if (!$user) {
        die("Invalid or expired verification link. Please request a new one.");
    }

    // Check if token is expired
    $tokenExpiry = new DateTime($user->tokenExpiry);
    $now = new DateTime();

    if ($now > $tokenExpiry) {
        die("Verification link has expired. Please request a new one.");
    }

    // Update user as verified with formatted DateTime
    $updateData = [
        'verified' => true,
        'verificationToken' => null,
        'tokenExpiry' => null,
        'updated_at' => (new DateTime())->format('Y-m-d H:i:s')
    ];

    $result = null;
    // Handle different MongoDB connection types
    if (is_object($db) && method_exists($db, 'selectCollection')) {
        $collection = $db->selectCollection('users');
        $result = $collection->updateOne(['_id' => $objId], ['$set' => $updateData]);
    } else {
        $result = $db->users->updateOne(['_id' => $objId], ['$set' => $updateData]);
    }

    // Check if update was successful
    if ($result && (method_exists($result, 'getModifiedCount') ? $result->getModifiedCount() > 0 : true)) {        // Success, redirect to login page
        $message = urlencode("Your account has been successfully verified. You can now log in.");
        header("Location: login.php?success=$message");
        exit;
    } else {
        die("Failed to verify account. Please try again or contact support.");
    }
} catch (Exception $e) {
    // Log the error but don't expose details to user
    error_log("Verification error: " . $e->getMessage());
    die("An error occurred during verification. Please try again or contact support.");
}
