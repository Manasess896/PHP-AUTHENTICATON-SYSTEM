<?php
/**
 * MongoDB Setup Instructions
 * 
 * This file contains instructions on how to set up MongoDB for use with PHP in XAMPP
 */

// Check if MongoDB extension is loaded
if (!extension_loaded('mongodb')) {
    echo "<h1>MongoDB Extension Not Found</h1>";
    echo "<p>Follow these steps to install the MongoDB PHP extension for XAMPP:</p>";
    
    echo "<h2>For Windows:</h2>";
    echo "<ol>";
    echo "<li>Download the MongoDB PHP driver for your PHP version from <a href='https://pecl.php.net/package/mongodb' target='_blank'>https://pecl.php.net/package/mongodb</a></li>";
    echo "<li>Extract the DLL file (php_mongodb.dll) from the downloaded zip</li>";
    echo "<li>Place the DLL file in your PHP extensions directory: <code>C:\\xampp\\php\\ext\\</code></li>";
    echo "<li>Edit your PHP.ini file (C:\\xampp\\php\\php.ini) and add the following line: <code>extension=php_mongodb.dll</code></li>";
    echo "<li>Restart your Apache server</li>";
    echo "</ol>";
    
    echo "<h2>For macOS/Linux:</h2>";
    echo "<ol>";
    echo "<li>Install the MongoDB driver using PECL: <code>sudo pecl install mongodb</code></li>";
    echo "<li>Edit your PHP.ini file and add: <code>extension=mongodb.so</code></li>";
    echo "<li>Restart your Apache server</li>";
    echo "</ol>";
    
    echo "<h2>Alternative: Use Composer</h2>";
    echo "<ol>";
    echo "<li>Install the MongoDB PHP library via Composer: <code>composer require mongodb/mongodb</code></li>";
    echo "<li>Include the Composer autoloader in your application</li>";
    echo "</ol>";
    
    echo "<p>After installing the extension, refresh this page to verify the installation.</p>";
    
    die();
} else {
    echo "<h1>MongoDB Extension Found!</h1>";
    echo "<p>The MongoDB PHP extension is properly installed.</p>";
    
    // Check if MongoDB PHP library is available
    if (!class_exists('MongoDB\Client')) {
        echo "<h2>MongoDB PHP Library Not Found</h2>";
        echo "<p style='color: orange;'>⚠️ The MongoDB extension is installed, but the MongoDB PHP library is not available.</p>";
        echo "<p>You need to install the MongoDB PHP library to use MongoDB\\Client:</p>";
        echo "<ol>";
        echo "<li>Install Composer if not already installed: <a href='https://getcomposer.org/download/' target='_blank'>https://getcomposer.org/download/</a></li>";
        echo "<li>Run this command in your project root: <code>composer require mongodb/mongodb</code></li>";
        echo "<li>Include the autoloader in your PHP files: <code>require 'vendor/autoload.php';</code></li>";
        echo "</ol>";
        echo "<p>Or you can use the MongoDB extension's native classes like MongoDB\\Driver\\Manager directly.</p>";
    } else {
        echo "<p style='color: green;'>✅ MongoDB PHP library is properly installed.</p>";
    }
    
    // Now check for MongoDB server connection
    try {
        $mongo = new MongoDB\Driver\Manager("mongodb://localhost:27017");
        
        // Execute a simple query to verify connection
        $command = new MongoDB\Driver\Command(['ping' => 1]);
        $mongo->executeCommand('admin', $command);
        
        echo "<p style='color: green;'>✅ Successfully connected to MongoDB server!</p>";
        
        echo "<p>You can now use MongoDB with your PHP application.</p>";
        echo "<p><a href='../index.html'>Go back to the application</a></p>";
    } catch (Exception $e) {
        echo "<h2>MongoDB Server Connection Error</h2>";
        echo "<p style='color: red;'>❌ Failed to connect to MongoDB server: " . $e->getMessage() . "</p>";
        
        echo "<h3>Make sure MongoDB server is installed and running:</h3>";
        echo "<ol>";
        echo "<li>Download and install MongoDB Community Server from <a href='https://www.mongodb.com/try/download/community' target='_blank'>https://www.mongodb.com/try/download/community</a></li>";
        echo "<li>Start the MongoDB service</li>";
        echo "<li>For Windows, check if the service is running in Services or start it with <code>net start MongoDB</code></li>";
        echo "<li>Verify MongoDB is running on port 27017</li>";
        echo "</ol>";
    }
}
?>
