<?php
/**
 * PHPMailer Installation Helper
 * 
 * This script helps with installing PHPMailer without requiring Composer.
 */

// Path to the vendor directory
$vendorDir = __DIR__ . '/../vendor';
$phpMailerDir = $vendorDir . '/phpmailer/phpmailer';

// Check if PHPMailer is already installed
if (file_exists($phpMailerDir . '/src/PHPMailer.php')) {
    echo "PHPMailer is already installed.\n";
    exit(0);
}

// Create vendor directory if it doesn't exist
if (!file_exists($vendorDir)) {
    if (!mkdir($vendorDir, 0755, true)) {
        die("Failed to create vendor directory.\n");
    }
}

// URL to download PHPMailer
$phpmailerUrl = 'https://github.com/PHPMailer/PHPMailer/archive/refs/tags/v6.8.0.zip';
$zipFile = $vendorDir . '/phpmailer.zip';

echo "Downloading PHPMailer...\n";
if (!copy($phpmailerUrl, $zipFile)) {
    die("Failed to download PHPMailer.\n");
}

echo "Extracting PHPMailer...\n";
$zip = new ZipArchive;
if ($zip->open($zipFile) !== TRUE) {
    die("Failed to open the zip file.\n");
}

$zip->extractTo($vendorDir);
$zip->close();

// Rename the extracted directory to match the expected path
if (!rename($vendorDir . '/PHPMailer-6.8.0', $phpMailerDir)) {
    die("Failed to rename the PHPMailer directory.\n");
}

// Remove the zip file
unlink($zipFile);

// Create simple autoloader
$autoloaderContent = <<<'EOT'
<?php
// Simple autoloader for PHPMailer

spl_autoload_register(function ($class) {
    // PHPMailer classes
    if (strpos($class, 'PHPMailer\\PHPMailer\\') === 0) {
        $name = str_replace(['PHPMailer\\PHPMailer\\', '\\'], ['', '/'], $class);
        $file = __DIR__ . '/phpmailer/phpmailer/src/' . $name . '.php';
        if (file_exists($file)) {
            require $file;
            return true;
        }
    }
    return false;
});
EOT;

file_put_contents($vendorDir . '/autoload.php', $autoloaderContent);

echo "PHPMailer has been successfully installed.\n";
echo "You can now use PHPMailer in your project.\n";
?>
