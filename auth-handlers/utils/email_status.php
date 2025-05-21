<?php
/**
 * Email Status Checker
 * 
 * A lightweight utility to check email status without dependencies
 */

/**
 * Check if there are any email logs for a given address
 * 
 * @param string $email The email address to check
 * @return array Status information
 */
function checkEmailStatus($email) {
    $logDir = __DIR__ . '/../logs';
    $mailLogDir = __DIR__ . '/../logs/mail';
    
    // Ensure directories exist
    if (!file_exists($logDir)) {
        @mkdir($logDir, 0755, true);
    }
    if (!file_exists($mailLogDir)) {
        @mkdir($mailLogDir, 0755, true);
    }
    
    $emailLogFile = $logDir . '/email.log';
    $result = [
        'email_address' => $email,
        'logs_exist' => false,
        'mail_files_exist' => false,
        'mail_files' => [],
        'app_environment' => getenv('APP_ENV') ?: 'development',
        'mail_driver' => getenv('MAIL_DRIVER') ?: 'log'
    ];
    
    // Check if email log file exists and contains this email
    if (file_exists($emailLogFile)) {
        $result['logs_exist'] = true;
        
        // Check if email is mentioned in the log file
        $logContent = file_get_contents($emailLogFile);
        $result['email_in_logs'] = strpos($logContent, $email) !== false;
    }
    
    // Check for mail files in the mail directory
    if (file_exists($mailLogDir)) {
        $mailFiles = scandir($mailLogDir);
        foreach ($mailFiles as $file) {
            if ($file !== '.' && $file !== '..' && is_file($mailLogDir . '/' . $file)) {
                $fileContent = file_get_contents($mailLogDir . '/' . $file);
                if (strpos($fileContent, $email) !== false) {
                    $result['mail_files_exist'] = true;
                    $result['mail_files'][] = $file;
                }
            }
        }
    }
    
    return $result;
}
?>
