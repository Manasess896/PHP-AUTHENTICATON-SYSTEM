<?php
require_once __DIR__ . '/../utils/mongodb_helper.php';

// Get diagnostics results
$diagnostics = runMongoDbDiagnostics();

// Windows-specific installation instructions
$windowsInstructions = <<<EOT
<h4>Installing MongoDB on Windows</h4>
<ol>
    <li>Download MongoDB Community Server from <a href="https://www.mongodb.com/try/download/community" target="_blank">mongodb.com</a></li>
    <li>Run the installer and follow the prompts</li>
    <li>Make sure "Install MongoDB as a Service" is checked</li>
    <li>After installation, MongoDB should start automatically</li>
    <li>If not, open Command Prompt as Administrator and run: <code>net start MongoDB</code></li>
</ol>
EOT;

// PHP extension installation instructions
$extensionInstructions = <<<EOT
<h4>Installing MongoDB PHP Extension</h4>
<p>For XAMPP:</p>
<ol>
    <li>Download the correct PHP extension (dll file) for your PHP version from <a href="https://pecl.php.net/package/mongodb" target="_blank">PECL</a></li>
    <li>Place the .dll file in your PHP extension directory (xampp/php/ext)</li>
    <li>Edit your php.ini file and add: <code>extension=mongodb</code></li>
    <li>Restart Apache</li>
</ol>
EOT;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MongoDB Setup - authBoost</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container py-5">
        <div class="row justify-content-center">
            <div class="col-md-10">
                <div class="card shadow-sm">
                    <div class="card-header bg-primary text-white">
                        <h3 class="mb-0">MongoDB Setup Assistance</h3>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-info">
                            <h4>Diagnostics Results</h4>
                            <ul class="mb-0">
                                <li>PHP Version: <?php echo $diagnostics['php_version']; ?></li>
                                <li>MongoDB Extension: <?php echo $diagnostics['mongodb_ext_version'] ?: 'Not installed'; ?></li>
                                <li>MongoDB Server Running: <?php echo $diagnostics['server_running'] ? 'Yes' : 'No'; ?></li>
                                <?php if ($diagnostics['server_version']): ?>
                                <li>MongoDB Server Version: <?php echo $diagnostics['server_version']; ?></li>
                                <?php endif; ?>
                                <li>Connection Test: <?php echo $diagnostics['can_connect'] ? 'Success' : 'Failed'; ?></li>
                            </ul>
                        </div>
                        
                        <?php if (!empty($diagnostics['suggestions'])): ?>
                        <div class="alert alert-warning">
                            <h4>Suggestions</h4>
                            <ul>
                                <?php foreach ($diagnostics['suggestions'] as $suggestion): ?>
                                <li><?php echo $suggestion; ?></li>
                                <?php endforeach; ?>
                            </ul>
                        </div>
                        <?php endif; ?>
                        
                        <div class="mt-4">
                            <?php if (!$diagnostics['server_running']): ?>
                            <div class="mb-4">
                                <?php echo $windowsInstructions; ?>
                            </div>
                            <?php endif; ?>
                            
                            <?php if (!$diagnostics['mongodb_ext_version']): ?>
                            <div class="mb-4">
                                <?php echo $extensionInstructions; ?>
                            </div>
                            <?php endif; ?>
                            
                            <div class="mt-4">
                                <h4>Test Connection</h4>
                                <form method="post" action="">
                                    <div class="mb-3">
                                        <label for="uri" class="form-label">MongoDB Connection URI</label>
                                        <input type="text" class="form-control" id="uri" name="uri" value="mongodb://localhost:27017" placeholder="mongodb://localhost:27017">
                                    </div>
                                    <button type="submit" name="test_connection" class="btn btn-primary">Test Connection</button>
                                </form>
                                
                                <?php if (isset($_POST['test_connection'])): ?>
                                <div class="mt-3">
                                    <?php 
                                    $testUri = $_POST['uri'] ?? 'mongodb://localhost:27017';
                                    $connection = createReliableMongoDBConnection($testUri);
                                    if ($connection): 
                                    ?>
                                    <div class="alert alert-success">
                                        <strong>Success!</strong> Connection to MongoDB established.
                                    </div>
                                    <?php else: ?>
                                    <div class="alert alert-danger">
                                        <strong>Failed!</strong> Could not connect to MongoDB with the provided URI.
                                    </div>
                                    <?php endif; ?>
                                </div>
                                <?php endif; ?>
                            </div>
                            
                            <div class="mt-4">
                                <a href="../index.html" class="btn btn-secondary">Back to Home</a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
