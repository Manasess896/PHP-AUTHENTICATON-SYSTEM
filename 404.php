<?php
// Set the HTTP response code to 404
http_response_code(404);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>404 - Page Not Found</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: #f8f9fa;
      color: #343a40;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      text-align: center;
    }
    .container {
      max-width: 600px;
      padding: 2rem;
    }
    h1 {
      font-size: 5rem;
      font-weight: 700;
      margin: 0;
      color: #dc3545;
    }
    p {
      font-size: 1.25rem;
      margin-top: 0.5rem;
      margin-bottom: 2rem;
    }
    a {
      display: inline-block;
      padding: 0.75rem 1.5rem;
      font-size: 1rem;
      font-weight: 600;
      color: #fff;
      background-color: #007bff;
      border-radius: 0.3rem;
      text-decoration: none;
      transition: background-color 0.15s ease-in-out;
    }
    a:hover {
      background-color: #0056b3;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>404</h1>
    <p>Sorry, the page you are looking for could not be found.</p>
    <a href="home">Go to Homepage</a>
  </div>
</body>
</html>