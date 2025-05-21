# PHP AUTHENTICATION SYSTEM

A secure, modern authentication system built with PHP and MongoDB, featuring comprehensive security measures including secure password reset functionality, CSRF protection, and reCAPTCHA integration.

## Features

- User registration with email verification
- Secure login with brute force protection
- Password reset functionality
- Two-factor authentication (2FA)
- Remember me functionality
- CSRF protection
- Input validation and sanitization
- MongoDB integration for data storage
- Secure session management
- Content security headers
- Responsive UI using Bootstrap

## Requirements

- PHP 7.4 or higher
- MongoDB server
- Composer (for managing dependencies)
- Web server with SSL support (recommended for production)
- Google reCAPTCHA API keys

## Installation

1. Clone the repository to your web server directory:

   ```bash
   git clone https://github.com/yourusername/auth-system.git
   cd auth-system
   ```

2. Install dependencies via Composer:

   ```bash
   composer install
   ```

3. Copy the example environment file and update it with your settings:

   ```bash
   cp .env.example .env
   ```

   Then edit the `.env` file with your specific configuration:

   ```plaintext
   # Application settings
   APP_NAME="Authentication System"
   APP_URL="http://localhost/auth"
   APP_DEBUG=true

   # MongoDB settings
   MONGODB_URI="mongodb://username:password@localhost:27017"
   MONGODB_DATABASE="auth"

   # Email settings
   SMTP_HOST="smtp.example.com"
   SMTP_PORT=587
   SMTP_USERNAME="your-email@example.com"
   SMTP_PASSWORD="your-password"
   SMTP_FROM="noreply@example.com"
   SMTP_FROM_NAME="Authentication System"

   # Security settings
   JWT_SECRET="your-jwt-secret-key"
   CSRF_TOKEN_EXPIRY=7200
   SESSION_LIFETIME=3600

   # reCAPTCHA settings
   RECAPTCHA_SITE_KEY="your-recaptcha-site-key"
   RECAPTCHA_SECRET_KEY="your-recaptcha-secret-key"
   ```

4. Create the required MongoDB collections:

   - `users`
   - `password_resets`
   - `sessions`
   - `failed_logins`

5. Ensure proper permissions are set:
   
   For Linux/Unix:

   ```bash
   chmod 755 -R /path/to/auth
   chmod 777 -R /path/to/auth/logs
   ```
   
   For Windows, ensure proper folder permissions in XAMPP environments:

   ```powershell
   # Verify XAMPP has proper file access in Windows
   # You can adjust permissions through File Explorer > Properties > Security tab
   ```

## Folder Structure

```plaintext
auth/
├── auth-handlers/         # Authentication handlers
│   ├── handlers/          # Request handlers
│   │   ├── contact_handler.php
│   │   └── register_handler.php
│   ├── logs/              # Application logs
│   │   └── email.log, error.log, etc.
│   ├── setup/             # Setup utilities
│   │   └── install_phpmailer.php
│   └── utils/             # Utility functions
│       ├── csrf_protection.php
│       ├── email.php
│       ├── mongodb_helper.php
│       ├── rate_limiter.php
│       ├── recaptcha.php
│       ├── session_manager.php
│       └── validation.php
├── config/                # Configuration files
│   ├── config.php         # Main configuration
│   ├── database.php       # Database configuration
│   ├── env_loader.php     # Environment variable loader
│   └── mongodb_setup.php  # MongoDB setup
├── dashboard/             # User dashboard
│   ├── dashboard.php      # Main dashboard page
│   └── logout.php         # Logout functionality
├── logs/                  # Log files
│   ├── password_reset.log
│   └── mail/
├── pages/                 # Public-facing pages
│   ├── contact.php
│   ├── forgot-password.php
│   ├── login.php
│   ├── register.php
│   ├── registration-success.php
│   ├── reset-password.php
│   └── verify.php
├── vendor/                # Composer dependencies
├── .env                   # Environment variables
├── .env.example           # Example environment configuration
├── .htaccess              # Apache web server configuration
└── index.html             # Landing page
```

## Security Features

- **Password Storage**: All passwords are hashed using PHP's `password_hash()` with bcrypt
- **CSRF Protection**: All forms include CSRF tokens to prevent cross-site request forgery
- **Brute Force Protection**: Automatic account lockout after multiple failed login attempts
- **Content Security Headers**: Implements strict security headers for XSS protection
- **Secure Session Management**: Sessions are protected against hijacking and fixation attacks
- **Input Validation**: All user inputs are validated and sanitized
- **reCAPTCHA**: Integration with Google reCAPTCHA to prevent automated attacks
- **Rate Limiting**: API requests are rate-limited to prevent abuse
- **Secure Password Reset**: One-time tokens with expiration for password reset functionality
- **Logging**: Comprehensive logging of authentication events and security incidents

## Usage

### Registration

Users can create an account by providing:

- Email address
- Password (with strength requirements)
- Basic profile information

A verification email is sent to confirm the email address before the account is activated.

### Login

Users can log in using:

- Email address
- Password
- Optional 2FA code (if enabled)
- Remember me option for extended session

### Password Reset

1. User requests a password reset by entering their email
2. A secure token is generated and sent via email
3. User clicks the link and sets a new password
4. Old sessions are invalidated for security

### Two-Factor Authentication

1. Navigate to profile settings to enable 2FA
2. Scan the provided QR code with an authenticator app
3. Enter the verification code to confirm setup
4. 2FA will be required for future logins

## Development

To run the project in development mode:

1. Set `APP_DEBUG=true` in your `.env` file
2. Enable PHP error reporting in your `php.ini`
3. Use the built-in PHP server for testing:

   ```bash
   php -S localhost:8000
   ```

## Production Deployment

For production environments:

1. Set `APP_DEBUG=false` in your `.env` file
2. Use a proper web server (Apache, Nginx) with SSL
3. Secure the `.env` file from public access
4. Set up proper firewall and network security
5. Configure regular database backups
6. Enable HTTPS and HSTS for secure connections
7. Consider implementing rate limiting at the server level

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Credits

- [Bootstrap](https://getbootstrap.com/)
- [MongoDB PHP Driver](https://www.php.net/manual/en/set.mongodb.php)
- [Google reCAPTCHA](https://www.google.com/recaptcha/)
- [PHPMailer](https://github.com/PHPMailer/PHPMailer)

## Contributions

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
