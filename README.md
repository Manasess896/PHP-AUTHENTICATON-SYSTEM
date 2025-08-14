# PHP Authentication System Template

Secure, modular PHP authentication & account management template built with MongoDB, PHPMailer, TOTP‑based 2FA, Google reCAPTCHA, CSRF protection, and hardened session flows. Designed for rapid bootstrapping of production‑grade authentication in traditional (non‑framework) PHP environments (XAMPP / LAMP / Nginx + PHP‑FPM).

---

## Contents

1. Features Overview
2. Technology Stack & Libraries
3. Architecture & File Responsibilities
4. Request Routing (.htaccess)
5. Authentication & Security Flows
6. Two‑Factor Authentication (TOTP + Forced Admin Flow)
7. Email Verification & Password Reset
8. Newsletter + Contact Modules
9. Security Controls (Defense in Depth)
10. Environment Configuration (.env)
11. Local Development Setup
12. Production Hardening Checklist
13. Extending / Customizing
14. Troubleshooting

<<<<<<< HEAD
---
=======
**Having trouble getting started?** Check out our comprehensive [**FAQ Guide**](https://manasess896.github.io/PHP-AUTHENTICATON-SYSTEM/faq.html) for solutions to common issues including:
>>>>>>> 64318e13bc7c2c716941dc80542bcafe4257aa77

## 1. Features Overview

<<<<<<< HEAD
| Category  | Capability                                                                                                                 |
| --------- | -------------------------------------------------------------------------------------------------------------------------- |
| Core Auth | Registration, login, logout, session protection                                                                            |
| Email     | Verification links, password reset, newsletter broadcast, contact confirmation                                             |
| 2FA       | TOTP enrollment, runtime enforcement, forced admin enablement, password re‑auth gate for users                             |
| Security  | CSRF tokens, reCAPTCHA v2, password hashing (`password_hash()`), rate limiting via Mongo collections, session regeneration |
| Admin     | Dashboard for contacts + newsletter blast, enforced 2FA bootstrap via signed email code                                    |
| UX        | Bootstrap 5 UI, SweetAlert2 feedback, progressive enhancement (JS optional for core)                                       |
| Data      | MongoDB collections: `users`, `attempts`, `contacts`, `newsletter`                                                         |
=======
➡️ **[View Complete FAQ Guide](https://manasess896.github.io/PHP-AUTHENTICATON-SYSTEM/faq.html)**
>>>>>>> 64318e13bc7c2c716941dc80542bcafe4257aa77

---

## 2. Technology Stack & Libraries

| Library                              | Purpose                                                        |
| ------------------------------------ | -------------------------------------------------------------- |
| **vlucas/phpdotenv**                 | Loads `.env` configuration (secrets kept out of code)          |
| **mongodb/mongodb**                  | Official MongoDB PHP driver wrapper (CRUD + BSON types)        |
| **PHPMailer/PHPMailer**              | SMTP email delivery (verification, reset, notices, newsletter) |
| **spomky-labs/otphp**                | Time‑based One‑Time Password (TOTP) generation/verification    |
| **paragonie/constant_time_encoding** | Side‑channel safe encoding utilities (dependency chain)        |
| **Google reCAPTCHA**                 | Bot mitigation on sensitive forms (login, register, etc.)      |
| **Bootstrap 5**                      | Rapid, accessible UI layout & components                       |
| **SweetAlert2**                      | User‑friendly modal notifications                              |
| **Symfony Polyfills**                | Runtime compatibility for older PHP environments               |

PHP native primitives used: `password_hash()`, `password_verify()`, `random_bytes()`, `hash_equals()`, `session_regenerate_id()`.

---

## 3. Architecture & File Responsibilities

| File / Path            | Responsibility                                                                |
| ---------------------- | ----------------------------------------------------------------------------- |
| `.htaccess`            | Pretty URLs → `pages/*.php` mapping; 404 handling; index aliasing             |
| `index.php`            | Landing + newsletter signup (reCAPTCHA + rate limit)                          |
| `pages/register.php`   | User registration + initial verification email issuance                       |
| `pages/email.php`      | Resend verification flow with attempt limiting (session gated)                |
| `pages/verify.php`     | One‑time token consumption to mark `is_verified`                              |
| `pages/login.php`      | Credential auth + reCAPTCHA + conditional 2FA staging (pending state)         |
| `pages/2fa-verify.php` | Verifies TOTP after password stage (promotes session)                         |
| `pages/2fa-setup.php`  | TOTP enrollment (admin: forced email code path / user: password re‑auth gate) |
| `pages/dashboard.php`  | Authenticated user home; triggers password re‑auth for 2FA enrollment         |
| `pages/admin.php`      | Admin console (contacts, newsletter) + forced 2FA email code bootstrap        |
| `pages/reset.php`      | Initiate password reset (token + email dispatch)                              |
| `pages/password.php`   | Consume reset token and set new password                                      |
| `contact.php`          | Public contact form with reCAPTCHA + persistence + confirmation email         |
| `faq.html`             | (Example static informational page)                                           |
| `vendor/*`             | Composer dependencies (excluded in VCS by default)                            |

Collections summary:

- `users`: credentials, flags (`is_admin`, `is_verified`, `twofa_secret`), transient fields (reset, forced 2FA codes).
- `attempts`: generic rate limiting / abuse tracking.
- `contacts`: stored messages + resolution status.
- `newsletter`: subscriber emails.

---

## 4. Request Routing (.htaccess)

Pretty URL pattern (example):

```text
/login  -> pages/login.php
/register -> pages/register.php
/admin-dashboard -> pages/admin.php
/2fa-setup -> pages/2fa-setup.php
/2fa-verify -> pages/2fa-verify.php
```

Keeps URLs framework‑like while staying on vanilla Apache + mod_rewrite.

---

## 5. Authentication & Security Flows

### Login Flow (User or Admin)

1. User submits email + password + reCAPTCHA.
2. If account unverified → redirect to resend verification path.
3. If `twofa_secret` present → create `pending_2fa_user_id` session and redirect to `/2fa-verify`.
4. Otherwise grant full session (`user_id` or admin flags).

### Session Model

- Pending 2FA: only `pending_2fa_user_id` present (no access to protected dashboards).
- Full: `user_id` or `admin_id` + role booleans.
- Admin forced 2FA state uses temporary email code fields in `users` document until success.

### Password Re‑Auth (User 2FA Enrollment)

Before enabling 2FA, user must confirm password via AJAX (sets `user_2fa_reauth_passed`). Prevents silent hijack enabling attacker’s 2FA.

<<<<<<< HEAD
### Admin Forced 2FA

If admin logs in without `twofa_secret`, JS dialogue triggers:

- Sends 6‑digit email code (max 3 sends, 10‑minute expiry).
- Verifies code (3 attempts) → session flag `force2fa_email_passed` → redirect to `/2fa-setup`.

---

## 6. Two‑Factor Authentication (TOTP)

Library: `spomky-labs/otphp`.

- Enrollment: generate secret + provisioning URI (issuer/name) + display QR.
- Verification window: default (can adjust tolerance if user device drift common).
- After success: session is intentionally destroyed → user must log in again (strengthens post‑enrollment security posture).
- Reconfiguration path allowed (requires same re‑auth gating pattern if you add secret reset logic).

---

## 7. Email Verification & Password Reset

### Email Verification

- Token: 64 hex chars (random_bytes) + 30‑minute expiry field.
- `verify.php` validates token + expiry → sets `is_verified` and removes transient fields.
- Resend attempts limited (session counter) to reduce abuse.
=======
- Email address
- Password
- Remember me option for extended session
>>>>>>> 64318e13bc7c2c716941dc80542bcafe4257aa77

### Password Reset

- Reset initiation issues token (similar pattern) + email with link.
- Consumption page validates token + optional rate limiting + enforces password strength policy (extend yourself).

---

## 8. Newsletter & Contact Modules

**Newsletter**: Subscribes with reCAPTCHA + duplicate check + rate limiting (`attempts` collection). Admin broadcast uses PHPMailer BCC fanout (basic; consider chunking for large lists).  
**Contact Form**: Sanitizes input, length caps, stores record, sends confirmation. Admin can mark resolved (AJAX).

---

## 9. Security Controls (Defense in Depth)

| Control                  | Purpose                                                                                                                                                          |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CSRF tokens              | All state‑changing POST forms                                                                                                                                    |
| reCAPTCHA                | Thwarts scripted credential + signup abuse                                                                                                                       |
| Password hashing         | PHP default Argon2i/BCrypt (depends on PHP build) via `password_hash()`                                                                                          |
| Session segregation      | Pending vs full vs forced 2FA bootstrap                                                                                                                          |
| Forced admin 2FA         | Reduces window of privilege abuse                                                                                                                                |
| Password re‑auth for 2FA | Prevents silent 2FA enrollment by attacker with stolen cookie only                                                                                               |
| Email attempt caps       | Limits token/code spamming                                                                                                                                       |
| Rate limiting collection | Generic pattern for per-IP throttling                                                                                                                            |
| Output escaping          | `htmlspecialchars()` in templates                                                                                                                                |
| Secret handling          | `.env` (NEVER commit secrets to VCS)                                                                                                                             |
| Randomness               | `random_bytes()` / `random_int()` cryptographic RNG                                                                                                              |
| XSS Mitigation           | All user‑derived data is escaped via `e()` (HTML), `escape_attr()`, or `json_encode()` for JS contexts. Avoid inline event handlers and prefer external scripts. |

<<<<<<< HEAD
Suggested additions (not yet implemented):
=======
**💡 Troubleshooting:** If you encounter any issues during development, check the [FAQ Guide](https://manasess896.github.io/PHP-AUTHENTICATON-SYSTEM/faq.html) for common solutions.
>>>>>>> 64318e13bc7c2c716941dc80542bcafe4257aa77

- Content Security Policy (CSP) header
- Strict Transport Security (HSTS) (production only w/ HTTPS)
- SameSite=Strict + secure cookie flags (set via PHP ini or `session_set_cookie_params`)
- Audit logging collection for security events
- TTL Indexes for transient code/token fields

---

## 10. Environment Configuration (.env)

Example keys (do NOT ship real secrets):

```bash
MONGODB_URI=...
MONGODB_DATABASE=auth
APP_NAME=PHP-AUTHENTICATION-TEMPLATE
MAIL_HOST=smtp.example.com
MAIL_PORT=587
MAIL_USERNAME=no-reply@example.com
MAIL_PASSWORD=CHANGE_ME
MAIL_ENCRYPTION=tls
MAIL_FROM_ADDRESS=no-reply@example.com
MAIL_FROM_NAME="Auth System"
RECAPTCHA_SITE_KEY=...
RECAPTCHA_SECRET_KEY=...
EMAIL_VERIFICATION_URL=https://yourdomain.com/verify-email
PASSWORD_RESET_URL=https://yourdomain.com/reset-password
```

Production note: rotate credentials, never commit real secrets, remove test accounts.

---

## 11. Local Development Setup

1. Clone repo into web root (e.g. `htdocs`).
2. Run `composer install`.
3. Copy `.env.example` → `.env` (create one if not present) and fill values.
4. Ensure MongoDB Atlas or local instance reachable; whitelist IP for Atlas.
5. Start Apache (or PHP built‑in server if you adjust routing) & navigate to `/home`.
6. Register a test user → verify email → login → (optionally) enable 2FA.

Troubleshooting email: use a local SMTP sink (e.g. MailHog) during development.

---

## 12. Production Hardening Checklist

| Item                                       | Status |
| ------------------------------------------ | ------ |
| Enforce HTTPS + redirect HTTP              | ☐      |
| Secure / HttpOnly / SameSite cookies       | ☐      |
| Remove verbose error output                | ☐      |
| Add CSP + X-Frame-Options headers          | ☐      |
| Configure log aggregation                  | ☐      |
| Enable database user with least privilege  | ☐      |
| Implement backup & secrets rotation        | ☐      |
| Add audit trail for admin actions          | ☐      |
| Enable Web Application Firewall (optional) | ☐      |

---

## 13. Extending / Customizing

| Goal                  | Guidance                                                      |
| --------------------- | ------------------------------------------------------------- |
| Add roles/permissions | Add `roles` array in user doc + middleware guard per page     |
| Add account lockouts  | Increment fail counter; add `locked_until` timestamp          |
| Add TOTP backup codes | Pre‑generate hashed codes; single‑use consumption             |
| Switch to JWT / SPA   | Abstract auth core; issue short‑lived access + refresh tokens |
| Add WebAuthn          | Introduce FIDO2 library; store public key credentials         |

---

## 14. Troubleshooting

## Session Variables Reference

| Session Key                           | Scope / When Set                                     | Purpose                                                   | Cleared / Expires                                 |
| ------------------------------------- | ---------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------- |
| `csrf_token`                          | First page load needing CSRF                         | Anti-CSRF token for form + AJAX validation                | Rotated manually if desired; persists for session |
| `pending_verification`                | After registration or login with unverified email    | Flags user must verify email before full access           | Removed after successful verification or logout   |
| `user_email`                          | Registration / resend verification                   | Tracks email for verification resend workflow             | Cleared on verification / logout                  |
| `verification_attempts`               | During verification resend attempts                  | Rate limiting resend or code usage                        | Reset on success or session end                   |
| `registration_time`                   | Registration                                         | Timestamp used to limit verification window or tokens     | Session end                                       |
| `pending_2fa_user_id`                 | After password auth when user has 2FA enabled        | Stages identity awaiting TOTP verification                | Deleted after successful TOTP or logout           |
| `pending_2fa_is_admin`                | Same as above (admin accounts)                       | Notes staged login intends to become admin                | Deleted after TOTP or logout                      |
| `role`                                | On full login (`admin` or `user`)                    | Canonical role discriminator for access checks            | Cleared on logout/session reset                   |
| `is_admin`                            | Legacy compatibility (boolean)                       | Backward compatible admin flag used in older checks       | Cleared / re-set on login or session reset        |
| `admin_id`                            | Admin full session                                   | MongoDB ObjectId for admin user                           | Cleared on logout                                 |
| `admin_username`                      | Admin full session                                   | Display name for admin UI                                 | Cleared on logout                                 |
| `user_id`                             | User full session                                    | MongoDB ObjectId for standard user                        | Cleared on logout                                 |
| `username`                            | User full session                                    | Display / greeting name                                   | Cleared on logout                                 |
| `twofa_setup_secret`                  | During 2FA enrollment (pre-confirm)                  | Temporary TOTP secret awaiting confirmation               | Deleted after success or cancel/logout            |
| `twofa_setup_uri`                     | During 2FA enrollment                                | Provisioning URI for QR rendering                         | Deleted after success or cancel/logout            |
| `force2fa_email_passed`               | Admin forced 2FA bootstrap after email code success  | Grants access to `/2fa-setup` for admin                   | Cleared after enrollment or session reset         |
| `user_2fa_reauth_passed`              | After user password modal success for 2FA enrollment | Gate to allow `/2fa-setup` entry for users                | Cleared after enrollment or logout                |
| `reauth_2fa_attempts`                 | While user re-auth modal attempts ongoing            | Counts failed password attempts for 2FA enrollment gating | Cleared on success or session end                 |
| `force_admin_2fa` _(future/optional)_ | Potential feature flag                               | Would enforce forced 2FA globally                         | N/A                                               |

### Session Design Notes

1. Separation: `pending_*` sessions hold pre-elevation state (email verification or 2FA) and never mix with full privilege markers (`user_id`, `admin_id`).
2. Role Canonicalization: `role` centralizes role logic; legacy keys retained for gradual refactor.
3. Post-2FA Hardening: After enabling 2FA, session is destroyed to prevent fixation; fresh login required.
4. Enrollment Gating: Differentiated gating (`force2fa_email_passed` for admins, `user_2fa_reauth_passed` for users) prevents privilege confusion or silent enrollment by attacker-controlled sessions.
5. Defensive Clearing: Login and 2FA promotion steps explicitly unset conflicting role/session markers before assigning new state.
6. Future Improvements: Add timestamp + expiry for `user_2fa_reauth_passed` (e.g., 5-minute validity) and IP/user-agent binding for sensitive flags.

| Symptom                     | Potential Cause                           | Fix                                                         |
| --------------------------- | ----------------------------------------- | ----------------------------------------------------------- |
| Email not sending           | Blocked SMTP / wrong credentials          | Verify SMTP port & encryption; test with `openssl s_client` |
| 2FA codes always invalid    | Clock skew or secret truncated            | Verify server time (NTP) and copy full secret               |
| reCAPTCHA always fails      | Missing server secret or blocked outbound | Check `.env` keys & firewall egress                         |
| Session lost after redirect | Cookie path/domain mismatch               | Verify cookie params & host consistency                     |
| Mongo auth failure          | Wrong URI or IP not whitelisted           | Recreate connection string; update Atlas IP list            |

---

## License & Attribution

This template aggregates several MIT licensed components. Verify each dependency’s license before commercial distribution. Replace placeholder branding (`AuthBoost`) with your project name.

---

## Disclaimer

This codebase is a starting point. Perform a security review and penetration test prior to production launch. Remove demo/test artifacts and sanitize any imported sample data.

---

Happy building! Strengthen authentication early—retrofits cost more later.
