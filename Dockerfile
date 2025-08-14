# Multi-stage build for PHP Auth System on Render
# Stage 1: Build vendor dependencies
FROM composer:2 AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
# Copy full source BEFORE install so classmap optimization sees project files
COPY . .
RUN composer install --no-dev --prefer-dist --no-progress --optimize-autoloader \
    && find vendor -type f -name '*.rst' -delete || true

# Stage 2: Runtime (Apache + PHP)
FROM php:8.2-apache

# Install system dependencies needed for PECL mongodb extension
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libssl-dev \
       pkg-config \
       ca-certificates \
       git \
       zip unzip \
    && rm -rf /var/lib/apt/lists/*

# Install mongodb extension
RUN pecl install mongodb \
    && docker-php-ext-enable mongodb

# Enable Apache modules
RUN a2enmod rewrite headers

# Configure Apache document root & AllowOverride
ENV APACHE_DOCUMENT_ROOT=/var/www/html
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/000-default.conf \
    && sed -ri -e 's/AllowOverride None/AllowOverride All/g' /etc/apache2/apache2.conf

# Copy application source (excluding via .dockerignore) & vendor from build stage
WORKDIR /var/www/html
COPY . /var/www/html
COPY --from=vendor /app/vendor /var/www/html/vendor

# Set production PHP defaults (override as needed via env)
RUN { \
  echo 'expose_php=0'; \
  echo 'display_errors=Off'; \
  echo 'log_errors=On'; \
  echo 'error_reporting=E_ALL & ~E_DEPRECATED & ~E_STRICT'; \
  echo 'memory_limit=256M'; \
  echo 'upload_max_filesize=16M'; \
  echo 'post_max_size=16M'; \
  echo 'session.cookie_httponly=1'; \
  echo 'session.use_strict_mode=1'; \
  echo 'session.cookie_samesite=Strict'; \
} > /usr/local/etc/php/conf.d/app.ini

# Provide default environment (Render will inject real values)
ENV APP_ENV=production \
    APP_DEBUG=false

# Copy entrypoint to adjust Apache listen port to Render's $PORT
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost/health || exit 1

# Expose (Render sets PORT env; entrypoint patches Apache to use it)
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["apache2-foreground"]
