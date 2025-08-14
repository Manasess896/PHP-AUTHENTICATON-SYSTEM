#!/usr/bin/env bash
set -euo pipefail
PORT_ENV="${PORT:-8080}"
# Update Apache listen port if PORT provided by Render
if ! grep -q "Listen ${PORT_ENV}" /etc/apache2/ports.conf ; then
  sed -i "s/^Listen .*/Listen ${PORT_ENV}/" /etc/apache2/ports.conf || true
fi
export APACHE_RUN_USER=www-data
export APACHE_RUN_GROUP=www-data
# Basic health endpoint if not present
if [ ! -f /var/www/html/health ]; then
  echo "OK" > /var/www/html/health
fi
exec "$@"
