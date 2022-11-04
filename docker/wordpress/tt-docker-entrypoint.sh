#!/usr/bin/env bash
set -ex
env
wp --path="${WORDPRESS_DIR}" option update home "${WP_HOME}"
wp --path="${WORDPRESS_DIR}" option update siteurl "${WP_SITEURL}"
exec docker-entrypoint.sh "${@}"
