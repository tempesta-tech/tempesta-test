# WordPress installation with generated blog data
FROM wordpress:php8.1-apache
COPY --from=composer/composer:2.4.3 /usr/bin/composer /usr/bin/composer

ARG WORDPRESS_URL=http://127.0.0.1
ARG WORDPRESS_DIR=/usr/src/wordpress
ENV WORDPRESS_DIR=$WORDPRESS_DIR
ENV WP_HOME=$WORDPRESS_URL
ENV WP_SITEURL=$WORDPRESS_URL
ENV PATH="${PATH}:/var/www/.composer/vendor/bin"

RUN chown www-data /var/www
COPY --chown=www-data wp-config.php "${WORDPRESS_DIR}/wp-config.php"
COPY --chown=www-data composer.json /var/www/.composer/composer.json
COPY --chown=www-data fixtures.yml /var/www/fixtures.yml
COPY html "$WORDPRESS_DIR"
COPY tt-docker-entrypoint.sh /usr/local/bin
RUN chmod +x /usr/local/bin/tt-docker-entrypoint.sh

USER www-data

RUN composer global update --no-interaction
RUN cp /var/www/.composer/wp-content/wp-sqlite-db/src/db.php "${WORDPRESS_DIR}/wp-content/db.php"

RUN wp core install --path="${WORDPRESS_DIR}" --url="${WORDPRESS_URL}" --title="Tempesta Wordpress Test" --admin_user=admin --admin_password=secret --admin_email=test@tempesta-tech.com --skip-email
RUN wp fixtures load --debug --path="${WORDPRESS_DIR}" --file=/var/www/fixtures.yml

WORKDIR /var/www/html
ENTRYPOINT ["tt-docker-entrypoint.sh"]
CMD ["apache2-foreground"]
