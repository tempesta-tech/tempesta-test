# WordPress installation with generated blog data

FROM wordpress:php8.1-apache
COPY --from=composer/composer:2.4.3 /usr/bin/composer /usr/bin/composer

ARG WORDPRESS_URL=http://127.0.0.1
ARG WORDPRESS_DIR=/usr/src/wordpress
ENV DEBIAN_FRONTEND=noninteractive
ENV WORDPRESS_DIR=$WORDPRESS_DIR
ENV WP_HOME=$WORDPRESS_URL
ENV WP_SITEURL=$WORDPRESS_URL
ENV PATH="${PATH}:/var/www/.composer/vendor/bin"

RUN apt-get -y update && apt install -y imagemagick

RUN chown www-data /var/www
COPY --chown=www-data wp-config.php "${WORDPRESS_DIR}/wp-config.php"
COPY --chown=www-data composer.json /var/www/.composer/composer.json
COPY tt-docker-entrypoint.sh /usr/local/bin
RUN chmod +x /usr/local/bin/tt-docker-entrypoint.sh

USER www-data

RUN composer global update --no-interaction
RUN cp /var/www/.composer/wp-content/wp-sqlite-db/src/db.php "${WORDPRESS_DIR}/wp-content/db.php"

RUN wp core install --path="${WORDPRESS_DIR}" --url="${WORDPRESS_URL}" --title="Tempesta Wordpress Test" --admin_user=admin --admin_password=secret --admin_email=test@tempesta-tech.com --skip-email

# Generate images
RUN mkdir "${WORDPRESS_DIR}/images" && \
    cd "${WORDPRESS_DIR}/images" && \
    for i in $(seq 128 128 2048); \
    do \
      convert -size "$i"x"$i" xc: +noise Random \
      -fill white -draw "scale 7,7 gravity center text 0,0 '$i'" \
      -quality 98 "$i.jpg"; \
    done

# Generate site data
COPY html "$WORDPRESS_DIR"
COPY --chown=www-data fixtures.yml /var/www/fixtures.yml
RUN wp fixtures load --debug --path="${WORDPRESS_DIR}" --file=/var/www/fixtures.yml

WORKDIR /var/www/html
ENTRYPOINT ["tt-docker-entrypoint.sh"]
CMD ["apache2-foreground"]
HEALTHCHECK --interval=0.5s --timeout=1s --retries=10 CMD \
            test -f /var/www/healthy || \
            { curl --fail http://127.0.0.1/health-check || exit 1; } && touch /var/www/healthy
