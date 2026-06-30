FROM php:8.1-apache

RUN apt-get update && apt-get install -y unzip git && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

RUN a2enmod rewrite

WORKDIR /var/www/html

COPY . /var/www/html/sdk

WORKDIR /var/www/html/sdk
RUN composer install --no-dev --optimize-autoloader

RUN echo '<VirtualHost *:80>\n\
    DocumentRoot /var/www/html/sdk/examples/sample-site\n\
    <Directory /var/www/html/sdk/examples/sample-site>\n\
        AllowOverride All\n\
        Require all granted\n\
        FallbackResource /index.php\n\
    </Directory>\n\
    ErrorLog ${APACHE_LOG_DIR}/error.log\n\
    CustomLog ${APACHE_LOG_DIR}/access.log combined\n\
</VirtualHost>' > /etc/apache2/sites-available/000-default.conf

EXPOSE 80
