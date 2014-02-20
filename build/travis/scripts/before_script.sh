#!/bin/sh

echo "Executing for PHP version $TRAVIS_PHP_VERSION"

if [ $TRAVIS_PHP_VERSION == "hhvm" ]
then
    cd $TRAVIS_BUILD_DIR
    echo '{"name":"fieryprophet/php-sandbox","description": "A PHP library that can be used to run PHP code in a sandbox environment","keywords": ["php", "sandbox", "parser", "whitelist", "blacklist"],"type": "library","homepage": "http://www.fieryprophet.com/phpsandbox","license": "BSD-3-Clause","authors": [    {        "name": "Elijah Horton"    }],"repositories": [    {        "type": "vcs",        "url": "https://github.com/fieryprophet/php-sandbox"    }],"minimum-stability": "dev","require": {    "php": ">=5.3.2",    "nikic/php-parser": "1.0.*@dev",    "jeremeamia/FunctionParser": "dev-master"},"require-dev": {    "phpunit/phpunit": "3.7.*"},"autoload": {    "psr-4": {        "PHPSandbox\\": "src/",        "PHPParser\\": "vendor/nikic/php-parser/lib/PhpParser/"    }}}' > composer.json
fi
    composer install
