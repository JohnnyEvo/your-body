<?php

use DI\Container;
use Slim\Factory\AppFactory;
use Slim\Views\Twig;

$container = new Container();
AppFactory::setContainer($container);

$container->set('view', function () {
    return Twig::create(__DIR__.'/../resources/views', [
        'cache' => false
        // __DIR__.'/../storage/tmp/views'
    ]);
});
