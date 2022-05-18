<?php

use DI\Container;
use Slim\Factory\AppFactory;
use Slim\Views\Twig;
use Kreait\Firebase\Factory;

$container = new Container();
AppFactory::setContainer($container);

$container->set('view', function () {
    return Twig::create(__DIR__.'/../resources/views', [
        'cache' => $_ENV['APP_DEBUG'] ? false : __DIR__.'/../storage/tmp/views',
    ]);
});
$container->set(Factory::class, function () {
    return (new Factory)->withServiceAccount(__DIR__.'/../firebase.json');
});
$container->set('auth', function (Factory $factory) {
    return $factory->createAuth();
});
