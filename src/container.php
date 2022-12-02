<?php

use DI\Container;
use Slim\Factory\AppFactory;

$container = new Container();
AppFactory::setContainer($container);

$container->set('token', function (\App\Auth\Token $token) {
    $token->setSecret(env('APP_SECRET'));
    $token->setIssuer(env('APP_BASE'));
    $token->setExpiration(time() + 3600);

    return $token;
});

$container->set(\App\Contracts\Token::class, $container->get('token'));

$container->set('auth', function (\App\Auth\Auth $auth) {
    return $auth;
});

$container->set('mailer', function (\App\Mailers\Mailer $mailer) {
    return $mailer;
});

$container->set('event_manager', function ($container) {
    $events = require __DIR__ . '/events.php';
    return new \App\Events\EventManager($events);
});
