<?php

use App\Controllers\UserController;
use App\Controllers\IndexController;
use App\Middleware\Auth;
use App\Middleware\TrailingSlash;
use Slim\Factory\AppFactory;
use Slim\Interfaces\RouteCollectorProxyInterface;
use Slim\Views\TwigMiddleware;

require __DIR__.'/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->load();

require __DIR__.'/../src/container.php';
require __DIR__.'/../src/capsule.php';

$app = AppFactory::create();

$app->add(new TrailingSlash());
$app->add(TwigMiddleware::createFromContainer($app));
$app->add(new Auth($app->getContainer(), ["path" => ["/api"],]));

$app->group('/api', function (RouteCollectorProxyInterface $app) {
    $app->group('/users', function (RouteCollectorProxyInterface $group) {
        $group->get('', UserController::class . ':index');
    });
});

$app->any('{route:.*}', IndexController::class . ':index');

$app->run();
