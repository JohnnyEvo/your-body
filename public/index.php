<?php

use App\Controllers\AuthController;
use App\Controllers\CharacteristicController;
use App\Middleware\Auth;
use App\Middleware\TrailingSlash;
use Slim\Factory\AppFactory;
use Slim\Interfaces\RouteCollectorProxyInterface;
use Slim\Psr7\Request;
use Slim\Psr7\Response;

require __DIR__.'/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__.'/..');
$dotenv->load();

require __DIR__.'/../src/container.php';
require __DIR__.'/../src/capsule.php';

$app = AppFactory::create();

$app->add(new TrailingSlash());
$app->add(new Auth($app->getContainer(), ["path" => ["/api"], "excludes" => ["/api/auth/login", "/api/auth/register"],]));

$app->group('/api', function (RouteCollectorProxyInterface $app) {
    $app->group('/auth', function (RouteCollectorProxyInterface $group) {
        $group->post('/login', AuthController::class.':login');
        $group->post('/register', AuthController::class.':register');
    });
    $app->group('/characteristics', function (RouteCollectorProxyInterface $group) {
        $group->post('', CharacteristicController::class.':store');
        $group->patch('', CharacteristicController::class.':update');
        $group->get('', CharacteristicController::class.':get');
        $group->delete('', CharacteristicController::class.':delete');
    });
});

$app->any('{route:.*}', function (Request $request, Response $response) {
    return $response
        ->withHeader('Content-Type', 'application/json')
        ->withStatus(404);
});

$app->run();
