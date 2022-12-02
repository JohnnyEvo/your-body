<?php

namespace App\Controllers;

use DI\Container;
use JsonException;
use Slim\Psr7\Response;

class Controller
{
    public function __construct(protected Container $container)
    {
    }

    /**
     * @throws JsonException
     */
    public function json(Response $response, mixed $payload = '', int $status = 200): Response
    {
        $response->getBody()->write(json_encode($payload, JSON_THROW_ON_ERROR));

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus($status);
    }
}
