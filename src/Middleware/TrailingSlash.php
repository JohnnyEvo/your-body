<?php

namespace App\Middleware;

use Psr\Http\Message\RequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\Psr7\Response;

class TrailingSlash
{
    public function __invoke(Request $request, RequestHandler $handler)
    {
        $uri = $request->getUri();
        $path = $uri->getPath();

        if ($path !== '/' && substr($path, -1) === '/') {
            $path = rtrim($path, '/');
            $uri = $uri->withPath($path);

            if ($request->getMethod() === 'GET') {
                $response = new Response();
                return $response
                    ->withHeader('Location', (string) $uri)
                    ->withStatus(301);
            }

            $request = $request->withUri($uri);
        }

        return $handler->handle($request);
    }
}
