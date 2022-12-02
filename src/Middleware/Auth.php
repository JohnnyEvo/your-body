<?php

namespace App\Middleware;

use DI\Container;
use DI\DependencyException;
use DI\NotFoundException;
use Illuminate\Support\Str;
use JetBrains\PhpStorm\Pure;
use Psr\Http\Message\RequestInterface as Request;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\Psr7\Response;

class Auth
{
    public function __construct(protected Container $container, protected array $params,)
    {
    }

    /**
     * @throws DependencyException
     * @throws NotFoundException
     */
    public function __invoke(Request $request, RequestHandler $handler): Response|ResponseInterface
    {
        $uri = $request->getUri();
        $path = $uri->getPath();

        if (!$this->routeShouldBeCatch($path)) {
            return $handler->handle($request);
        }

        $token = $this->getToken($request);

        if (!$token) {
            return $this->abort();
        }

        $verifiedToken = $this->getVerifiedToken($token);
        if (!$verifiedToken) {
            return $this->abort();
        }

        $token = $this->container->get('token')->refresh($token, env('APP_SECRET'));

        $this->container->get('auth')->setToken($token);

        $response = $handler->handle($request);

        $response->withHeader('Authorization', $token);

        return $response;
    }

    #[Pure] private function routeShouldBeCatch($path): bool
    {
        return Str::startsWith($path, $this->params['path']) && !in_array($path, $this->params['excludes']);
    }

    private function getToken(Request $request): null|string
    {
        $authorizations = $request->getHeader('Authorization');
        if (!empty($authorizations) && preg_match('/Bearer\s(\S+)/', $authorizations[0], $matches)) {
            return $matches[1];
        }
        return null;
    }

    private function abort(): Response
    {
        return (new Response())->withStatus(403);
    }

    private function getVerifiedToken(string $token)
    {
        return $this->container->get('token')->validate($token, env('APP_SECRET'));
    }
}
