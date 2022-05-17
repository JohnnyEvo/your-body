<?php

namespace App\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class IndexController extends Controller
{
    public function index(Request $request, Response $response)
    {
        return $this->render($response, 'main.twig');
    }
}
