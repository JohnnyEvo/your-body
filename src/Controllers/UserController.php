<?php

namespace App\Controllers;

use App\Models\User;
use JsonException;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class UserController extends Controller
{
    /**
     * @throws JsonException
     */
    public function index(Request $request, Response $response)
    {
        $users = User::all();
        return $this->json($response, $users);
    }
}
