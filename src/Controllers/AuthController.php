<?php

namespace App\Controllers;

use App\Exceptions\BadParamsException;
use App\Models\User;
use App\Validators\LoginUserValidator;
use App\Validators\RegistrationUserValidator;
use JsonException;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class AuthController extends Controller
{
    /**
     * @throws JsonException
     */
    public function register(Request $request, Response $response): \Slim\Psr7\Response
    {
        $data = json_decode($request->getBody(), true) ?? [];

        try {
            RegistrationUserValidator::validate($data);
        } catch (BadParamsException $exception) {
            return $this->json($response, ["errors" => [$exception->getMessage()]], 422);
        }

        $userModel = new User();
        $userModel->email = $data['email'];
        $userModel->password = $data['password'];
        $userModel->save();

        return $this->json($response, [], 201);
    }

    /**
     * @throws JsonException
     */
    public function login(Request $request, Response $response): \Slim\Psr7\Response
    {
        $data = json_decode($request->getBody(), true) ?? [];

        try {
            LoginUserValidator::validate($data);
        } catch (BadParamsException $exception) {
            return $this->json($response, ["errors" => [$exception->getMessage()]], 422);
        }

        $userModel = new User();
        $user = $userModel->whereEmail($data['email'])->first();

        if (!$user) {
            return $this->json($response, ["errors" => ["bad credentials."]], 401);
        }

        if (!password_verify($data['password'], $user->password)) {
            return $this->json($response, ["errors" => ["bad credentials."]], 401);
        }

        $token = $this->container->get('token');
        $token->addPayload('uid', $user->id);
        $token_generated = $token->generate();

        $response->withHeader('Authorization', "Bearer $token_generated");

        return $this->json($response, ['token' => $token_generated], 201);
    }
}
