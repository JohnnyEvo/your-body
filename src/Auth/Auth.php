<?php

namespace App\Auth;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;

class Auth
{
    private string $token;

    public function __construct(protected \App\Contracts\Token $tokenService)
    {
    }

    public function setToken(string $token): void
    {
        $this->token = $token;
    }

    public function user(): Model
    {
        $payload = $this->tokenService->getPayload($this->token, env("APP_SECRET"));

        $userModel = new User();

        return $userModel->whereId($payload['uid'])->firstOrFail();
    }
}
