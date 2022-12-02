<?php

namespace App\Mailers;

use App\Models\User;
use DI\Container;

class HealthReportMailer
{
    public function __construct(protected Container $container)
    {
    }

    static public function send(User $user): void
    {
        dd($user);
    }
}
