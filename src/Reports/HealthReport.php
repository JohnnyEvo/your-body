<?php

namespace App\Reports;

use App\Contracts\Report;
use App\Models\User;

class HealthReport implements Report
{
    public function __construct(protected User $user)
    {
    }

    public function reporting(): array
    {
        return [
            "name" => $this->user->email
        ];
    }
}
