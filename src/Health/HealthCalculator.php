<?php

namespace App\Health;

use App\Models\Characteristic;

abstract class HealthCalculator
{
    public function __construct(protected Characteristic $characteristic)
    {
    }
}
