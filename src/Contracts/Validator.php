<?php

namespace App\Contracts;

interface Validator
{
    static public function validate(array $data): bool;
}
