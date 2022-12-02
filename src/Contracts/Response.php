<?php

namespace App\Contracts;

use Illuminate\Database\Eloquent\Model;

interface Response
{
    static public function render(Model $model): array;
}
