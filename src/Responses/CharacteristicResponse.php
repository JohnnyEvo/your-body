<?php

namespace App\Responses;

use App\Contracts\Response;
use Illuminate\Database\Eloquent\Model;

class CharacteristicResponse implements Response
{
    static public function render(Model $model): array
    {
        return [
            'id' => $model->id,
            'age' => (int) $model->age,
            'weight' => (int) $model->weight,
            'height' => (int) $model->height,
            'sexe' => $model->sexe,
            'activity' => $model->activity,
            'created_at' => $model->created_at,
            'updated_at' => $model->updated_at,
        ];
    }
}
