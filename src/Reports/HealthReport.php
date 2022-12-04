<?php

namespace App\Reports;

use App\Contracts\Report;
use App\Exceptions\BadCharacteristicUserException;
use App\Models\User;

class HealthReport implements Report
{
    /**
     * @throws BadCharacteristicUserException
     */
    public function __construct(protected User $user)
    {
        if(!$this->user->characteristic->weight) {
            throw new BadCharacteristicUserException('weight is not defined.');
        }

        if(!$this->user->characteristic->height) {
            throw new BadCharacteristicUserException('height is not defined.');
        }
    }

    public function reporting(): array
    {
        return [
            "name" => $this->user->email,
            "bmi" => $this->calculateBmi(),
        ];
    }

    public function calculateBmi(): float
    {
        return round(
            $this->user->characteristic->weight / (($this->user->characteristic->height/100)**2),
            2
        );
    }
}
