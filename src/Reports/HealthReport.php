<?php

namespace App\Reports;

use App\Contracts\Report;
use App\Exceptions\BadCharacteristicUserException;
use App\Health\Bmi;
use App\Health\Bmr;
use App\Models\User;

class HealthReport implements Report
{
    public function __construct(protected User $user)
    {
    }

    /**
     * @throws BadCharacteristicUserException
     */
    public function reporting(): array
    {
        return [
            "name" => $this->user->email,
            "bmi" => $this->getBmi(),
            "bmr" => $this->getBmr(),
        ];
    }

    /**
     * @throws BadCharacteristicUserException
     */
    public function getBmi(): float
    {
        $bmi = new Bmi($this->user->characteristic);
        return $bmi->calculate();
    }

    /**
     * @throws BadCharacteristicUserException
     */
    public function getBmr(): float
    {
        $bmr = new Bmr($this->user->characteristic);
        return $bmr->calculate();
    }
}
