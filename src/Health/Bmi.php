<?php

namespace App\Health;

use App\Exceptions\BadCharacteristicUserException;

class Bmi extends HealthCalculator
{
    /**
     * @throws BadCharacteristicUserException
     */
    function calculate(): float
    {
        $this->canCalculate();
        return round($this->characteristic->weight / (($this->characteristic->height / 100) ** 2), 2);
    }

    /**
     * @throws BadCharacteristicUserException
     */
    private function canCalculate()
    {
        if(!$this->characteristic->weight) {
            throw new BadCharacteristicUserException('weight is not defined.');
        }

        if(!$this->characteristic->height) {
            throw new BadCharacteristicUserException('height is not defined.');
        }
    }
}
