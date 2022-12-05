<?php

namespace App\Health;

use App\Exceptions\BadCharacteristicUserException;

class Bmr extends HealthCalculator
{
    /**
     * @throws BadCharacteristicUserException
     */
    function calculate(): float
    {
        /**
         * @todo WIP,manage sexe
         */
        $this->canCalculate();
        return (13.7516 * $this->characteristic->weight) + (5 * $this->characteristic->height) - (6.76 * $this->characteristic->age) + 66.473;
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
