<?php

namespace App\Listeners;

use App\Events\CharacteristicUpdated;

class HealthReport
{
    public function __invoke(CharacteristicUpdated $characteristicUpdated): void
    {
        /**
         * @todo call mailer
         */
    }
}
