<?php

return [
    \App\Events\CharacteristicUpdated::class => [new \App\Listeners\HealthReport($container)],
];
