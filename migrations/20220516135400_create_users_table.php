<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/capsule.php';

use Illuminate\Database\Capsule\Manager as Capsule;

return new class
{
    public function __invoke()
    {
        Capsule::schema()->create('users', function ($table) {
            $table->increments('id');
            $table->string('email')->unique();
            $table->timestamps();
        });
    }
};
