<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/capsule.php';

use Illuminate\Database\Capsule\Manager as Capsule;

return new class
{
    public function __invoke(): void
    {
        Capsule::schema()->create('characteristics', function ($table) {
            $table->bigIncrements('id');
            $table->unsignedInteger('age')->nullable();
            $table->unsignedDecimal('weight')->nullable();
            $table->unsignedDecimal('height')->nullable();
            $table->enum('sexe', ['male', 'female', 'other'])->nullable();
            $table->enum('activity', ['low', 'moderate', 'active', 'hard'])->nullable();
            $table->foreignId('user_id')->constrained();
            $table->timestamps();
        });
    }
};
