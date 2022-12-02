<?php

use Illuminate\Database\Capsule\Manager as Capsule;

$capsule = new Capsule;
$capsule->addConnection([
    "driver" => "mysql",
    "host" =>  env('DB_HOST'),
    "database" =>  env('DB_NAME'),
    "username" => env('DB_USERNAME'),
    "password" => env('DB_PASSWORD')
]);
$capsule->setAsGlobal();
$capsule->bootEloquent();
