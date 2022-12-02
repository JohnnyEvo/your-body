<?php

namespace App\Events;

use App\Models\User;

class CharacteristicUpdated
{
    public function __construct(public User $user)
    {
    }
}
