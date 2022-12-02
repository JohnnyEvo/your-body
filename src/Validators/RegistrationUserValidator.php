<?php

namespace App\Validators;

use App\Contracts\Validator;
use App\Exceptions\BadParamsException;
use App\Models\User;
use Respect\Validation\Validator as v;

class RegistrationUserValidator implements Validator
{
    /**
     * @throws BadParamsException
     */
    static public function validate(array $data): bool
    {
        $emailIsValid = self::validateEmail($data['email']??null);
        $passwordIsValid = self::validatePassword($data['password']??null);

        if (
            !$emailIsValid
            || !$passwordIsValid
        ) {
            return false;
        }

        return true;
    }

    /**
     * @throws BadParamsException
     */
    private static function validateEmail(mixed $email): bool
    {
        if (!v::email()->validate($email)) {
            throw new BadParamsException("email is not valid.");
        }

        $user = new User();
        if ($user->whereEmail($email)->count()) {
            throw new BadParamsException("email already exists.");
        }

        return true;
    }

    /**
     * @throws BadParamsException
     */
    private static function validatePassword(mixed $password): bool
    {
        if (!v::notBlank()->validate($password)) {
            throw new BadParamsException("password should not be blank.");
        }

        if (!v::length(8)->validate($password)) {
            throw new BadParamsException("password should be 8 min characters.");
        }

        return true;
    }
}
