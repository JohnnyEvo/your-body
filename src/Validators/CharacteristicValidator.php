<?php

namespace App\Validators;

use App\Contracts\Characteristic;
use App\Contracts\Validator;
use App\Exceptions\BadParamsException;
use Respect\Validation\Validator as v;

class CharacteristicValidator implements Validator, Characteristic
{
    /**
     * @throws BadParamsException
     */
    static public function validate(array $data): bool
    {
        $ageIsValid = self::validateAge($data['age'] ?? null);
        $weightIsValid = self::validateWeight($data['weight'] ?? null);
        $heightIsValid = self::validateHeight($data['height'] ?? null);
        $sexeIsValid = self::validateSexe($data['sexe'] ?? null);
        $activityIsValid = self::validateActivity($data['activity'] ?? null);

        if (
            !$ageIsValid
            || !$weightIsValid
            || !$heightIsValid
            || !$sexeIsValid
            || !$activityIsValid
        ) {
            return false;
        }

        return true;
    }

    /**
     * @throws BadParamsException
     */
    private static function validateAge(mixed $age): bool
    {
        if (!v::optional(v::digit()->greaterThan(0))->validate($age)) {
            throw new BadParamsException("age is not valid.");
        }

        return true;
    }

    /**
     * @throws BadParamsException
     */
    private static function validateWeight(mixed $weight): bool
    {
        if (!v::optional(v::digit()->greaterThan(0))->validate($weight)) {
            throw new BadParamsException("weight is not valid.");
        }

        return true;
    }

    /**
     * @throws BadParamsException
     */
    private static function validateHeight(mixed $height): bool
    {
        if (!v::optional(v::digit()->greaterThan(0))->validate($height)) {
            throw new BadParamsException("height is not valid.");
        }

        return true;
    }

    /**
     * @throws BadParamsException
     */
    private static function validateSexe(mixed $sexe): bool
    {
        if (!v::optional(v::in(self::SEXE))->validate($sexe)) {
            throw new BadParamsException("sexe is not valid.");
        }

        return true;
    }

    /**
     * @throws BadParamsException
     */
    private static function validateActivity(mixed $activity): bool
    {
        if (!v::optional(v::in(self::ACTIVITY))->validate($activity)) {
            throw new BadParamsException("activity is not valid.");
        }

        return true;
    }
}
