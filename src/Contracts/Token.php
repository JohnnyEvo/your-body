<?php

namespace App\Contracts;

interface Token
{
    public function setSecret(string $secret): self;

    public function setIssuer(string $issuer): self;

    public function setExpiration(int $timestamp): self;

    public function addPayload(string $key, mixed $data): self;

    public function generate(): string;

    public function validate(string $token, string $secret): bool;

    public function refresh(string $token, string $secret): string;

    public function getPayload(string $token, string $secret): array;
}
