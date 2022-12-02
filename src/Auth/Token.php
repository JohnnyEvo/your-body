<?php

namespace App\Auth;

use App\Contracts\Token as TokenContract;
use PsrJwt\Factory\Jwt;
use ReallySimpleJWT\Build;
use ReallySimpleJWT\Exception\BuildException;
use ReallySimpleJWT\Token as RSToken;

class Token implements TokenContract
{
    private Build $builder;

    public function __construct(protected Jwt $jwt)
    {
        $this->builder = $this->jwt->builder();
    }

    /**
     * @throws BuildException
     */
    public function setSecret(string $secret): self
    {
        $this->builder->setSecret($secret);

        return $this;
    }

    public function setIssuer(string $issuer): self
    {
        $this->builder->setIssuer($issuer);

        return $this;
    }

    public function validate(string $token, string $secret): bool
    {
        try {
            return RSToken::validate($token, $secret);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * @throws BuildException
     */
    public function refresh(string $token, string $secret): string
    {
        $payload = $this->getPayload($token, $secret);

        foreach ($payload as $key => $item) {
            $this->addPayload($key, $item);
        }

        $this->setExpiration(time() + 3600);
        return $this->generate();
    }

    public function getPayload(string $token, string $secret): array
    {
        return $this->jwt->parser($token, $secret)->getDecodedPayload();
    }

    public function addPayload(string $key, mixed $data): self
    {
        $this->builder->setPayloadClaim($key, $data);

        return $this;
    }

    /**
     * @throws BuildException
     */
    public function setExpiration(int $timestamp): self
    {
        $this->builder->setExpiration($timestamp);

        return $this;
    }

    public function generate(): string
    {
        $this->builder->setIssuedAt(time());
        return $this->builder->build()->getToken();
    }
}
