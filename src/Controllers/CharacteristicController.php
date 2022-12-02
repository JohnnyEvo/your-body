<?php

namespace App\Controllers;

use App\Events\CharacteristicUpdated;
use App\Exceptions\BadParamsException;
use App\Models\Characteristic;
use App\Responses\CharacteristicResponse;
use App\Validators\CharacteristicValidator;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class CharacteristicController extends Controller
{
    public function store(Request $request, Response $response): \Slim\Psr7\Response
    {
        $data = json_decode($request->getBody(), true) ?? [];

        try {
            CharacteristicValidator::validate($data);
        } catch (BadParamsException $exception) {
            return $this->json($response, ["errors" => [$exception->getMessage()]], 422);
        }

        $characteristicModel = new Characteristic();
        if ($characteristicModel->whereUserId($this->container->get('auth')->user()->id)->count()) {
            return $this->json($response, ["errors" => ["characteristic already exists."]], 409);
        }

        $characteristicModel->create([
            ...$data,
            'user_id' => $this->container->get('auth')->user()->id
        ]);
        $this->container->get('event_manager')->emit(CharacteristicUpdated::class, $this->container->get('auth')->user());

        return $this->json($response, [], 201);
    }

    public function get(Request $request, Response $response): \Slim\Psr7\Response
    {
        return $this->json($response, [
            "data" =>
                CharacteristicResponse::render((new Characteristic())->whereUserId($this->container->get('auth')->user()->id)->firstOrFail())
        ], 200);
    }

    public function delete(Request $request, Response $response): \Slim\Psr7\Response
    {
        (new Characteristic())->whereUserId($this->container->get('auth')->user()->id)->firstOrFail()->delete();

        return $this->json($response, [], 204);
    }

    public function update(Request $request, Response $response): \Slim\Psr7\Response
    {
        $data = json_decode($request->getBody(), true) ?? [];

        try {
            CharacteristicValidator::validate($data);
        } catch (BadParamsException $exception) {
            return $this->json($response, ["errors" => [$exception->getMessage()]], 422);
        }

        $this->container->get('auth')->user()->characteristic->update($data);
        $this->container->get('event_manager')->emit(CharacteristicUpdated::class, $this->container->get('auth')->user());

        return $this->json($response, [], 200);
    }
}
