<?php

namespace App\Listeners;

use App\Events\CharacteristicUpdated;
use App\Exceptions\BadCharacteristicUserException;
use App\Mailers\Mailer;
use DI\Container;
use DI\DependencyException;
use DI\NotFoundException;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;

class HealthReport
{
    public function __construct(protected Container $container)
    {
    }

    /**
     * @param  CharacteristicUpdated  $characteristicUpdated
     * @throws DependencyException
     * @throws NotFoundException
     * @throws TransportExceptionInterface
     */
    public function __invoke(CharacteristicUpdated $characteristicUpdated): void
    {
        $user = $characteristicUpdated->user;

        try {
            $report = new \App\Reports\HealthReport($user);
            $template = new \App\Mailers\Templates\HealthReport($report);
        } catch (BadCharacteristicUserException $exception) {
            $template = new \App\Mailers\Templates\Promotion($user);
        }

        /** @var Mailer $mailer */
        $mailer = $this->container->get('mailer');

        $mailer->template($template);
        $mailer->to($user->email);
        $mailer->send();
    }
}
