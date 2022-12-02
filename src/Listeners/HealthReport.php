<?php

namespace App\Listeners;

use App\Events\CharacteristicUpdated;
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
     * @throws DependencyException
     * @throws TransportExceptionInterface
     * @throws NotFoundException
     */
    public function __invoke(CharacteristicUpdated $characteristicUpdated): void
    {
        $user = $characteristicUpdated->user;

        $report = new \App\Reports\HealthReport($user);
        $template = new \App\Mailers\Templates\HealthReport($report);

        /** @var Mailer $mailer */
        $mailer = $this->container->get('mailer');

        $mailer->template($template);
        $mailer->to($user->email);
        $mailer->send();
    }
}
