<?php

namespace App\Events;

use League\Event\EventDispatcher;

class EventManager
{
    protected ?EventDispatcher $dispatcher;

    public function __construct(protected array $subscribers = [])
    {
        $this->dispatcher = new EventDispatcher();

        if (!empty($subscribers)) {
            $this->addListeners($this->subscribers);
        }
    }

    protected function addListeners(array $subscribers = []): void
    {
        foreach ($subscribers as $event => $listeners) {
            foreach ($listeners as $listener) {
                $this->dispatcher->subscribeTo($event, $listener);
            }
        }
    }

    public function emit(string $event, ...$args): void
    {
        $this->dispatcher->dispatch(new $event(...$args));
    }
}
