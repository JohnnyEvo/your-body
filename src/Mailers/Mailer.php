<?php

namespace App\Mailers;

use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\Mailer as MailerService;
use Symfony\Component\Mime\Email;

class Mailer
{
    private Email $email;

    public function __construct(protected MailerService $mailer)
    {
        $this->email = new Email();
        $this->email->from(env('MAIL_FROM'));
    }

    public function to(string $to): void
    {
        $this->email->to($to);
    }

    public function subject(string $subject): void
    {
        $this->email->subject($subject);
    }

    public function text(string $text): void
    {
        $this->email->text($text);
    }

    public function html(string $text): void
    {
        $this->email->html($text);
    }

    /**
     * @throws TransportExceptionInterface
     */
    public function send(): void
    {
        $this->mailer->send($this->email);
    }
}
