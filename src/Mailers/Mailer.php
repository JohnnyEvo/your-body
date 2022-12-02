<?php

namespace App\Mailers;

use App\Contracts\MailerTemplate;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\Mailer as MailerService;
use Symfony\Component\Mailer\Transport;
use Symfony\Component\Mime\Email;

class Mailer
{
    private Email $email;
    private ?MailerTemplate $template;
    private MailerService $mailer;

    public function __construct()
    {
        $transport = Transport::fromDsn(env('MAIL_DSN'));

        $this->mailer = new MailerService($transport);
        $this->email = new Email();
        $this->email->from(env('MAIL_FROM'));
    }

    public function to(string $to): void
    {
        $this->email->to($to);
    }

    public function template(MailerTemplate $template): void
    {
        $this->template = $template;
    }

    /**
     * @throws TransportExceptionInterface
     */
    public function send(): void
    {
        $this->email->subject($this->template->getSubject());
        $this->email->html($this->template->getContent());
        $this->mailer->send($this->email);
    }
}
