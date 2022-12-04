<?php

namespace App\Mailers\Templates;

use App\Contracts\MailerTemplate;
use App\Models\User;
use Michelf\Markdown;

class Promotion implements MailerTemplate
{
    protected string $subject = 'Promotion';
    protected string $content;

    public function __construct(User $user)
    {
        $name = $user->email;
        $html = Markdown::defaultTransform(require self::MAILS_DIR . '/promotion.php');
        $this->setContent($html);
    }

    /**
     * @return string
     */
    public function getSubject(): string
    {
        return $this->subject;
    }

    /**
     * @param  string  $subject
     */
    public function setSubject(string $subject): void
    {
        $this->subject = $subject;
    }

    /**
     * @return string
     */
    public function getContent(): string
    {
        return $this->content;
    }

    /**
     * @param  string  $content
     */
    public function setContent(string $content): void
    {
        $this->content = $content;
    }
}
