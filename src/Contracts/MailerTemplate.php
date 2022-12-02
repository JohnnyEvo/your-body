<?php

namespace App\Contracts;

interface MailerTemplate
{
    const MAILS_DIR = __DIR__.'/../../resources/mails';

    public function getSubject(): string;

    public function setSubject(string $subject): void;

    public function getContent(): string;

    public function setContent(string $content): void;
}
