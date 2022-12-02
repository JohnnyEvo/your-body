<?php

namespace App\Mailers\Templates;

use App\Contracts\MailerTemplate;
use App\Contracts\Report;
use Michelf\Markdown;

class HealthReport implements MailerTemplate
{
    protected string $subject = 'Health reporting';
    protected string $content;

    public function __construct(Report $report)
    {
        $reporting = $report->reporting();
        $html = Markdown::defaultTransform(require self::MAILS_DIR . '/health_report.php');
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
