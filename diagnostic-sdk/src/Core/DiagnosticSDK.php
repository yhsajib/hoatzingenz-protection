<?php

namespace Hoatzingenz\Diagnostic\Core;

use Hoatzingenz\Diagnostic\Errors\ErrorHandler;
use Hoatzingenz\Diagnostic\Security\FIMScanner;
use Hoatzingenz\Diagnostic\Security\SecretRedactor;
use Hoatzingenz\Diagnostic\Storage\LocalSpool;

class DiagnosticSDK
{
    private static ?DiagnosticSDK $instance = null;
    private array $config;
    private Tracker $tracker;
    private RingBuffer $ringBuffer;
    private LocalSpool $spool;
    private FIMScanner $fimScanner;

    private function __construct(array $config)
    {
        $this->config = array_merge([
            'project_key' => '',
            'environment' => 'production',
            'spool_path' => sys_get_temp_dir() . '/hoatzingenz_spool',
            'security' => [
                'fim_enabled' => true,
                'scan_paths' => [],
                'quarantine_dir' => '',
            ],
            'ring_buffer_capacity' => 100,
        ], $config);

        $this->tracker = new Tracker();
        $this->ringBuffer = new RingBuffer($this->config['ring_buffer_capacity']);
        $this->spool = new LocalSpool($this->config['spool_path']);
        $this->fimScanner = new FIMScanner($this->config['security']['quarantine_dir']);

        $this->registerHandlers();
    }

    public static function init(array $config = []): DiagnosticSDK
    {
        if (self::$instance === null) {
            try {
                self::$instance = new self($config);
            } catch (\Throwable $e) {
                // Fail-open: SDK init failure MUST NEVER crash host application
            }
        }
        return self::$instance;
    }

    public static function getInstance(): ?DiagnosticSDK
    {
        return self::$instance;
    }

    public function getTracker(): Tracker
    {
        return $this->tracker;
    }

    public function recordEvent(array $event): void
    {
        try {
            $event['request_id'] = $this->tracker->getRequestId();
            $event['project_key'] = $this->config['project_key'];
            $event['environment'] = $this->config['environment'];

            $redactedEvent = SecretRedactor::redact($event);

            $this->ringBuffer->push($redactedEvent);
            $this->spool->enqueue($redactedEvent);
        } catch (\Throwable $e) {
            // Fail-open
        }
    }

    public function scanSecurity(string $uploadDirectory): array
    {
        try {
            $threats = $this->fimScanner->scanUploadDirectory($uploadDirectory);
            foreach ($threats as $threat) {
                $this->recordEvent($threat);
            }
            return $threats;
        } catch (\Throwable $e) {
            // Fail-open
            return [];
        }
    }

    public function flushSummary(): void
    {
        try {
            $summary = $this->tracker->captureSummary();
            $this->recordEvent($summary);
        } catch (\Throwable $e) {
            // Fail-open
        }
    }

    private function registerHandlers(): void
    {
        ErrorHandler::register(function (array $errorPayload) {
            $this->recordEvent($errorPayload);
        });

        register_shutdown_function(function () {
            $this->flushSummary();
        });
    }
}
