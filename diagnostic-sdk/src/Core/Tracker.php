<?php

namespace Hoatzingenz\Diagnostic\Core;

use Hoatzingenz\Diagnostic\Security\SecretRedactor;

class Tracker
{
    private string $requestId;
    private float $startTime;
    private int $startMemory;
    private array $requestContext;

    public function __construct()
    {
        $this->requestId = 'req_' . bin2hex(random_bytes(12));
        $this->startTime = microtime(true);
        $this->startMemory = memory_get_usage();

        $this->requestContext = [
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'CLI',
            'uri' => SecretRedactor::redact($_SERVER['REQUEST_URI'] ?? 'cli'),
            'http_host' => $_SERVER['HTTP_HOST'] ?? 'localhost',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
        ];
    }

    public function getRequestId(): string
    {
        return $this->requestId;
    }

    public function captureSummary(int $statusCode = 200): array
    {
        $durationMs = round((microtime(true) - $this->startTime) * 1000, 2);
        $peakMemoryBytes = memory_get_peak_usage();

        return [
            'request_id' => $this->requestId,
            'event_type' => 'REQUEST_SUMMARY',
            'timestamp' => date('c'),
            'duration_ms' => $durationMs,
            'peak_memory_bytes' => $peakMemoryBytes,
            'status_code' => http_response_code() ?: $statusCode,
            'context' => $this->requestContext
        ];
    }
}
