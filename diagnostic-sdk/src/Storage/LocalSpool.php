<?php

namespace Hoatzingenz\Diagnostic\Storage;

class LocalSpool
{
    private string $spoolDir;
    private int $maxSizeBytes;

    public function __construct(string $spoolDir, int $maxSizeBytes = 52428800) // 50MB default
    {
        $this->spoolDir = $spoolDir;
        $this->maxSizeBytes = $maxSizeBytes;

        if (!is_dir($this->spoolDir)) {
            @mkdir($this->spoolDir, 0755, true);
        }
    }

    /**
     * Appends an event object to the local spool file safely.
     *
     * @param array $event
     * @return bool
     */
    public function enqueue(array $event): bool
    {
        try {
            $this->enforceCapacityLimit();

            $filename = $this->getSpoolFilename($event);
            $filePath = $this->spoolDir . DIRECTORY_SEPARATOR . $filename;

            $json = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
            return (bool)@file_put_contents($filePath, $json, FILE_APPEND | LOCK_EX);
        } catch (\Throwable $e) {
            // Fail-open: Storage failure must never stop the PHP application
            return false;
        }
    }

    /**
     * Reads spooled event items for transmission.
     *
     * @param int $limit
     * @return array
     */
    public function dequeue(int $limit = 50): array
    {
        $events = [];
        try {
            $files = glob($this->spoolDir . DIRECTORY_SEPARATOR . '*.spool');
            if (empty($files)) {
                return [];
            }

            // Sort files by creation time
            usort($files, fn($a, $b) => filemtime($a) <=> filemtime($b));

            foreach ($files as $file) {
                if (count($events) >= $limit) {
                    break;
                }

                $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                if ($lines !== false) {
                    foreach ($lines as $line) {
                        $decoded = json_decode($line, true);
                        if (is_array($decoded)) {
                            $events[] = [
                                'file' => $file,
                                'payload' => $decoded
                            ];
                        }
                    }
                }
            }
        } catch (\Throwable $e) {
            // Fail-open
        }

        return $events;
    }

    /**
     * Purges spooled files after successful cloud API ingestion.
     */
    public function acknowledge(array $dequeuedItems): void
    {
        try {
            $filesToDelete = array_unique(array_column($dequeuedItems, 'file'));
            foreach ($filesToDelete as $file) {
                if (file_exists($file)) {
                    @unlink($file);
                }
            }
        } catch (\Throwable $e) {
            // Fail-open
        }
    }

    private function getSpoolFilename(array $event): string
    {
        $severity = $event['severity'] ?? 'INFO';
        $prefix = ($severity === 'CRITICAL' || ($event['event_type'] ?? '') === 'SECURITY_ALERT') ? 'critical_' : 'metric_';
        return $prefix . date('Ymd_H') . '.spool';
    }

    private function enforceCapacityLimit(): void
    {
        $currentSize = $this->calculateTotalSize();
        if ($currentSize < $this->maxSizeBytes) {
            return;
        }

        // Capacity exceeded: delete non-critical metric spool files first
        $metricFiles = glob($this->spoolDir . DIRECTORY_SEPARATOR . 'metric_*.spool');
        usort($metricFiles, fn($a, $b) => filemtime($a) <=> filemtime($b));

        foreach ($metricFiles as $file) {
            @unlink($file);
            if ($this->calculateTotalSize() < ($this->maxSizeBytes * 0.8)) {
                break;
            }
        }
    }

    private function calculateTotalSize(): int
    {
        $size = 0;
        $files = glob($this->spoolDir . DIRECTORY_SEPARATOR . '*.spool');
        if ($files) {
            foreach ($files as $file) {
                $size += (int)@filesize($file);
            }
        }
        return $size;
    }
}
