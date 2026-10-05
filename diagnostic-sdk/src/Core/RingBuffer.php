<?php

namespace Hoatzingenz\Diagnostic\Core;

class RingBuffer
{
    private array $buffer = [];
    private int $maxCapacity;
    private int $ttlSeconds;

    public function __construct(int $maxCapacity = 100, int $ttlSeconds = 60)
    {
        $this->maxCapacity = $maxCapacity;
        $this->ttlSeconds = $ttlSeconds;
    }

    public function push(array $event): void
    {
        $now = microtime(true);
        $event['_buffered_at'] = $now;
        $this->buffer[] = $event;

        $this->purgeExpired($now);

        if (count($this->buffer) > $this->maxCapacity) {
            array_shift($this->buffer);
        }
    }

    public function getTimeline(): array
    {
        $this->purgeExpired(microtime(true));
        return array_values($this->buffer);
    }

    public function clear(): void
    {
        $this->buffer = [];
    }

    private function purgeExpired(float $now): void
    {
        $cutoff = $now - $this->ttlSeconds;
        $this->buffer = array_values(array_filter($this->buffer, function ($item) use ($cutoff) {
            return isset($item['_buffered_at']) && $item['_buffered_at'] >= $cutoff;
        }));
    }
}
