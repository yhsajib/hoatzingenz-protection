<?php

namespace Hoatzingenz\Diagnostic\Security;

class SecretRedactor
{
    private static array $sensitiveKeys = [
        'password',
        'pass',
        'pwd',
        'secret',
        'token',
        'api_key',
        'apikey',
        'authorization',
        'auth',
        'bearer',
        'cookie',
        'session',
        'phpsessid',
        'laravel_session',
        'credit_card',
        'card_number',
        'cvv',
        'ssn',
    ];

    /**
     * Recursively redacts sensitive keys in associative arrays or strings.
     *
     * @param mixed $data
     * @return mixed
     */
    public static function redact($data)
    {
        if (is_array($data)) {
            $redacted = [];
            foreach ($data as $key => $value) {
                if (self::isSensitiveKey((string)$key)) {
                    $redacted[$key] = '[REDACTED]';
                } else {
                    $redacted[$key] = self::redact($value);
                }
            }
            return $redacted;
        }

        if (is_string($data)) {
            return self::redactString($data);
        }

        return $data;
    }

    private static function isSensitiveKey(string $key): bool
    {
        $normalized = strtolower(trim($key));
        foreach (self::$sensitiveKeys as $sensitive) {
            if ($normalized === $sensitive || str_contains($normalized, $sensitive)) {
                return true;
            }
        }
        return false;
    }

    private static function redactString(string $input): bool|string
    {
        // Redact Authorization headers
        $input = preg_replace('/(Authorization:\s*)(Bearer|Basic)\s+[A-Za-z0-9\-\._~\+\/]+=*/i', '$1$2 [REDACTED]', $input);

        // Redact credit card numbers (13-19 digits)
        $input = preg_replace('/\b(?:\d[ -]*?){13,19}\b/', '[REDACTED_CC]', $input);

        return $input;
    }
}
