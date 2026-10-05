<?php

namespace Hoatzingenz\Diagnostic\Errors;

use Hoatzingenz\Diagnostic\Security\SecretRedactor;

class ErrorHandler
{
    private static bool $registered = false;
    private static ?\Closure $callback = null;

    public static function register(\Closure $callback): void
    {
        if (self::$registered) {
            return;
        }

        self::$callback = $callback;
        self::$registered = true;

        set_error_handler([self::class, 'handleError']);
        set_exception_handler([self::class, 'handleException']);
        register_shutdown_function([self::class, 'handleShutdown']);
    }

    public static function handleError(int $errno, string $errstr, string $errfile, int $errline): bool
    {
        // Respect error_reporting settings
        if (!(error_reporting() & $errno)) {
            return false;
        }

        self::dispatch([
            'event_type' => 'ERROR',
            'severity' => ($errno === E_USER_ERROR || $errno === E_RECOVERABLE_ERROR) ? 'ERROR' : 'WARNING',
            'error_type' => self::errorTypeToString($errno),
            'message' => SecretRedactor::redact($errstr),
            'file' => $errfile,
            'line' => $errline,
            'timestamp' => date('c'),
            'stack' => debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 10)
        ]);

        return false; // Allow standard PHP error handling to continue
    }

    public static function handleException(\Throwable $exception): void
    {
        self::dispatch([
            'event_type' => 'EXCEPTION',
            'severity' => 'ERROR',
            'error_type' => get_class($exception),
            'message' => SecretRedactor::redact($exception->getMessage()),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'timestamp' => date('c'),
            'stack' => SecretRedactor::redact($exception->getTraceAsString())
        ]);
    }

    public static function handleShutdown(): void
    {
        $error = error_get_last();
        if ($error !== null && self::isFatalError($error['type'])) {
            self::dispatch([
                'event_type' => 'FATAL_ERROR',
                'severity' => 'CRITICAL',
                'error_type' => self::errorTypeToString($error['type']),
                'message' => SecretRedactor::redact($error['message']),
                'file' => $error['file'],
                'line' => $error['line'],
                'timestamp' => date('c')
            ]);
        }
    }

    private static function dispatch(array $payload): void
    {
        if (self::$callback !== null) {
            try {
                (self::$callback)($payload);
            } catch (\Throwable $e) {
                // Fail-open: Error handler dispatch failure MUST NEVER crash the app
            }
        }
    }

    private static function isFatalError(int $type): bool
    {
        return in_array($type, [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true);
    }

    private static function errorTypeToString(int $type): string
    {
        return match ($type) {
            E_ERROR => 'E_ERROR',
            E_WARNING => 'E_WARNING',
            E_PARSE => 'E_PARSE',
            E_NOTICE => 'E_NOTICE',
            E_CORE_ERROR => 'E_CORE_ERROR',
            E_COMPILE_ERROR => 'E_COMPILE_ERROR',
            E_USER_ERROR => 'E_USER_ERROR',
            E_USER_WARNING => 'E_USER_WARNING',
            E_USER_NOTICE => 'E_USER_NOTICE',
            E_RECOVERABLE_ERROR => 'E_RECOVERABLE_ERROR',
            E_DEPRECATED => 'E_DEPRECATED',
            default => "UNKNOWN_ERROR_{$type}",
        };
    }
}
