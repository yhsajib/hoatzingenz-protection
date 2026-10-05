<?php

namespace Hoatzingenz\Diagnostic\Adapters\WordPress;

use Hoatzingenz\Diagnostic\Core\DiagnosticSDK;

class WordPressAdapter
{
    private DiagnosticSDK $sdk;

    public function __construct(DiagnosticSDK $sdk)
    {
        $this->sdk = $sdk;
        $this->registerWordPressHooks();
    }

    private function registerWordPressHooks(): void
    {
        if (!function_exists('add_action')) {
            return;
        }

        // Track WordPress admin login failures (Brute-force detection)
        add_action('wp_login_failed', [$this, 'onLoginFailed']);

        // Track successful admin logins
        add_action('wp_login', [$this, 'onLoginSuccess'], 10, 2);

        // Schedule periodic FIM uploads directory check
        add_action('wp_scheduled_delete', [$this, 'scanUploadsDirectory']);

        // Enrich request context with WP details
        add_action('init', [$this, 'enrichContext'], 1);
    }

    public function onLoginFailed(string $username): void
    {
        $this->sdk->recordEvent([
            'event_type' => 'SECURITY_ALERT',
            'trigger' => 'BRUTE_FORCE_ATTACK',
            'severity' => 'WARNING',
            'timestamp' => date('c'),
            'target_username' => $username,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
            'message' => "Failed login attempt for user [{$username}]"
        ]);
    }

    public function onLoginSuccess(string $userLogin, \WP_User $user): void
    {
        if (in_array('administrator', (array)$user->roles, true)) {
            $this->sdk->recordEvent([
                'event_type' => 'SECURITY_AUDIT',
                'trigger' => 'ADMIN_LOGIN',
                'severity' => 'INFO',
                'timestamp' => date('c'),
                'username' => $userLogin,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
                'message' => "Administrator [{$userLogin}] logged in successfully"
            ]);
        }
    }

    public function scanUploadsDirectory(): void
    {
        if (function_exists('wp_upload_dir')) {
            $uploadDir = wp_upload_dir();
            if (!empty($uploadDir['basedir'])) {
                $this->sdk->scanSecurity($uploadDir['basedir']);
            }
        }
    }

    public function enrichContext(): void
    {
        global $wp_version;

        $context = [
            'wp_version' => $wp_version ?? 'Unknown',
            'active_theme' => get_stylesheet() ?? 'Unknown',
            'is_user_logged_in' => is_user_logged_in(),
            'is_admin' => is_admin(),
        ];

        $this->sdk->recordEvent([
            'event_type' => 'WORDPRESS_CONTEXT',
            'context' => $context
        ]);
    }
}
