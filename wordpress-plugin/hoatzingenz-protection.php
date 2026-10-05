<?php
/**
 * Plugin Name: Hoatzingenz Protection & Root Cause Agent
 * Plugin URI: https://hoatzingenz-protection.io
 * Description: Production-grade website incident root-cause diagnosis and security protection platform for WordPress.
 * Version: 1.1.0
 * Author: Hoatzingenz Security Team
 * License: MIT
 */

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/../diagnostic-sdk/src/Security/SecretRedactor.php';
require_once __DIR__ . '/../diagnostic-sdk/src/Security/FIMScanner.php';
require_once __DIR__ . '/../diagnostic-sdk/src/Storage/LocalSpool.php';
require_once __DIR__ . '/../diagnostic-sdk/src/Core/RingBuffer.php';
require_once __DIR__ . '/../diagnostic-sdk/src/Core/Tracker.php';
require_once __DIR__ . '/../diagnostic-sdk/src/Errors/ErrorHandler.php';
require_once __DIR__ . '/../diagnostic-sdk/src/Core/DiagnosticSDK.php';
require_once __DIR__ . '/../diagnostic-sdk/adapters/WordPress/WordPressAdapter.php';

use Hoatzingenz\Diagnostic\Core\DiagnosticSDK;
use Hoatzingenz\Diagnostic\Adapters\WordPress\WordPressAdapter;

function hoatzingenz_init_protection() {
    $projectKey = get_option('hoatzingenz_project_key', 'wp_default_key');
    $uploadDir = wp_upload_dir();

    $sdk = DiagnosticSDK::init([
        'project_key' => $projectKey,
        'environment' => defined('WP_ENVIRONMENT_TYPE') ? WP_ENVIRONMENT_TYPE : 'production',
        'spool_path' => WP_CONTENT_DIR . '/uploads/hoatzingenz_spool',
        'security' => [
            'fim_enabled' => true,
            'quarantine_dir' => WP_CONTENT_DIR . '/uploads/hoatzingenz_quarantine',
        ]
    ]);

    new WordPressAdapter($sdk);
}

add_action('plugins_loaded', 'hoatzingenz_init_protection');
