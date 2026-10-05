<?php

namespace Hoatzingenz\Diagnostic\Adapters\Laravel;

use Hoatzingenz\Diagnostic\Core\DiagnosticSDK;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\DB;

class DiagnosticServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(DiagnosticSDK::class, function ($app) {
            return DiagnosticSDK::init([
                'project_key' => config('diagnostic.project_key', env('DIAGNOSTIC_PROJECT_KEY', '')),
                'environment' => config('diagnostic.environment', env('APP_ENV', 'production')),
                'spool_path' => storage_path('framework/cache/hoatzingenz_spool'),
                'security' => [
                    'fim_enabled' => true,
                    'quarantine_dir' => storage_path('app/quarantine'),
                ]
            ]);
        });
    }

    public function boot(): void
    {
        $sdk = $this->app->make(DiagnosticSDK::class);

        // Listen for Database Slowdowns
        DB::listen(function ($query) use ($sdk) {
            if ($query->time > 1000) { // Query duration > 1000ms
                $sdk->recordEvent([
                    'event_type' => 'DATABASE_SLOWDOWN',
                    'severity' => 'WARNING',
                    'duration_ms' => $query->time,
                    'sql' => $query->sql,
                    'timestamp' => date('c')
                ]);
            }
        });
    }
}
