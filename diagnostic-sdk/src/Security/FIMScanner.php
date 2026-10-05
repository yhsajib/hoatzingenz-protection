<?php

namespace Hoatzingenz\Diagnostic\Security;

class FIMScanner
{
    private array $executableExtensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'phar', 'inc', 'sh', 'bash', 'exe', 'so', 'dll'];
    private string $quarantineDir;

    public function __construct(string $quarantineDir = '')
    {
        $this->quarantineDir = $quarantineDir;
    }

    /**
     * Scans a directory path for suspicious executable files dropped in non-code paths.
     *
     * @param string $path
     * @return array List of detected threat event arrays
     */
    public function scanUploadDirectory(string $path): array
    {
        $threats = [];
        if (!is_dir($path) || !is_readable($path)) {
            return $threats;
        }

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($path, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $ext = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));
                    if (in_array($ext, $this->executableExtensions, true)) {
                        $fullPath = $file->getRealPath();
                        $sha256 = hash_file('sha256', $fullPath);

                        $threatEvent = [
                            'event_type' => 'SECURITY_ALERT',
                            'trigger' => 'WEBSHELL_DETECTED',
                            'severity' => 'CRITICAL',
                            'timestamp' => date('c'),
                            'file_path' => $fullPath,
                            'file_size' => $file->getSize(),
                            'file_hash' => $sha256,
                            'message' => "Executable file [{$file->getFilename()}] detected in writable path [{$path}]",
                            'quarantined' => false
                        ];

                        if (!empty($this->quarantineDir)) {
                            $threatEvent['quarantined'] = $this->quarantineFile($fullPath);
                        }

                        $threats[] = $threatEvent;
                    }
                }
            }
        } catch (\Throwable $e) {
            // Fail-open: Never allow scanner exception to halt application execution
        }

        return $threats;
    }

    /**
     * Safely moves a suspicious dropped file into quarantine sandbox.
     */
    public function quarantineFile(string $filePath): bool
    {
        if (!file_exists($filePath) || empty($this->quarantineDir)) {
            return false;
        }

        try {
            if (!is_dir($this->quarantineDir)) {
                @mkdir($this->quarantineDir, 0755, true);
            }

            $targetName = date('Ymd_His_') . basename($filePath) . '.quarantine';
            $targetPath = rtrim($this->quarantineDir, '/\\') . DIRECTORY_SEPARATOR . $targetName;

            // Remove execution permission before moving
            @chmod($filePath, 0000);

            if (@rename($filePath, $targetPath)) {
                // Leave a tombstone record
                @file_put_contents($filePath . '.quarantined', "Quarantined by Hoatzingenz Agent at " . date('c'));
                return true;
            }
        } catch (\Throwable $e) {
            // Fail-open
        }

        return false;
    }
}
