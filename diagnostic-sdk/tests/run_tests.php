<?php

require_once __DIR__ . '/../src/Security/SecretRedactor.php';
require_once __DIR__ . '/../src/Security/FIMScanner.php';
require_once __DIR__ . '/../src/Storage/LocalSpool.php';
require_once __DIR__ . '/../src/Core/RingBuffer.php';
require_once __DIR__ . '/../src/Core/Tracker.php';
require_once __DIR__ . '/../src/Errors/ErrorHandler.php';
require_once __DIR__ . '/../src/Core/DiagnosticSDK.php';

use Hoatzingenz\Diagnostic\Core\DiagnosticSDK;
use Hoatzingenz\Diagnostic\Security\FIMScanner;
use Hoatzingenz\Diagnostic\Security\SecretRedactor;
use Hoatzingenz\Diagnostic\Storage\LocalSpool;

echo "========================================================\n";
echo " Running Hoatzingenz Protection SDK Verification Suite\n";
echo "========================================================\n\n";

$passed = 0;
$failed = 0;

function assertCheck(string $title, bool $condition) {
    global $passed, $failed;
    if ($condition) {
        echo " [PASS] {$title}\n";
        $passed++;
    } else {
        echo " [FAIL] {$title}\n";
        $failed++;
    }
}

// Test 1: Secret Redaction
$sampleInput = [
    'user' => 'admin',
    'password' => 'SuperSecret99',
    'authorization' => 'Bearer token_123456789'
];
$redacted = SecretRedactor::redact($sampleInput);
assertCheck('SecretRedactor scrubs password field', $redacted['password'] === '[REDACTED]');
assertCheck('SecretRedactor scrubs authorization header', $redacted['authorization'] === '[REDACTED]');

// Test 2: FIM Webshell Detection & Quarantine
$tmpUpload = sys_get_temp_dir() . '/test_upload_' . uniqid();
$tmpQuarantine = sys_get_temp_dir() . '/test_quarantine_' . uniqid();
@mkdir($tmpUpload, 0755, true);
@mkdir($tmpQuarantine, 0755, true);

$shellPath = $tmpUpload . '/backdoor.php';
file_put_contents($shellPath, '<?php system($_GET["c"]); ?>');

$scanner = new FIMScanner($tmpQuarantine);
$threats = $scanner->scanUploadDirectory($tmpUpload);

assertCheck('FIMScanner detects executable drop', count($threats) === 1);
assertCheck('FIMScanner assigns WEBSHELL_DETECTED trigger', isset($threats[0]['trigger']) && $threats[0]['trigger'] === 'WEBSHELL_DETECTED');
assertCheck('FIMScanner quarantines dropped file', $threats[0]['quarantined'] === true);
assertCheck('Dropped file moved out of upload directory', !file_exists($shellPath));

// Cleanup test dirs
@unlink($shellPath . '.quarantined');
@rmdir($tmpUpload);
@unlink(glob($tmpQuarantine . '/*')[0] ?? '');
@rmdir($tmpQuarantine);

// Test 3: Local Spool Queue
$tmpSpool = sys_get_temp_dir() . '/test_spool_' . uniqid();
$spool = new LocalSpool($tmpSpool);
$spool->enqueue(['event_type' => 'METRIC', 'severity' => 'INFO']);

$dequeued = $spool->dequeue(10);
assertCheck('LocalSpool enqueues and dequeues event', count($dequeued) === 1);
$spool->acknowledge($dequeued);
assertCheck('LocalSpool clears acknowledged files', count($spool->dequeue(10)) === 0);
@rmdir($tmpSpool);

// Test 4: DiagnosticSDK Facade Initialization & Request Tracking
$sdk = DiagnosticSDK::init([
    'project_key' => 'proj_test_123',
    'spool_path' => sys_get_temp_dir() . '/test_sdk_spool_' . uniqid()
]);

assertCheck('DiagnosticSDK initialized cleanly', $sdk !== null);
assertCheck('DiagnosticSDK generates request_id', str_starts_with($sdk->getTracker()->getRequestId(), 'req_'));

echo "\n--------------------------------------------------------\n";
echo " Results: {$passed} Passed, {$failed} Failed\n";
echo "========================================================\n";

exit($failed === 0 ? 0 : 1);
