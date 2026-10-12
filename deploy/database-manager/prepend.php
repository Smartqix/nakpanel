<?php
declare(strict_types=1);
require '/etc/nakpanel-database-manager/adapter.php';
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
try {
    if (($_SERVER['SCRIPT_FILENAME'] ?? '') === '/etc/nakpanel-database-manager/health.php') {
        $context = $_SERVER;
        $context['HTTP_X_NAKPANEL_MANAGER_GRANT'] = str_repeat('0', 64);
        nakpanel_context($context, trim((string) file_get_contents('/etc/nakpanel-database-manager/proxy.key')));
    } else {
        nakpanel_bootstrap();
    }
} catch (Throwable $error) {
    http_response_code(403);
    echo 'Database manager session unavailable. Return to the panel and open a new session.';
    exit;
}
