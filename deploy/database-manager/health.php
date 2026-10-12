<?php
declare(strict_types=1);
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET' || !extension_loaded('mysqli') || !extension_loaded('curl')
    || !file_exists('/run/nakpanel-db-manager/bridge.sock')
    || !is_readable('/opt/nakpanel-database-manager/current/index.php')) {
    http_response_code(503);
    exit;
}
header('X-Nakpanel-Manager-Version: 5.2.3');
http_response_code(204);
