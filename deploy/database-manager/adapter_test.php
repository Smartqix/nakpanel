<?php
declare(strict_types=1);
require __DIR__ . '/adapter.php';

function check(bool $condition, string $message): void {
    if (!$condition) { throw new RuntimeException($message); }
}
function rejects(callable $operation): void {
    try { $operation(); } catch (RuntimeException $error) { return; }
    throw new RuntimeException('expected rejection');
}
$key = str_repeat('k', 64);
$grant = str_repeat('a', 64);
$headers = ['HTTP_X_NAKPANEL_MANAGER_KEY' => $key, 'HTTP_X_NAKPANEL_MANAGER_GRANT' => $grant];
check(nakpanel_context($headers, $key) === $grant, 'valid context');
rejects(fn() => nakpanel_context([], $key));
rejects(fn() => nakpanel_context($headers, ''));
rejects(fn() => nakpanel_context(array_replace($headers, ['HTTP_X_NAKPANEL_MANAGER_GRANT' => '../escape']), $key));
$credentials = ['grant' => $grant, 'username' => 'tenant_user', 'password' => 'private-password', 'database' => 'tenant_db'];
check(nakpanel_credentials($credentials, $grant)['database'] === 'tenant_db', 'valid credentials');
rejects(fn() => nakpanel_credentials(array_replace($credentials, ['grant' => str_repeat('b', 64)]), $grant));
rejects(fn() => nakpanel_credentials(array_replace($credentials, ['username' => 'root']), $grant));
rejects(fn() => nakpanel_credentials(array_replace($credentials, ['password' => '']), $grant));
rejects(fn() => nakpanel_credentials(array_replace($credentials, ['database' => '../escape']), $grant));
foreach (['mysql', 'information_schema', 'performance_schema', 'sys', 'MYSQL', 'Information_Schema', 'Performance_Schema', 'Sys'] as $systemDatabase) {
    rejects(fn() => nakpanel_credentials(array_replace($credentials, ['database' => $systemDatabase]), $grant));
    $escaped = str_replace('_', '\\_', $systemDatabase);
    check(!nakpanel_grant_schema('GRANT ALL PRIVILEGES ON `' . $escaped . '`.* TO `tenant_user`@`localhost`', $systemDatabase), 'system schema denied');
}
check(nakpanel_grant_schema('GRANT ALL PRIVILEGES ON `tenant\\_db`.* TO `u`@`localhost`', 'tenant_db'), 'escaped schema');
check(!nakpanel_grant_schema('GRANT ALL PRIVILEGES ON `tenant_db`.* TO `u`@`localhost`', 'tenant_db'), 'wildcard underscore');
check(!nakpanel_grant_schema('GRANT ALL PRIVILEGES ON *.* TO `u`@`localhost`', 'tenant_db'), 'global privileges');
check(!nakpanel_grant_schema('GRANT SELECT ON `other`.* TO `u`@`localhost`', 'tenant_db'), 'cross-schema');
check(!nakpanel_grant_schema('GRANT SELECT ON `tenant\\_db`.* TO `u`@`localhost` WITH GRANT OPTION', 'tenant_db'), 'grant option');
echo "adapter protocol tests passed\n";
