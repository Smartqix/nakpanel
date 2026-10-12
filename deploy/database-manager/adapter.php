<?php
declare(strict_types=1);

function nakpanel_context(array $server, string $key): string {
    $provided = $server['HTTP_X_NAKPANEL_MANAGER_KEY'] ?? '';
    $grant = $server['HTTP_X_NAKPANEL_MANAGER_GRANT'] ?? '';
    if (strlen($key) < 32 || !hash_equals($key, $provided) || !preg_match('/\A[a-f0-9]{64}\z/D', $grant)) {
        throw new RuntimeException('Manager authorization required');
    }
    return $grant;
}

function nakpanel_system_database(string $database): bool {
    return in_array(strtolower($database), ['mysql', 'information_schema', 'performance_schema', 'sys'], true);
}

function nakpanel_credentials(array $value, string $grant): array {
    if (($value['grant'] ?? '') !== $grant) { throw new RuntimeException('Invalid manager credentials'); }
    foreach (['username', 'database'] as $name) {
        if (!is_string($value[$name] ?? null) || !preg_match('/\A[A-Za-z0-9_]{1,64}\z/D', $value[$name])) {
            throw new RuntimeException('Invalid manager credentials');
        }
    }
    if (nakpanel_system_database($value['database']) || strtolower($value['username']) === 'root' || !is_string($value['password'] ?? null)
        || strlen($value['password']) < 1 || strlen($value['password']) > 1024) {
        throw new RuntimeException('Invalid manager credentials');
    }
    return $value;
}

function nakpanel_grant_schema(string $line, string $database): bool {
    if (nakpanel_system_database($database) || preg_match('/\bWITH GRANT OPTION\b/i', $line)
        || !preg_match('/\AGRANT ([A-Z_, ()]+) ON `([^`]+)`\.\* TO /', $line, $parts)) {
        return false;
    }
    return $parts[2] === str_replace('_', '\\_', $database);
}

function nakpanel_check_grants(array $credentials): void {
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $db = mysqli_init();
    $db->options(MYSQLI_OPT_CONNECT_TIMEOUT, 3);
    $db->real_connect('localhost', $credentials['username'], $credentials['password'], $credentials['database'], 3306, '/run/mysqld/mysqld.sock');
    $grants = $db->query('SHOW GRANTS FOR CURRENT_USER()');
    $scoped = false;
    foreach ($grants as $row) {
        $line = (string) array_values($row)[0];
        if (preg_match('/\bWITH GRANT OPTION\b/i', $line)) { throw new RuntimeException('Unsafe database grants'); }
        if (preg_match('/\AGRANT USAGE ON \*\.\* TO /', $line)) { continue; }
        if (!nakpanel_grant_schema($line, $credentials['database'])) {
            throw new RuntimeException('Unsafe database grants');
        }
        $scoped = true;
    }
    $db->close();
    if (!$scoped) { throw new RuntimeException('Missing database grants'); }
}

function nakpanel_redeem(string $capability, string $grant): array {
    if (!preg_match('/\A[A-Za-z0-9_-]{32,256}\z/D', $capability)) { throw new RuntimeException('Invalid capability'); }
    $curl = curl_init('http://localhost/redeem');
    curl_setopt_array($curl, [CURLOPT_UNIX_SOCKET_PATH => '/run/nakpanel-db-manager/bridge.sock',
        CURLOPT_POST => true, CURLOPT_POSTFIELDS => json_encode(['capability' => $capability], JSON_THROW_ON_ERROR),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'], CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 2, CURLOPT_TIMEOUT => 5, CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_PROXY => '', CURLOPT_PROTOCOLS => CURLPROTO_HTTP]);
    $body = curl_exec($curl);
    $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    curl_close($curl);
    if ($status !== 200 || !is_string($body) || strlen($body) > 8192) { throw new RuntimeException('Bridge unavailable'); }
    $credentials = nakpanel_credentials(json_decode($body, true, 16, JSON_THROW_ON_ERROR), $grant);
    nakpanel_check_grants($credentials);
    return $credentials;
}

function nakpanel_bootstrap(): void {
    $grant = nakpanel_context($_SERVER, trim((string) file_get_contents('/etc/nakpanel-database-manager/proxy.key')));
    $directory = '/var/lib/nakpanel-database-manager/grants/' . $grant;
    $capability = $_SERVER['HTTP_X_NAKPANEL_MANAGER_CAPABILITY'] ?? '';
    if ($capability !== '') {
        $credentials = nakpanel_redeem($capability, $grant);
        if (!mkdir($directory, 0700)) { throw new RuntimeException('Manager already initialized'); }
        $credentials['created_at'] = time();
        if (file_put_contents($directory . '/credentials.json', json_encode($credentials, JSON_THROW_ON_ERROR), LOCK_EX) === false) {
            throw new RuntimeException('Manager initialization failed');
        }
        chmod($directory . '/credentials.json', 0600);
    }
    $stored = json_decode((string) file_get_contents($directory . '/credentials.json'), true, 16, JSON_THROW_ON_ERROR);
    $credentials = nakpanel_credentials($stored, $grant);
    if (!isset($stored['created_at']) || time() >= $stored['created_at'] + 3600) {
        @unlink($directory . '/credentials.json');
        throw new RuntimeException('Manager expired');
    }
    ini_set('session.save_path', $directory);
    $GLOBALS['nakpanel_credentials'] = $credentials;
    unset($_SERVER['HTTP_X_NAKPANEL_MANAGER_KEY'], $_SERVER['HTTP_X_NAKPANEL_MANAGER_CAPABILITY']);
}
