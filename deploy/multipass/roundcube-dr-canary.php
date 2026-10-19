<?php
// Exercise actual Roundcube contacts/preferences in the encrypted DR archive.
declare(strict_types=1);

function roundcube_literal(string $raw): string {
    if (!preg_match('~^([\'\"])(.*)\1$~s', $raw, $match)) {
        throw new RuntimeException('Roundcube database configuration must use static literals');
    }
    $quote = $match[1]; $body = $match[2]; $value = '';
    for ($i = 0; $i < strlen($body); $i++) {
        $char = $body[$i];
        if (str_contains("\r\n\0", $char) || $char === $quote || ($quote === '"' && $char === '$')) {
            throw new RuntimeException('Roundcube database configuration contains an unsupported literal');
        }
        if ($char === '\\' && $i + 1 < strlen($body) && in_array($body[$i + 1], ['\\', $quote], true)) {
            $value .= $body[++$i];
        } else {
            $value .= $char;
        }
    }
    return $value;
}

function roundcube_static_file(string $path, ?int $owner = null): ?string {
    if (!file_exists($path) && !is_link($path)) return null;
    if (is_link($path) || !is_file($path) || filesize($path) > 65536 || (fileperms($path) & 0022) !== 0 || fileowner($path) !== ($owner ?? 0)) {
        throw new RuntimeException('Roundcube configuration must be a bounded root-owned regular file');
    }
    $text = file_get_contents($path);
    if (!is_string($text)) throw new RuntimeException('Roundcube configuration could not be read');
    return $text;
}

function roundcube_has_dsn_override(string $text): bool {
    $tokens = token_get_all($text);
    $meaningful = array_values(array_filter($tokens, static fn($token) => !is_array($token) || !in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)));
    foreach ($meaningful as $index => $token) {
        if (!is_array($token) || $token[0] !== T_VARIABLE || $token[1] !== '$config') continue;
        $key = $meaningful[$index + 2] ?? null;
        if (($meaningful[$index + 1] ?? null) === '[' && is_array($key) && $key[0] === T_CONSTANT_ENCAPSED_STRING && roundcube_literal($key[1]) === 'db_dsnw' && ($meaningful[$index + 3] ?? null) === ']' && ($meaningful[$index + 4] ?? null) === '=') return true;
    }
    return false;
}

function roundcube_database_config(string $configDir = '/etc/roundcube', ?int $owner = null): array {
    $wrapper = roundcube_static_file($configDir . '/debian-db-roundcube.php', $owner);
    if ($wrapper !== null && !str_contains($wrapper, '$dbtype') && preg_match('~\$config\[[\'\"]db_dsnw[\'\"]\]\s*=\s*([\'\"]sqlite:[^\r\n]*?[\'\"])\s*;~', $wrapper, $match)) {
        $dsn = roundcube_literal($match[1]);
        return ['backend' => 'sqlite', 'path' => '/' . ltrim(substr($dsn, 7), '/')];
    }
    if ($wrapper !== null && hash('sha256', trim($wrapper)) !== 'c39d06fa29d90d8343d731f3a49a41670aeae04981090fb570284750fdd4e81a') throw new RuntimeException('unsupported custom Roundcube database wrapper');
    $text = roundcube_static_file($configDir . '/debian-db.php', $owner);
    if ($text === null) throw new RuntimeException('configured Roundcube database was not found');
    preg_match_all('~\$(dbtype|dbbasepath|basepath|dbname|dbuser|dbpass|dbserver|dbport)\s*=\s*((?:\'(?:\\\\.|[^\'\\\\])*\')|(?:"(?:\\\\.|[^"\\\\])*"))\s*;~', $text, $matches, PREG_SET_ORDER);
    $values = [];
    foreach ($matches as $match) {
        if (array_key_exists($match[1], $values)) throw new RuntimeException('ambiguous Roundcube database configuration');
        $values[$match[1]] = roundcube_literal($match[2]);
    }
    if (in_array($values['dbtype'] ?? '', ['sqlite', 'sqlite3'], true)) {
        return ['backend' => 'sqlite', 'path' => rtrim($values['dbbasepath'] ?? $values['basepath'] ?? '', '/') . '/' . ($values['dbname'] ?? '')];
    }
    if (($values['dbtype'] ?? '') !== 'mysql' || ($values['dbname'] ?? '') !== 'roundcube' || ($values['dbuser'] ?? '') !== 'roundcube' || !in_array($values['dbserver'] ?? '', ['', 'localhost'], true) || !in_array($values['dbport'] ?? '', ['', '3306'], true) || ($values['dbpass'] ?? '') === '') {
        throw new RuntimeException('only the default local Roundcube MySQL backend is supported');
    }
    $overrides = roundcube_static_file($configDir . '/config.inc.php', $owner);
    if ($overrides !== null && roundcube_has_dsn_override($overrides)) throw new RuntimeException('custom Roundcube database DSN overrides are unsupported');
    return ['backend' => 'mysql', 'username' => 'roundcube', 'password' => $values['dbpass'], 'database' => 'roundcube'];
}

function roundcube_database_path(string $configDir = '/etc/roundcube', ?int $owner = null): string {
    $config = roundcube_database_config($configDir, $owner);
    if ($config['backend'] !== 'sqlite') throw new RuntimeException('configured Roundcube database uses MySQL');
    return $config['path'];
}

function roundcube_canary(string|array $connection, string $mailbox, bool $seed): void {
    $config = is_string($connection) ? ['backend' => 'sqlite', 'path' => $connection] : $connection;
    $mysql = $config['backend'] === 'mysql';
    if (!$mysql && (!is_file($config['path']) || is_link($config['path']))) {
        throw new RuntimeException('Roundcube SQLite fixture is missing or is a symlink');
    }
    try {
        $db = $mysql
            ? new PDO('mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=roundcube;charset=utf8mb4', $config['username'], $config['password'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION])
            : new PDO('sqlite:' . $config['path'], null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    } catch (Throwable $error) {
        throw new RuntimeException('Roundcube database connection failed');
    }
    if (!$mysql) $db->exec('PRAGMA busy_timeout=10000');
    $db->beginTransaction();
    $now = $mysql ? 'NOW()' : "datetime('now')";
    try {
        $query = $db->prepare('SELECT user_id, preferences FROM users WHERE username=:username ORDER BY user_id LIMIT 1');
        $query->execute([':username' => $mailbox]);
        $user = $query->fetch(PDO::FETCH_ASSOC);
        if (!$user && $seed) {
            $query = $db->prepare("INSERT INTO users(username, mail_host, created, last_login, language, preferences) VALUES (:username, '127.0.0.1', $now, $now, 'en_US', '')");
            $query->execute([':username' => $mailbox]);
            $user = ['user_id' => $db->lastInsertId(), 'preferences' => ''];
            $query = $db->prepare("INSERT INTO identities(user_id, changed, del, standard, name, email) VALUES (:id, $now, 0, 1, '', :email)");
            $query->execute([':id' => (int)$user['user_id'], ':email' => $mailbox]);
        }
        if (!$user) throw new RuntimeException('restored Roundcube user is missing');
        $prefs = ($user['preferences'] ?? '') !== '' ? unserialize($user['preferences'], ['allowed_classes' => false]) : [];
        if (!is_array($prefs)) throw new RuntimeException('Roundcube preferences are not a serialized array');
        if ($seed) {
            $prefs['phase29_dr_canary'] = 'phase29-roundcube-preference';
            $query = $db->prepare('UPDATE users SET preferences=:preferences WHERE user_id=:id');
            $query->execute([':preferences' => serialize($prefs), ':id' => (int)$user['user_id']]);
            $query = $db->prepare("DELETE FROM contacts WHERE user_id=:id AND email='phase29-contact@example.test'");
            $query->execute([':id' => (int)$user['user_id']]);
            $query = $db->prepare("INSERT INTO contacts(user_id, changed, del, name, email, firstname, surname, vcard, words) VALUES (:id, $now, 0, 'Phase29 Restored Contact', 'phase29-contact@example.test', 'Phase29', 'Restored Contact', '', 'phase29 restored contact')");
            $query->execute([':id' => (int)$user['user_id']]);
        } else {
            if (($prefs['phase29_dr_canary'] ?? '') !== 'phase29-roundcube-preference') throw new RuntimeException('Roundcube preference did not survive restore');
            $query = $db->prepare("SELECT count(*) FROM contacts WHERE user_id=:id AND del=0 AND name='Phase29 Restored Contact' AND email='phase29-contact@example.test'");
            $query->execute([':id' => (int)$user['user_id']]);
            if ((int)$query->fetchColumn() !== 1) throw new RuntimeException('Roundcube contact did not survive restore');
        }
        $db->commit();
    } catch (Throwable $error) {
        $db->rollBack();
        throw $error;
    }
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    try {
        if ($argc !== 3 || !in_array($argv[1], ['seed', 'assert'], true)) throw new RuntimeException('usage: roundcube-dr-canary.php seed|assert MAILBOX');
        $config = roundcube_database_config();
        if ($config['backend'] === 'sqlite' && !in_array($config['path'], ['/var/lib/roundcube/roundcube.sqlite', '/var/lib/roundcube/db/roundcube', '/var/lib/dbconfig-common/sqlite3/roundcube/roundcube'], true)) throw new RuntimeException('Roundcube database is outside supported backup paths');
        roundcube_canary($config, $argv[2], $argv[1] === 'seed');
        echo 'Roundcube contacts/preferences ' . $argv[1] . ' verified: ' . $config['backend'] . PHP_EOL;
    } catch (Throwable $error) {
        fwrite(STDERR, $error instanceof PDOException ? 'Roundcube database operation failed' . PHP_EOL : $error->getMessage() . PHP_EOL);
        exit(1);
    }
}
