<?php
// Exercise real Roundcube contacts/preferences in the encrypted DR archive.
declare(strict_types=1);

function roundcube_database_path(string $configDir = '/etc/roundcube'): string {
    $dbtype = $dbbasepath = $basepath = $dbname = null;
    if (is_file($configDir . '/debian-db.php')) {
        require $configDir . '/debian-db.php';
        $dbbasepath = $dbbasepath ?: $basepath;
        if (in_array($dbtype, ['sqlite', 'sqlite3'], true) && is_string($dbbasepath) && is_string($dbname)) {
            return rtrim($dbbasepath, '/') . '/' . $dbname;
        }
    }
    $config = [];
    if (is_file($configDir . '/debian-db-roundcube.php')) {
        require $configDir . '/debian-db-roundcube.php';
    }
    $dsn = $config['db_dsnw'] ?? '';
    if (is_string($dsn) && preg_match('~^sqlite:/{2,}(.+)$~', $dsn, $matches)) {
        return '/' . $matches[1];
    }
    throw new RuntimeException('configured Roundcube SQLite database was not found');
}

function roundcube_canary(string $path, string $mailbox, bool $seed): void {
    if (!is_file($path) || is_link($path)) {
        throw new RuntimeException('Roundcube SQLite fixture is missing or is a symlink: ' . $path);
    }
    $db = new SQLite3($path, SQLITE3_OPEN_READWRITE);
    $db->enableExceptions(true);
    $db->busyTimeout(10000);
    $db->exec('BEGIN IMMEDIATE');
    try {
        $query = $db->prepare('SELECT user_id, preferences FROM users WHERE username=:username ORDER BY user_id LIMIT 1');
        $query->bindValue(':username', $mailbox, SQLITE3_TEXT);
        $user = $query->execute()->fetchArray(SQLITE3_ASSOC);
        if (!$user && $seed) {
            $query = $db->prepare("INSERT INTO users(username, mail_host, created, last_login, language, preferences) VALUES (:username, '127.0.0.1', datetime('now'), datetime('now'), 'en_US', '')");
            $query->bindValue(':username', $mailbox, SQLITE3_TEXT);
            $query->execute();
            $user = ['user_id' => $db->lastInsertRowID(), 'preferences' => ''];
        }
        if (!$user) {
            throw new RuntimeException('restored Roundcube user is missing');
        }
        $prefs = ($user['preferences'] ?? '') !== '' ? unserialize($user['preferences'], ['allowed_classes' => false]) : [];
        if (!is_array($prefs)) {
            throw new RuntimeException('Roundcube preferences are not a serialized array');
        }
        if ($seed) {
            $prefs['phase29_dr_canary'] = 'phase29-roundcube-preference';
            $query = $db->prepare('UPDATE users SET preferences=:preferences WHERE user_id=:id');
            $query->bindValue(':preferences', serialize($prefs), SQLITE3_TEXT);
            $query->bindValue(':id', (int)$user['user_id'], SQLITE3_INTEGER);
            $query->execute();
            $query = $db->prepare("DELETE FROM contacts WHERE user_id=:id AND email='phase29-contact@example.test'");
            $query->bindValue(':id', (int)$user['user_id'], SQLITE3_INTEGER);
            $query->execute();
            $query = $db->prepare("INSERT INTO contacts(user_id, changed, del, name, email, firstname, surname, vcard, words) VALUES (:id, datetime('now'), 0, 'Phase29 Restored Contact', 'phase29-contact@example.test', 'Phase29', 'Restored Contact', '', 'phase29 restored contact')");
            $query->bindValue(':id', (int)$user['user_id'], SQLITE3_INTEGER);
            $query->execute();
        } else {
            if (($prefs['phase29_dr_canary'] ?? '') !== 'phase29-roundcube-preference') {
                throw new RuntimeException('Roundcube preference did not survive restore');
            }
            $query = $db->prepare("SELECT count(*) FROM contacts WHERE user_id=:id AND del=0 AND name='Phase29 Restored Contact' AND email='phase29-contact@example.test'");
            $query->bindValue(':id', (int)$user['user_id'], SQLITE3_INTEGER);
            if ((int)$query->execute()->fetchArray(SQLITE3_NUM)[0] !== 1) {
                throw new RuntimeException('Roundcube contact did not survive restore');
            }
        }
        $db->exec('COMMIT');
    } catch (Throwable $error) {
        $db->exec('ROLLBACK');
        throw $error;
    } finally {
        $db->close();
    }
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    try {
        if ($argc !== 3 || !in_array($argv[1], ['seed', 'assert'], true)) {
            throw new RuntimeException('usage: roundcube-dr-canary.php seed|assert MAILBOX');
        }
        $path = roundcube_database_path();
        if (!in_array($path, ['/var/lib/roundcube/roundcube.sqlite', '/var/lib/roundcube/db/roundcube', '/var/lib/dbconfig-common/sqlite3/roundcube/roundcube'], true)) {
            throw new RuntimeException('Roundcube database is outside supported backup paths: ' . $path);
        }
        roundcube_canary($path, $argv[2], $argv[1] === 'seed');
        echo 'Roundcube contacts/preferences ' . $argv[1] . ' verified: ' . $path . PHP_EOL;
    } catch (Throwable $error) {
        fwrite(STDERR, $error->getMessage() . PHP_EOL);
        exit(1);
    }
}
