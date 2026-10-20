<?php
// Fixed read-only default-local-MySQL fact. Credentials never leave this process.
declare(strict_types=1);
try {
    if (posix_geteuid() !== 0 || $argc !== 3 || $argv[2] !== 'l3@current-bootstrap.test') throw new RuntimeException('identity');
    require $argv[1];
    $config = roundcube_database_config();
    if ($config['backend'] !== 'mysql') throw new RuntimeException('backend');
    $db = new PDO('mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=roundcube;charset=utf8mb4', $config['username'], $config['password'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_STRINGIFY_FETCHES => true]);
    if ($db->query('SELECT CURRENT_USER()')->fetchColumn() !== 'roundcube@localhost') throw new RuntimeException('authentication');
    $grants = $db->query('SHOW GRANTS')->fetchAll(PDO::FETCH_COLUMN);
    $usage = 0; $schema = 0;
    foreach ($grants as $grant) {
        if (str_contains($grant, 'GRANT OPTION') || str_contains($grant, 'PROXY')) throw new RuntimeException('grant');
        if (str_starts_with($grant, 'GRANT USAGE ON *.* TO `roundcube`@`localhost`')) ++$usage;
        elseif ($grant === 'GRANT ALL PRIVILEGES ON `roundcube`.* TO `roundcube`@`localhost`') ++$schema;
        else throw new RuntimeException('grant');
    }
    if (count($grants) !== 2 || $usage !== 1 || $schema !== 1) throw new RuntimeException('grant');
    $denied = false;
    try { $db->query('SELECT COUNT(*) FROM mysql.user')->fetchColumn(); }
    catch (PDOException $e) { $denied = ($e->errorInfo[1] ?? null) === 1142; }
    if (!$denied) throw new RuntimeException('system read');
    roundcube_canary($config, $argv[2], false);
    $db->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
    $db->beginTransaction();
    $names = $db->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN); sort($names, SORT_STRING);
    $tables = []; $ddl = [];
    foreach ($names as $name) {
        if (!is_string($name) || !preg_match('/^[a-z][a-z0-9_]*$/D', $name)) throw new RuntimeException('table');
        // Session/cache rows are live observations, never claimed immutable data.
        if ($name === 'session' || $name === 'cache' || str_starts_with($name, 'cache_')) continue;
        $ddlRow = $db->query('SHOW CREATE TABLE `'.$name.'`')->fetch(PDO::FETCH_NUM);
        if (!is_array($ddlRow) || !is_string($ddlRow[1] ?? null)) throw new RuntimeException('ddl');
        // Preserve complete durable table DDL, including table options/counters.
        $ddl[$name] = $ddlRow[1];
        $rows = $db->query('SELECT * FROM `'.$name.'`')->fetchAll(PDO::FETCH_ASSOC);
        $encoded = [];
        foreach ($rows as $row) {
            // Normal login changes only these measured user observations.
            if ($name === 'users') unset($row['last_login'], $row['failed_login'], $row['failed_login_counter']);
            ksort($row, SORT_STRING);
            $encoded[] = json_encode($row, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        }
        sort($encoded, SORT_STRING);
        $tables[$name] = ['count' => count($rows), 'sha256' => hash('sha256', implode("\n", $encoded)."\n")];
    }
    $collation = $db->query("SELECT DEFAULT_CHARACTER_SET_NAME,DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='roundcube'")->fetch(PDO::FETCH_NUM);
    $db->commit();
    $files = [];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator('/etc/roundcube', FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $file) {
        if ($file->isLink()) { $files[$file->getPathname()] = hash('sha256', 'symlink:'.readlink($file->getPathname())); continue; }
        if ($file->isFile()) $files[$file->getPathname()] = hash_file('sha256', $file->getPathname());
    }
    $package = '/etc/dbconfig-common/roundcube.conf';
    if (is_link($package) || !is_file($package)) throw new RuntimeException('package configuration');
    $files[$package] = hash_file('sha256', $package); ksort($files, SORT_STRING);
    $des = '/var/lib/nakpanel/roundcube-des-key';
    if (is_link($des) || !is_file($des)) throw new RuntimeException('des key');
    echo json_encode(['backend'=>'mysql','host'=>'localhost','database'=>'roundcube','username'=>'roundcube','config_sha256'=>hash('sha256',json_encode($files,JSON_THROW_ON_ERROR)),'des_key_sha256'=>hash_file('sha256',$des),'database_sha256'=>hash('sha256',json_encode([$ddl,$tables],JSON_THROW_ON_ERROR)),'tables'=>$tables,'collation'=>$collation,'canary_asserted'=>true,'scoped_authentication'=>true,'system_read_denied'=>true], JSON_THROW_ON_ERROR), "\n";
} catch (Throwable $error) {
    fwrite(STDERR, "L3 MySQL proof failed\n"); exit(1);
}
