<?php
declare(strict_types=1);
$cfg['blowfish_secret'] = trim(file_get_contents('/etc/nakpanel-database-manager/cookie.key'));
$cfg['AllowArbitraryServer'] = false;
$cfg['AllowUserDropDatabase'] = false;
$cfg['VersionCheck'] = false;
$cfg['SendErrorReports'] = 'never';
$cfg['ShowPhpInfo'] = false;
$cfg['ShowServerInfo'] = false;
$cfg['ShowChgPassword'] = false;
$cfg['PmaNoRelation_DisableWarning'] = true;
$cfg['ZeroConf'] = false;
$cfg['AllowThirdPartyFraming'] = false;
$cfg['LoginCookieValidity'] = 900;
$cfg['LoginCookieStore'] = 0;
$cfg['CookieSameSite'] = 'Strict';
$cfg['TempDir'] = '/var/lib/nakpanel-database-manager/tmp';
$cfg['UploadDir'] = '';
$cfg['SaveDir'] = '';
$cfg['ExecTimeLimit'] = 60;
$cfg['MemoryLimit'] = '128M';
$cfg['Servers'][1] = [
    'auth_type' => 'signon', 'host' => 'localhost', 'port' => '3306', 'socket' => '/run/mysqld/mysqld.sock',
    'AllowNoPassword' => false, 'AllowRoot' => false,
    'SignonScript' => '/etc/nakpanel-database-manager/signon.php',
    'SignonURL' => '/db', 'LogoutURL' => '/db',
    'only_db' => [$GLOBALS['nakpanel_credentials']['database']],
];
$cfg['ServerDefault'] = 1;
$path = $_SERVER['HTTP_X_NAKPANEL_MANAGER_PATH'] ?? '';
$host = $_SERVER['HTTP_HOST'] ?? '';
if (!preg_match('~\A/database-manager/[A-Za-z0-9_-]{32,256}/\z~D', $path)
    || !preg_match('/\A[A-Za-z0-9.-]+(?::[0-9]{1,5})?\z/D', $host)) {
    http_response_code(403);
    exit;
}
$cfg['PmaAbsoluteUri'] = 'https://' . $host . $path;
ini_set('session.cookie_path', $path);
if (!isset($_GET['db']) && !isset($_POST['db'])) {
    $_GET['db'] = $GLOBALS['nakpanel_credentials']['database'];
}
