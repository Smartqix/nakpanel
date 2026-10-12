<?php
declare(strict_types=1);
function get_login_credentials($unused): array {
    $credentials = $GLOBALS['nakpanel_credentials'] ?? null;
    if (!is_array($credentials)) { return ['', '']; }
    return [$credentials['username'], $credentials['password']];
}
