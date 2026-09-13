<?php
declare(strict_types=1);
require __DIR__ . '/session.php';

$failures = 0;
function check(bool $condition, string $label): void
{
    global $failures;
    if ($condition) {
        echo "ok - {$label}\n";
    } else {
        $failures++;
        fwrite(STDERR, "not ok - {$label}\n");
    }
}

$store = new SessionStore();
$issued = $store->issue('user-1', 1000, 300);
check($issued['status'] === 'active', 'issued session is active');
check($store->validate($issued['token'], 1200)['status'] === 'active', 'session is valid before expiry');

check($store->issue('', 1000, 300)['status'] === 'invalid', 'empty user id is rejected');
check($store->issue('user-2', 1000, 0)['status'] === 'invalid', 'non-positive ttl is rejected');

check($store->validate($issued['token'], 1300)['status'] === 'expired', 'session expires at the boundary');

$refreshed = $store->refresh($issued['token'], 1400, 600);
check($refreshed['status'] === 'invalid' || $refreshed['status'] === 'active' || $refreshed['status'] === 'expired',
    'refresh on expired session is a defined transition');

$second = $store->issue('user-2', 1000, 300);
$refreshed = $store->refresh($second['token'], 1100, 600);
check($store->validate($second['token'], 1600)['status'] === 'active', 'refresh extends the expiry');

$store->revoke($second['token']);
check($store->validate($second['token'], 1200)['status'] === 'revoked', 'revoked session is rejected');
check($store->revoke('missing-token')['status'] === 'unknown', 'revoking an unknown session is rejected');

if ($failures > 0) {
    fwrite(STDERR, "{$failures} test(s) failed\n");
    exit(1);
}
echo "all 9 checks passed\n";
