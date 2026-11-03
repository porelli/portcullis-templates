<?php
// Portcullis settings hook "apply-settings" (manifest hooks[], contract
// §13.8). The Hub runs it with Docker exec in the nextcloud container as
// www-data, at start and after a settings save, with the desired state as
// JSON (HookInput) on stdin. It applies the instance options through occ,
// idempotently (a value that is already set is left alone), and exits
// non-zero on bad input or on any occ failure: the Hub then records the
// delivery as failed and retries it on the next trigger.
//
//   values.default_quota    files default_quota: an integer number of GiB,
//                           written "<n> GB" (Nextcloud reads GB as 1024^3),
//                           or "none" (unlimited)
//   values.trash_retention  system trashbin_retention_obligation "auto, <d>":
//                           deleted files are removed after <d> days (earlier
//                           only when space runs out)
//
// An option missing from values (or null) is left as it is.
declare(strict_types=1);

const OCC = '/var/www/html/occ';
const INSTALL_WAIT = 45; // seconds; the hook's timeout is 60s

function fail(string $msg): never
{
    fwrite(STDERR, "apply-settings: $msg\n");
    exit(1);
}

/** Runs occ with an argv list (no shell). Returns [exit code, stdout, stderr]. */
function occ(array $args): array
{
    $cmd = array_merge([PHP_BINARY, OCC, '--no-interaction', '--no-ansi'], $args);
    $p = proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(OCC));
    if (!is_resource($p)) {
        fail('cannot run occ');
    }
    $out = (string) stream_get_contents($pipes[1]);
    $err = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return [proc_close($p), $out, $err];
}

/** Sets a config value through occ unless it already has $want. */
function ensure(string $what, array $get, array $set, string $want): void
{
    [$rc, $out] = occ($get);
    if ($rc === 0 && rtrim($out, "\r\n") === $want) {
        echo "apply-settings: $what already $want\n";
        return;
    }
    [$rc, $out, $err] = occ(array_merge($set, ['--value=' . $want]));
    if ($rc !== 0) {
        fail("$what: occ exited $rc: " . trim($err !== '' ? $err : $out));
    }
    [$rc, $out] = occ($get);
    if ($rc !== 0 || rtrim($out, "\r\n") !== $want) {
        fail("$what: occ did not keep the value $want");
    }
    echo "apply-settings: $what set to $want\n";
}

/** A non-negative whole number (JSON number or digit string), else null. */
function whole(mixed $v): ?int
{
    if (is_int($v) && $v >= 0) {
        return $v;
    }
    if (is_string($v) && preg_match('/^[0-9]{1,15}$/D', $v) === 1) {
        return (int) $v;
    }
    return null;
}

$raw = stream_get_contents(STDIN);
if ($raw === false || $raw === '') {
    fail('no input on stdin');
}
try {
    $in = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
} catch (JsonException $e) {
    fail('input is not JSON: ' . $e->getMessage());
}
if (!is_array($in) || ($in['version'] ?? null) !== 1) {
    fail('unexpected input (want HookInput version 1)');
}
$values = $in['values'] ?? [];
if (!is_array($values)) {
    fail('input values is not an object');
}

// Validate everything before changing anything.
$quota = null;
if (isset($values['default_quota'])) {
    $v = $values['default_quota'];
    if ($v === 'none') {
        $quota = 'none';
    } elseif (($n = whole($v)) !== null) {
        $quota = $n . ' GB';
    } else {
        fail('default_quota must be a whole number of GiB or "none"');
    }
}
$retention = null;
if (isset($values['trash_retention'])) {
    $n = whole($values['trash_retention']);
    if ($n === null || $n < 1) {
        fail('trash_retention must be a whole number of days (at least 1)');
    }
    $retention = 'auto, ' . $n;
}
if ($quota === null && $retention === null) {
    echo "apply-settings: nothing to apply\n";
    exit(0);
}

// At start the hook may run while the image's entrypoint still installs or
// upgrades Nextcloud: wait for an installed instance out of maintenance.
$deadline = time() + INSTALL_WAIT;
for (;;) {
    [$rc, $out] = occ(['status', '--output=json']);
    $st = $rc === 0 ? json_decode(trim($out), true) : null;
    if (is_array($st) && ($st['installed'] ?? false) === true && ($st['maintenance'] ?? true) === false
        && ($st['needsDbUpgrade'] ?? false) === false) {
        break;
    }
    if (time() >= $deadline) {
        fail('Nextcloud is not installed and ready yet; retry the delivery once it has started');
    }
    sleep(3);
}

if ($quota !== null) {
    ensure('files default_quota', ['config:app:get', 'files', 'default_quota'],
        ['config:app:set', 'files', 'default_quota'], $quota);
}
if ($retention !== null) {
    ensure('trashbin_retention_obligation', ['config:system:get', 'trashbin_retention_obligation'],
        ['config:system:set', 'trashbin_retention_obligation'], $retention);
}
