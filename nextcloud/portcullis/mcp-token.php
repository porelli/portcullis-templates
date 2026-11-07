<?php
// Portcullis AI hooks "mcp-mint" / "mcp-revoke" (manifest hooks + ai.mcp,
// contract §15.5). The Hub runs this with Docker exec in the nextcloud
// container as www-data: `php /portcullis/mcp-token.php mint|revoke`, one
// JSON document on stdin. It mints and revokes the person's Nextcloud app
// password through occ only (verified against Nextcloud 34.0.5:
// core/Command/User/AuthTokens/{Add,ListCommand,Delete}.php,
// core/Command/User/Info.php):
//
//   mint        occ user:info <user>               the person's account:
//                                                  user_id == user exactly,
//                                                  backend user_oidc (the
//                                                  template's OIDC login maps
//                                                  preferred_username to the
//                                                  uid), enabled
//               occ user:auth-tokens:add --name    app password (72 chars),
//                                                  read from occ's stdout
//               occ user:auth-tokens:list          its id, by name
//   revoke      occ user:auth-tokens:list + :delete <uid> <id>
//                                                  the person's portcullis-ai-*
//                                                  app passwords with those ids
//                                                  (ids [] = all of them)
//   revoke_all  occ user:list + the above for every account
//
// The app password is never on an argv (occ prints it; this script reads
// the pipe and prints {"credential","id"} once). occ runs from the
// container itself, so no admin credential exists to leak. Fails closed:
// any unexpected occ answer exits 1; mint exits 3 only when occ says the
// account does not exist. A mint that fails (or is interrupted: TERM, INT,
// HUP) after occ created the app password deletes it again.
declare(strict_types=1);

const OCC = '/var/www/html/occ';
const NAME_PREFIX = 'portcullis-ai-';
const OIDC_BACKEND = 'user_oidc';
const MAX_INPUT = 65536;

/** @var array{uid: string, name: string}|null app password minted but not handed over yet */
$PENDING = null;

function fail(string $msg, int $code = 1): never
{
    fwrite(STDERR, "mcp-token: $msg\n");
    exit($code);
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

/** occ's own error text, clipped (never stdout of auth-tokens:add). */
function why(string $err): string
{
    $err = trim(preg_replace('/\s+/', ' ', $err) ?? '');
    return $err === '' ? '(no message)' : substr($err, 0, 300);
}

/**
 * The person's Nextcloud account: the uid the template's OIDC login gives
 * them (user_oidc, uid = preferred_username = the LLDAP username). null when
 * occ says there is none; exits 1 on anything unexpected.
 *
 * @return array{uid: string, enabled: bool, oidc: bool}|null
 */
function account(string $user): ?array
{
    // Never an option or an impossible uid (user_oidc's column is 64 chars).
    if (preg_match('/^[A-Za-z0-9_.@][A-Za-z0-9_.@-]{0,63}$/D', $user) !== 1) {
        return null;
    }
    [$rc, $out, $err] = occ(['user:info', '--output=json', '--', $user]);
    if ($rc === 1 && trim($out) === 'user not found') {
        return null;
    }
    if ($rc !== 0) {
        fail("occ user:info exited $rc: " . why($err !== '' ? $err : $out));
    }
    $info = json_decode(trim($out), true);
    if (!is_array($info) || !is_string($info['user_id'] ?? null) || !is_bool($info['enabled'] ?? null)
        || !is_string($info['backend'] ?? null)) {
        fail('occ user:info: unexpected output');
    }
    if ($info['user_id'] !== $user) {
        // Another spelling of the name (case-insensitive lookups): not this person.
        return null;
    }
    return ['uid' => $info['user_id'], 'enabled' => $info['enabled'], 'oidc' => $info['backend'] === OIDC_BACKEND];
}

/**
 * The account's app passwords: [id => name]. Exits 1 on any failure.
 *
 * @return array<int, string>
 */
function tokens(string $uid): array
{
    [$rc, $out, $err] = occ(['user:auth-tokens:list', '--output=json', '--', $uid]);
    if ($rc !== 0) {
        fail("occ user:auth-tokens:list exited $rc: " . why($err !== '' ? $err : $out));
    }
    $list = json_decode(trim($out), true);
    if (!is_array($list)) {
        fail('occ user:auth-tokens:list: unexpected output');
    }
    $res = [];
    foreach ($list as $t) {
        if (!is_array($t) || !is_int($t['id'] ?? null) || !is_string($t['name'] ?? null) || ($t['uid'] ?? $uid) !== $uid) {
            fail('occ user:auth-tokens:list: unexpected entry');
        }
        $res[$t['id']] = $t['name'];
    }
    return $res;
}

/** Deletes one app password of the account (a gone one counts as deleted). */
function delete_token(string $uid, int $id): void
{
    // --cancel-wipe: an AI credential marked for remote wipe is still revoked.
    [$rc, $out, $err] = occ(['user:auth-tokens:delete', '--cancel-wipe', '--', $uid, (string) $id]);
    if ($rc !== 0) {
        fail("occ user:auth-tokens:delete exited $rc: " . why($err !== '' ? $err : $out));
    }
}

/**
 * Deletes the account's portcullis-ai-* app passwords ($ids null = all of
 * them) and checks they are gone.
 *
 * @param list<int>|null $ids
 */
function revoke_tokens(string $uid, ?array $ids): void
{
    $want = static fn(int $id, string $name): bool =>
        str_starts_with($name, NAME_PREFIX) && ($ids === null || in_array($id, $ids, true));
    foreach (tokens($uid) as $id => $name) {
        if ($want($id, $name)) {
            delete_token($uid, $id);
        }
    }
    foreach (tokens($uid) as $id => $name) {
        if ($want($id, $name)) {
            fail("app password $id of $uid is still there after delete");
        }
    }
}

/** Removes the app password a failed or interrupted mint created. */
function cleanup_pending(): void
{
    global $PENDING;
    if ($PENDING === null) {
        return;
    }
    [$uid, $name] = [$PENDING['uid'], $PENDING['name']];
    $PENDING = null;
    [$rc, $out] = occ(['user:auth-tokens:list', '--output=json', '--', $uid]);
    $list = $rc === 0 ? json_decode(trim($out), true) : null;
    if (!is_array($list)) {
        fwrite(STDERR, "mcp-token: could not list $uid's app passwords to remove the unissued $name\n");
        return;
    }
    foreach ($list as $t) {
        if (is_array($t) && ($t['name'] ?? null) === $name && is_int($t['id'] ?? null)) {
            [$rc] = occ(['user:auth-tokens:delete', '--cancel-wipe', '--', $uid, (string) $t['id']]);
            if ($rc !== 0) {
                fwrite(STDERR, "mcp-token: could not remove the unissued app password $name of $uid\n");
            }
        }
    }
}

register_shutdown_function('cleanup_pending');
// The nextcloud image ships pcntl; without it an interrupted mint could
// leave an unissued app password behind, so refuse to run.
if (!function_exists('pcntl_async_signals')) {
    fail('the pcntl extension is missing');
}
pcntl_async_signals(true);
foreach ([SIGTERM, SIGINT, SIGHUP] as $sig) {
    pcntl_signal($sig, static function (): never {
        exit(143); // runs cleanup_pending (shutdown function)
    });
}

// ── Input: one JSON document, exactly the §15.5 shapes ──
$verb = $argv[1] ?? '';
if ($argc !== 2 || !in_array($verb, ['mint', 'revoke'], true)) {
    fail('usage: mcp-token.php mint|revoke');
}
$raw = stream_get_contents(STDIN, MAX_INPUT + 1);
if ($raw === false || $raw === '' || strlen($raw) > MAX_INPUT) {
    fail('no input, or input too large');
}
try {
    $in = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
} catch (JsonException) {
    fail('input is not JSON');
}
if (!is_array($in) || array_is_list($in)) {
    fail('input is not a JSON object');
}
$keys = array_keys($in);
sort($keys);
$is_str = static fn(mixed $v): bool => is_string($v) && $v !== '' && strlen($v) <= 255;
$id_shape = static fn(mixed $v): bool => is_string($v) && preg_match('/^[a-z0-9]+(-[a-z0-9]+)*$/D', $v) === 1 && strlen($v) <= 63;

if ($verb === 'mint') {
    if ($keys !== ['action', 'companion', 'instance', 'mode', 'name', 'scopes', 'user'] || $in['action'] !== 'mint'
        || !$is_str($in['user']) || !$id_shape($in['instance']) || !$id_shape($in['companion'])
        || !is_string($in['name']) || preg_match('/^portcullis-ai-[a-z0-9]{12}$/D', $in['name']) !== 1
        || !in_array($in['mode'], ['read_only', 'read_write'], true)
        // Nextcloud app passwords have no scopes; the manifest declares none.
        || $in['scopes'] !== []) {
        fail('unexpected mint input');
    }
    $acct = account($in['user']);
    if ($acct === null) {
        fail('no Nextcloud account for this person yet (they never signed in)', 3);
    }
    if (!$acct['oidc']) {
        fail('the Nextcloud account of that name is not a Portcullis (user_oidc) account');
    }
    if (!$acct['enabled']) {
        fail('the Nextcloud account is disabled');
    }
    $uid = $acct['uid'];
    $name = $in['name'];
    if (in_array($name, tokens($uid), true)) {
        fail('an app password of that name exists already');
    }

    $PENDING = ['uid' => $uid, 'name' => $name];
    [$rc, $out, $err] = occ(['user:auth-tokens:add', '--name=' . $name, '--', $uid]);
    if ($rc !== 0) {
        fail("occ user:auth-tokens:add exited $rc: " . why($err));
    }
    // "No password provided. …" (always: no login password exists), then
    // "app password:" and the 72-character password.
    if (preg_match('/\A(?:No password provided\.[^\n]*\n)?app password:\n([A-Za-z0-9]{72})\n\z/', $out, $m) !== 1) {
        fail('occ user:auth-tokens:add: unexpected output');
    }
    $cred = $m[1];
    $ids = array_keys(tokens($uid), $name, true);
    if (count($ids) !== 1) {
        fail('the new app password was not found exactly once');
    }
    $PENDING = null;
    printf("{\"credential\":\"%s\",\"id\":\"%d\"}\n", $cred, $ids[0]);
    exit(0);
}

if (($in['action'] ?? null) === 'revoke') {
    if ($keys !== ['action', 'ids', 'user'] || !$is_str($in['user']) || !is_array($in['ids']) || !array_is_list($in['ids'])
        || count($in['ids']) > 1000) {
        fail('unexpected revoke input');
    }
    $ids = [];
    foreach ($in['ids'] as $id) {
        if (!is_string($id) || preg_match('/^[1-9][0-9]{0,17}$/D', $id) !== 1) {
            fail('unexpected revoke input (ids)');
        }
        $ids[] = (int) $id;
    }
    $acct = account($in['user']);
    if ($acct === null) {
        exit(0); // no account: nothing to revoke (Nextcloud deletes a deleted account's app passwords)
    }
    revoke_tokens($acct['uid'], $ids === [] ? null : $ids);
    exit(0);
}

if (($in['action'] ?? null) === 'revoke_all') {
    if ($keys !== ['action', 'prefix'] || $in['prefix'] !== NAME_PREFIX) {
        fail('unexpected revoke_all input');
    }
    [$rc, $out, $err] = occ(['user:list', '--limit=0', '--output=json']);
    $users = $rc === 0 ? json_decode(trim($out), true) : null;
    if (!is_array($users)) {
        fail("occ user:list failed ($rc): " . why($err));
    }
    foreach (array_keys($users) as $uid) {
        revoke_tokens((string) $uid, null);
    }
    exit(0);
}

fail('unexpected action');
