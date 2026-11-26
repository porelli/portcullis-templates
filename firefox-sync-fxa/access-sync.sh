#!/bin/sh
# fxa-access-sync's hook (manifest hooks[] access-sync, start and
# membership_change): who may have an account is Portcullis's access group.
# The verified emails of its members (the Hub's data file access.json,
# people.<user>.email; a member without a verified email isn't in it) become
# the sign-up allowlist of the accounts (ffs.signup_allowlist, porelli's
# sign-up policy with access managed elsewhere), and the accounts of people
# who left are disabled, re-enabled when they come back.
#
#   new      = the file's emails, lowercased, sorted, unique
#   db       = the allowlist's rows (read FOR UPDATE in the transaction)
#   leaves   = (db + state.listed + state.removed) - new
#                -> their rows deleted, then ffs.disable_account_by_email
#   joins    = new - db -> inserted (every member's row made sure of)
#   rejoins  = new & state.removed -> ffs.enable_account_by_email
#   state    = {listed: new, removed: (state.removed + leaves) - new
#               - the leavers without an account}
#
# Every run (start and membership_change) disables every account of a
# non-member it knows of, not only on a transition; "no such account" is
# ignored, an account already disabled stays as it is (the procedure keeps
# its disabledAt). A member is never enabled but on coming back (rejoins): a
# member an admin disabled stays disabled.
#
# Fails closed: a missing, unreadable or unparsable data file, a version
# other than 1 or another instance's file is exit 1 before any SQL. An email
# becomes an SQL literal only after it matches
# ^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+$ (at most 254 characters), its
# quotes doubled; one that doesn't is left out (that person is no member
# here). The allowlist changes are one transaction; the accounts are then
# disabled / enabled one CALL each (porelli's procedures commit by
# themselves: sign_out_all starts its own transaction). The state is written
# atomically after both, so a failed run is redone in full by the next.
#
# Exit 0: applied. Exit 1: refused or failed: before the transaction
# nothing changed; after it the allowlist is applied and a disable / enable
# failed 3 times (the next run redoes them). Logs counts only, never an email or a password. The
# password reaches mysql only through MYSQL_PWD (the service's environment),
# never argv.
#
# Environment: MYSQL_HOST, MYSQL_PWD (ffs_access), PORTCULLIS_INSTANCE;
# FXA_ACCESS_FILE (default /portcullis/access.json) and FXA_ACCESS_STATE
# (default /state/applied.json) for tests.
set -u
umask 077
export LC_ALL=C

ACCESS_FILE=${FXA_ACCESS_FILE:-/portcullis/access.json}
STATE_FILE=${FXA_ACCESS_STATE:-/state/applied.json}
# The largest data file read (the Hub's has one short entry per member).
MAX_BYTES=4194304
EMAIL_RE='^[a-z0-9.!#$%&'"'"'*+/=?^_`{|}~-]+@[a-z0-9.-]+$'

say() { echo "access-sync: $*" >&2; }
die() { say "$*: nothing changed"; exit 1; }

# The Hub's HookInput on stdin (the data file is read instead): drained.
[ -t 0 ] || cat > /dev/null

work=$(mktemp -d) || die "no temporary directory"
trap 'rm -rf "$work"' EXIT

# json_read <file> <mode>: a strict JSON reader (RFC 8259: one value, no
# trailing commas or comments, no duplicate keys, nesting at most 32).
# mode access: prints "E <email>" for each people.<user>.email of a version 1
# file of $PORTCULLIS_INSTANCE. mode state: prints "L <email>" / "R <email>"
# for listed / removed of a version 1 state file. Escaped and raw control
# characters in a value become \001 (never a line break in the output). On
# any error prints "ERR <reason>" alone and exits 1.
json_read() {
  awk -v mode="$2" -v want="${PORTCULLIS_INSTANCE:-}" '
    function perr(m) { if (err == "") err = m }
    function ws(  c) {
      while (pos <= n) { c = substr(s, pos, 1); if (c == " " || c == "\t" || c == "\n" || c == "\r") pos++; else break }
    }
    function hexval(h,  i, v) {
      v = 0
      for (i = 1; i <= 4; i++) v = v * 16 + index("0123456789abcdef", tolower(substr(h, i, 1))) - 1
      return v
    }
    function pstr(  out, c, e, h, v) {
      pos++
      out = ""
      while (err == "") {
        if (pos > n) { perr("an unterminated string"); return "" }
        c = substr(s, pos, 1)
        if (c == "\"") { pos++; return out }
        if (index(ctl, c)) { perr("a control character in a string"); return "" }
        if (c != "\\") { out = out c; pos++; continue }
        e = substr(s, pos + 1, 1)
        if (e == "\"" || e == "\\" || e == "/") { out = out e; pos += 2 }
        else if (e == "b" || e == "f" || e == "n" || e == "r" || e == "t") { out = out "\001"; pos += 2 }
        else if (e == "u") {
          h = substr(s, pos + 2, 4)
          if (h !~ /^[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]$/) { perr("a bad \\u escape"); return "" }
          v = hexval(h)
          out = out ((v >= 32 && v < 127) ? sprintf("%c", v) : "\001")
          pos += 6
        } else { perr("a bad escape"); return "" }
      }
      return ""
    }
    function pnum(  t, c) {
      t = substr(s, pos)
      if (!match(t, /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?/)) { perr("a bad number"); return "" }
      t = substr(t, 1, RLENGTH)
      pos += RLENGTH
      c = substr(s, pos, 1)
      if (c != "" && index("0123456789.eE+-", c)) { perr("a bad number"); return "" }
      return t
    }
    # pval(ctx, depth): ctx says what the value is (top, people, person,
    # email, version, instance, list, item, any); sets vtype.
    function pval(ctx, depth,  c, t) {
      ws()
      if (depth > 32) { perr("nested too deep"); return }
      c = substr(s, pos, 1)
      if (c == "{") { vtype = "object"; pobj(ctx, depth + 1); vtype = "object"; return }
      if (c == "[") { vtype = "array"; parr(ctx, depth + 1); vtype = "array"; return }
      if (c == "\"") { t = pstr(); vtype = "string"; vstr = t; return }
      if (c == "-" || index("0123456789", c)) { vstr = pnum(); vtype = "number"; return }
      if (substr(s, pos, 4) == "true") { pos += 4; vtype = "bool"; return }
      if (substr(s, pos, 5) == "false") { pos += 5; vtype = "bool"; return }
      if (substr(s, pos, 4) == "null") { pos += 4; vtype = "null"; return }
      perr(pos > n ? "an unexpected end" : "an unexpected character")
    }
    function sub_ctx(ctx, key) {
      if (ctx == "top" && mode == "access") {
        if (key == "version") return "version"
        if (key == "instance") return "instance"
        if (key == "people") return "people"
      }
      if (ctx == "top" && mode == "state") {
        if (key == "version") return "version"
        if (key == "listed") return "L"
        if (key == "removed") return "R"
      }
      if (ctx == "people") return "person"
      if (ctx == "person" && key == "email") return "email"
      return "any"
    }
    function pobj(ctx, depth,  id, key, sc, c) {
      pos++
      id = ++objs
      ws()
      if (substr(s, pos, 1) == "}") { pos++; return }
      while (err == "") {
        ws()
        if (substr(s, pos, 1) != "\"") { perr("an object key that is not a string"); return }
        key = pstr()
        if (err != "") return
        if ((id, key) in seen) { perr("a duplicate key"); return }
        seen[id, key] = 1
        ws()
        if (substr(s, pos, 1) != ":") { perr("a missing colon"); return }
        pos++
        sc = sub_ctx(ctx, key)
        pval(sc, depth)
        if (err != "") return
        check(sc)
        if (err != "") return
        ws()
        c = substr(s, pos, 1)
        if (c == ",") { pos++; continue }
        if (c == "}") { pos++; return }
        perr("a missing comma or brace"); return
      }
    }
    function parr(ctx, depth,  ic, c) {
      pos++
      ic = (ctx == "L" || ctx == "R") ? "item" ctx : "any"
      ws()
      if (substr(s, pos, 1) == "]") { pos++; return }
      while (err == "") {
        pval(ic, depth)
        if (err != "") return
        check(ic)
        if (err != "") return
        ws()
        c = substr(s, pos, 1)
        if (c == ",") { pos++; continue }
        if (c == "]") { pos++; return }
        perr("a missing comma or bracket"); return
      }
    }
    # check(ctx): the value just read, as ctx wants it.
    function check(ctx) {
      if (ctx == "version") { if (vtype != "number" || vstr != "1") perr("version is not 1"); else got_version = 1 }
      else if (ctx == "instance") { if (vtype != "string") perr("instance is not a string"); else { got_instance = 1; instance = vstr } }
      else if (ctx == "people") { if (vtype != "object") perr("people is not an object"); else got_people = 1 }
      else if (ctx == "person") { if (vtype != "object") perr("a person is not an object") }
      else if (ctx == "email") { if (vtype != "string") perr("an email is not a string"); else out[++nout] = "E " vstr }
      else if (ctx == "L" || ctx == "R") { if (vtype != "array") perr(ctx == "L" ? "listed is not a list" : "removed is not a list"); else got[ctx] = 1 }
      else if (ctx == "itemL" || ctx == "itemR") { if (vtype != "string") perr("a list item is not a string"); else out[++nout] = substr(ctx, 5) " " vstr }
    }
    { s = s $0 "\n" }
    END {
      for (i = 1; i < 32; i++) ctl = ctl sprintf("%c", i)
      n = length(s); pos = 1; err = ""
      ws()
      if (substr(s, pos, 1) != "{") perr("not a JSON object")
      else pval("top", 0)
      if (err == "") { ws(); if (pos <= n) perr("trailing data after the document") }
      if (err == "" && !got_version) perr("no version")
      if (err == "" && mode == "access" && !got_instance) perr("no instance")
      if (err == "" && mode == "access" && !got_people) perr("no people")
      if (err == "" && mode == "access" && (want == "" || instance != want)) perr("not the data file of this instance (PORTCULLIS_INSTANCE)")
      if (err == "" && mode == "state" && !(got["L"] && got["R"])) perr("no listed or removed")
      if (err != "") { print "ERR " err; exit 1 }
      for (i = 1; i <= nout; i++) print out[i]
    }' "$1"
}

# plain <tag> < "E/L/R lines": the emails of one tag, trimmed, lowercased,
# that may become SQL literals (the regex, 254 characters at most), sorted
# and unique; the count of those that may not goes to $work/refused.<tag>.
plain() {
  awk -v tag="$1" -v re="$EMAIL_RE" -v rf="$work/refused.$1" '
    substr($0, 1, 2) == tag " " {
      e = tolower(substr($0, 3)); sub(/^[ \t]+/, "", e); sub(/[ \t]+$/, "", e)
      if (length(e) <= 254 && e ~ re) print e; else bad++
    }
    END { print bad + 0 > rf }' | sort -u
}

# ── the data file ──
[ -f "$ACCESS_FILE" ] && [ -r "$ACCESS_FILE" ] || die "the data file $ACCESS_FILE is missing or unreadable"
size=$(wc -c < "$ACCESS_FILE" | tr -d ' ') || die "the data file can't be read"
[ "$size" -le "$MAX_BYTES" ] 2> /dev/null || die "the data file is larger than $MAX_BYTES bytes"
# awk may drop a NUL byte: none is valid JSON outside a string either.
[ "$(tr -d '\000' < "$ACCESS_FILE" | wc -c | tr -d ' ')" = "$size" ] || die "the data file holds a NUL byte"
if ! json_read "$ACCESS_FILE" access > "$work/access"; then
  die "the data file isn't a valid version 1 data file of this instance ($(sed -n 's/^ERR //p' "$work/access" | head -1))"
fi
plain E < "$work/access" > "$work/new"
skipped=$(cat "$work/refused.E")

# ── the state of the last applied run (none: from the database alone) ──
: > "$work/listed"; : > "$work/removed"
if [ -f "$STATE_FILE" ]; then
  if json_read "$STATE_FILE" state > "$work/state"; then
    plain L < "$work/state" > "$work/listed"
    plain R < "$work/state" > "$work/removed"
  else
    say "the state file is unreadable ($(sed -n 's/^ERR //p' "$work/state" | head -1)): from the allowlist alone"
  fi
fi

q() { sed "s/'/''/g"; }  # SQL literal body: quotes doubled (the regex allows no backslash)

my() {  # mysql as ffs_access; the password only in MYSQL_PWD
  mysql --no-defaults --protocol=tcp -h "${MYSQL_HOST:?MYSQL_HOST must be set}" -u ffs_access \
    --default-character-set=utf8mb4 --connect-timeout=10 --batch --skip-column-names --silent "$@"
}
[ -n "${MYSQL_PWD:-}" ] || die "MYSQL_PWD (ffs_access's password) is not set"

# ── one transaction: read the allowlist under lock, delete every row of a
# non-member, insert every member's missing row ──
{
  echo "SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION';"
  echo "START TRANSACTION;"
  echo "SELECT entry FROM ffs.signup_allowlist ORDER BY entry FOR UPDATE;"
  if [ -s "$work/new" ]; then
    printf "DELETE FROM ffs.signup_allowlist WHERE entry NOT IN (%s);\n" \
      "$(q < "$work/new" | sed "s/.*/'&'/" | paste -sd, -)"
    printf "INSERT INTO ffs.signup_allowlist (entry) SELECT n.e FROM (%s) AS n WHERE NOT EXISTS (SELECT 1 FROM ffs.signup_allowlist a WHERE a.entry = n.e);\n" \
      "$(q < "$work/new" | sed "s/.*/SELECT '&' AS e/" | sed '2,$s/^/UNION ALL /' | paste -sd' ' -)"
  else
    echo "DELETE FROM ffs.signup_allowlist;"
  fi
  echo "COMMIT;"
  echo "SELECT 'portcullis-access-committed';"
} > "$work/tx.sql"
if ! my < "$work/tx.sql" > "$work/tx.out" 2> "$work/tx.err"; then
  die "the allowlist transaction failed ($(sed 's/at line [0-9]*: .*/(details withheld)/' "$work/tx.err" | head -1))"
fi
[ "$(tail -n 1 "$work/tx.out")" = portcullis-access-committed ] || die "the allowlist transaction didn't confirm its commit"
sed '$d' "$work/tx.out" > "$work/db.raw"
rows_before=$(grep -c '' "$work/db.raw")
sed 's/^/D /' "$work/db.raw" | plain D > "$work/db"

# ── the sets ──
# comm needs sorted input: every list above is sort -u'd in the C locale.
sort -u "$work/db" "$work/listed" "$work/removed" | comm -23 - "$work/new" > "$work/leaves"
comm -23 "$work/new" "$work/db" > "$work/joins"
comm -12 "$work/new" "$work/removed" > "$work/rejoins"
left=$(comm -23 "$work/listed" "$work/new" | grep -c '')
joined=$(grep -c '' "$work/joins")

# ── the accounts: one CALL a line, "no such account" ignored; a call that
# fails otherwise (a deadlock with fxa-auth's writes, a lost connection) is
# tried again, up to ACCESS_TRIES times in all with a short backoff; if one
# still fails the run fails (the state stays as it was: the next run does it
# all again, and the Hub records the failed hook) ──
ACCESS_TRIES=3
NOACCT_RE='^ERROR 1644 \(45000\) at line [0-9]+: no such account$'
{ sed 's/^/D /' "$work/leaves"; sed 's/^/E /' "$work/rejoins"; } > "$work/pending"
: > "$work/noacct"
try=1
while [ -s "$work/pending" ]; do
  {
    sed -n 's/^D //p' "$work/pending" | q | sed "s/.*/CALL ffs.disable_account_by_email('&');/"
    sed -n 's/^E //p' "$work/pending" | q | sed "s/.*/CALL ffs.enable_account_by_email('&');/"
    echo "SELECT 'portcullis-access-calls';"
  } > "$work/calls.sql"
  # the statements in that order: line n of calls.sql = line n of order
  { grep '^D ' "$work/pending"; grep '^E ' "$work/pending"; } > "$work/order"
  my --force < "$work/calls.sql" > "$work/calls.out" 2> "$work/calls.err"
  if [ "$(tail -n 1 "$work/calls.out")" = portcullis-access-calls ]; then
    # done but for the lines that failed; "no such account" is done too
    sed -n 's/^ERROR 1644 (45000) at line \([0-9]*\): no such account$/\1/p' "$work/calls.err" \
      | awk 'NR == FNR { n[$1] = 1; next } (FNR in n)' - "$work/order" >> "$work/noacct"
    grep -v -E "$NOACCT_RE" "$work/calls.err" | sed -n 's/^ERROR [0-9]* ([0-9A-Z]*) at line \([0-9]*\): .*/\1/p' \
      | awk 'NR == FNR { n[$1] = 1; next } (FNR in n)' - "$work/order" > "$work/pending.next"
    if grep -v -E "$NOACCT_RE" "$work/calls.err" | grep -v -E '^ERROR [0-9]+ \([0-9A-Z]+\) at line [0-9]+: ' | grep -q ''; then
      cp "$work/order" "$work/pending.next"   # an error that names no line: all again
    fi
  else
    cp "$work/order" "$work/pending.next"     # the session stopped: all again (idempotent)
  fi
  why=$(grep -v -E "$NOACCT_RE" "$work/calls.err" | sed 's/ at line [0-9]*: .*//; s/: .*//' | head -1)
  mv -f "$work/pending.next" "$work/pending"
  [ -s "$work/pending" ] || break
  if [ "$try" -ge "$ACCESS_TRIES" ]; then
    say "$(grep -c '^D ' "$work/pending") disables and $(grep -c '^E ' "$work/pending") enables still failed after $try tries (${why:-the session stopped}); the allowlist is applied, the next run does the accounts again"
    exit 1
  fi
  say "$(grep -c '' "$work/pending") calls failed (${why:-the session stopped}): trying again"
  sleep $((try * ${FXA_ACCESS_BACKOFF:-2}))
  try=$((try + 1))
done
ndis=$(grep -c '' "$work/leaves")
noacct_dis=$(grep -c '^D ' "$work/noacct")
noacct_en=$(grep -c '^E ' "$work/noacct")
sed -n 's/^D //p' "$work/noacct" | sort -u > "$work/gone"

# ── the state, atomically ──
state_dir=$(dirname "$STATE_FILE")
tmp="$state_dir/.applied.json.$$"
json_list() { sed 's/.*/"&"/' "$1" | paste -sd, -; }
# A leaver without an account ("no such account") isn't kept: none can
# appear under that email while it is off the allowlist.
sort -u "$work/removed" "$work/leaves" | comm -23 - "$work/new" | comm -23 - "$work/gone" > "$work/removed.next"
if ! printf '{"version":1,"listed":[%s],"removed":[%s]}\n' "$(json_list "$work/new")" "$(json_list "$work/removed.next")" > "$tmp" \
    || ! mv -f "$tmp" "$STATE_FILE"; then
  rm -f "$tmp"
  say "the state couldn't be written to $STATE_FILE; the allowlist and the accounts are applied, the next run does them again"
  exit 1
fi

say "applied: $(grep -c '' "$work/new") listed ($joined new rows, $left left since the last run, $((rows_before - $(grep -c '' "$work/new") + joined)) rows removed), $((ndis - noacct_dis)) accounts of non-members disabled or kept disabled ($noacct_dis without an account), $(($(grep -c '' "$work/rejoins") - noacct_en)) re-enabled, $skipped emails left out (not a plain address)"
exit 0
