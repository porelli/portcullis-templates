#!/usr/bin/env bash
# grafana/portcullis/trust.sh with a stubbed `ip` (no Docker): what Grafana
# trusts for given interface addresses, and every refusal. Run in lint.
set -euo pipefail
cd "$(dirname "$0")/../.."
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
# The script, with /run.sh replaced by printing the allowlist.
sed 's|exec /run.sh "\$@"|printf "RESULT %s\\n" "$GF_AUTH_PROXY_WHITELIST"; exit 0|' grafana/portcullis/trust.sh > "$T/trust.sh"
grep -q '^printf "RESULT' "$T/trust.sh" || { echo "FAIL could not stub /run.sh"; exit 1; }
FAILS=0
# case NAME EXPECT(RESULT line | "refused") V4LINES [V6_ON_TRUST] [AI]
case_() {
  local name="$1" want="$2" v4="$3" v6="${4:-}" ai="${5:-true}" out rc=0
  cat > "$T/ip" <<STUB
#!/bin/sh
# ip -4 -o addr show scope global | ip -4 -o addr show dev X | ip -6 -o addr show dev X scope global
if [ "\$1" = -6 ]; then printf '%b' '$v6'; exit 0; fi
if [ "\$5" = dev ]; then printf '%b' '$v4' | awk -v d="\$6" '\$2 == d || \$2 == d":"'; exit 0; fi
printf '%b' '$v4'
STUB
  chmod +x "$T/ip"
  out=$(PATH="$T:$PATH" GF_AUTH_PROXY_WHITELIST=172.31.250.2 PORTCULLIS_AI_ENABLED="$ai" sh "$T/trust.sh" 2>"$T/err") || rc=$?
  if [ "$want" = refused ]; then
    if [ "$rc" != 0 ] && [ -z "$out" ]; then echo "  PASS $name: refused ($(tail -n1 "$T/err"))"; else echo "  FAIL $name: expected a refusal, got rc=$rc '$out'"; FAILS=$((FAILS + 1)); fi
  elif [ "$rc" = 0 ] && [ "$out" = "RESULT $want" ]; then
    echo "  PASS $name"
  else
    echo "  FAIL $name: rc=$rc '$out' (want 'RESULT $want'): $(cat "$T/err")"; FAILS=$((FAILS + 1))
  fi
}
P='2: eth0    inet 172.31.250.140/24 brd 172.31.250.255 scope global eth0\\       valid_lft forever preferred_lft forever\n'
case_ "AI off: Traefik only" 172.31.250.2 "$P" "" false
case_ "/29: the prefix minus network, gateway, own address, broadcast" \
  172.31.250.2,172.20.0.3/32,172.20.0.4/31,172.20.0.6/32 "${P}3: eth1    inet 172.20.0.2/29 brd 172.20.0.7 scope global eth1\n"
case_ "/16 (Docker's default pool), interfaces in the other order" \
  172.31.250.2,172.23.0.3/32,172.23.0.4/30,172.23.0.8/29,172.23.0.16/28,172.23.0.32/27,172.23.0.64/26,172.23.0.128/25,172.23.1.0/24,172.23.2.0/23,172.23.4.0/22,172.23.8.0/21,172.23.16.0/20,172.23.32.0/19,172.23.64.0/18,172.23.128.0/18,172.23.192.0/19,172.23.224.0/20,172.23.240.0/21,172.23.248.0/22,172.23.252.0/23,172.23.254.0/24,172.23.255.0/25,172.23.255.128/26,172.23.255.192/27,172.23.255.224/28,172.23.255.240/29,172.23.255.248/30,172.23.255.252/31,172.23.255.254/32 \
  "3: eth1    inet 172.23.0.2/16 brd 172.23.255.255 scope global eth1\n${P}"
case_ "/20 (192.168 pool)" \
  172.31.250.2,192.168.16.3/32,192.168.16.4/30,192.168.16.8/29,192.168.16.16/28,192.168.16.32/27,192.168.16.64/26,192.168.16.128/25,192.168.17.0/24,192.168.18.0/23,192.168.20.0/22,192.168.24.0/22,192.168.28.0/23,192.168.30.0/24,192.168.31.0/25,192.168.31.128/26,192.168.31.192/27,192.168.31.224/28,192.168.31.240/29,192.168.31.248/30,192.168.31.252/31,192.168.31.254/32 \
  "${P}3: eth1    inet 192.168.16.2/20 brd 192.168.31.255 scope global eth1\n"
case_ "only one network" refused "$P"
case_ "three networks" refused "${P}3: eth1    inet 172.20.0.2/29 scope global eth1\n4: eth2    inet 172.21.0.2/16 scope global eth2\n"
case_ "two addresses on the trust interface" refused "${P}3: eth1    inet 172.20.0.2/29 scope global eth1\n3: eth1    inet 172.20.0.5/29 scope global secondary eth1\n"
case_ "Traefik on neither network" refused "2: eth0    inet 10.1.0.2/24 scope global eth0\n3: eth1    inet 172.20.0.2/29 scope global eth1\n"
case_ "Traefik on both networks" refused "${P}3: eth1    inet 172.31.250.141/24 scope global eth1\n"
case_ "prefix broader than /16" refused "${P}3: eth1    inet 10.0.0.2/8 scope global eth1\n"
case_ "prefix narrower than /29" refused "${P}3: eth1    inet 10.0.0.2/30 scope global eth1\n"
case_ "global IPv6 on the trust interface" refused "${P}3: eth1    inet 172.20.0.2/29 scope global eth1\n" "3: eth1    inet6 fd00::2/64 scope global\n"
case_ "unreadable address" refused "${P}3: eth1    inet 172.20.0/29 scope global eth1\n"
cat > "$T/ip" <<'STUB'
#!/bin/sh
exit 0
STUB
out=$(PATH="$T:$PATH" GF_AUTH_PROXY_WHITELIST=172.31.250.0/24 PORTCULLIS_AI_ENABLED=false sh "$T/trust.sh" 2>/dev/null) && { echo "  FAIL a subnet as Traefik's address accepted: $out"; FAILS=$((FAILS + 1)); } || echo "  PASS a non-address GF_AUTH_PROXY_WHITELIST refused"
[ "$FAILS" = 0 ] && echo "trust.sh: all cases pass" || { echo "trust.sh: $FAILS case(s) failed"; exit 1; }
