#!/usr/bin/env bash
# Tests for verify.sh: unit-tests the SAN/status/expiry helpers, then runs the
# script against a local openssl s_server with a generated certificate.
# Skips (exit 0) when openssl or curl is missing.
set -u
dir="$(cd "$(dirname "$0")" && pwd)"
command -v openssl >/dev/null && command -v curl >/dev/null || { echo "SKIP: openssl/curl missing"; exit 0; }
# shellcheck source=verify.sh
. "$dir/verify.sh"
fails=0
ok() { if "$@" >/dev/null; then :; else echo "FAIL: $*"; fails=$((fails + 1)); fi; }
no() { if "$@" >/dev/null; then echo "FAIL (expected no): $*"; fails=$((fails + 1)); fi; }

# SAN matching
ok san_match app.example.test "DNS:app.example.test, DNS:other.example.test"
ok san_match APP.example.test "DNS:app.example.test"
ok san_match app.example.test "DNS:*.example.test, DNS:example.test"
no san_match example.test "DNS:*.example.test"
no san_match a.b.example.test "DNS:*.example.test"
no san_match .example.test "DNS:*.example.test"
no san_match evilexample.test "DNS:*.example.test"
no san_match app.example.test "DNS:*.other.test, IP Address:192.0.2.1"
no san_match app.example.test ""
# status classes
[[ "$(status_class 200)" == 2xx ]] || { echo "FAIL 200"; fails=$((fails + 1)); }
[[ "$(status_class 302)" == 3xx ]] || { echo "FAIL 302"; fails=$((fails + 1)); }
[[ "$(status_class 404)" == 4xx ]] || { echo "FAIL 404"; fails=$((fails + 1)); }
[[ "$(status_class 401)" == auth && "$(status_class 403)" == auth ]] || { echo "FAIL auth"; fails=$((fails + 1)); }
no status_class 502
no status_class 000
[[ "$(issuer_flag 'C=US, O=(STAGING) Let'"'"'s Encrypt')" == STAGING ]] || { echo "FAIL staging"; fails=$((fails + 1)); }
[[ "$(issuer_flag 'CN=Fake LE Intermediate X1')" == STAGING ]] || { echo "FAIL fakele"; fails=$((fails + 1)); }
[[ "$(issuer_flag 'O=Let'"'"'s Encrypt')" == ok ]] || { echo "FAIL issuer ok"; fails=$((fails + 1)); }
[[ "$(expiry_state 1 1)" == fail && "$(expiry_state 0 1)" == warn && "$(expiry_state 0 0)" == ok ]] || { echo "FAIL expiry"; fails=$((fails + 1)); }

# Integration
tmp="$(mktemp -d)"
pid=""
cleanup() { [[ -n "$pid" ]] && { kill "$pid" 2>/dev/null; { wait "$pid"; } 2>/dev/null; }; rm -rf "$tmp"; }
trap cleanup EXIT
mkcert() { # mkcert DAYS SAN
	openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/k.pem" -out "$tmp/c.pem" -days "$1" \
		-subj "/CN=app.example.test" -addext "subjectAltName=$2" >/dev/null 2>&1
}
port=$((20000 + RANDOM % 20000))
serve() {
	[[ -n "$pid" ]] && { kill "$pid" 2>/dev/null; { wait "$pid"; } 2>/dev/null; }
	openssl s_server -accept "$port" -cert "$tmp/c.pem" -key "$tmp/k.pem" -www -quiet >/dev/null 2>&1 &
	pid=$!
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		(exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && return 0
		sleep 0.2
	done
	echo "FAIL: s_server did not start"; fails=$((fails + 1))
}
printf '# comment\napp.example.test\n\n' >"$tmp/hosts"
printf 'wrong.other.test\n' >"$tmp/hosts-wrong"
printf 'bad host;rm -rf x\n' >"$tmp/hosts-bad"

run() { bash "$dir/verify.sh" "$@" >"$tmp/out" 2>"$tmp/err"; }

mkcert 90 "DNS:*.example.test"; serve
run "$tmp/hosts" --resolve 127.0.0.1 --port "$port" --cacert "$tmp/c.pem"
ok test $? -eq 0
run "$tmp/hosts-wrong" --resolve 127.0.0.1 --port "$port" --insecure
no test $? -eq 0
grep -q "SAN does not cover" "$tmp/out" || { echo "FAIL: wrong host should report SAN"; fails=$((fails + 1)); }
run "$tmp/hosts-bad" --resolve 127.0.0.1 --port "$port"
no test $? -eq 0
grep -q "invalid hostname" "$tmp/out" || { echo "FAIL: invalid hostname"; fails=$((fails + 1)); }
run "$tmp/hosts" --port "$port"
ok test $? -eq 2
# Untrusted cert without --insecure/--cacert must fail on curl verification.
run "$tmp/hosts" --resolve 127.0.0.1 --port "$port"
no test $? -eq 0

mkcert 3 "DNS:app.example.test"; serve
run "$tmp/hosts" --resolve 127.0.0.1 --port "$port" --insecure
no test $? -eq 0
grep -q "<7 days" "$tmp/out" || { echo "FAIL: expiry <7d"; fails=$((fails + 1)); }
mkcert 20 "DNS:app.example.test"; serve
run "$tmp/hosts" --resolve 127.0.0.1 --port "$port" --insecure
ok test $? -eq 0
grep -q "WARN" "$tmp/out" || { echo "FAIL: expected WARN <30d"; fails=$((fails + 1)); }

if [[ $fails -ne 0 ]]; then echo "verify_test: $fails failure(s)"; exit 1; fi
echo "verify_test: ok"
