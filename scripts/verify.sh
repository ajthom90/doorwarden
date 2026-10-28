#!/usr/bin/env bash
# verify.sh - post-cutover verification for Doorwarden/Traefik.
#
# Usage: verify.sh HOSTLIST [--resolve IP] [--port N] [--cacert FILE] [--insecure]
#
# HOSTLIST has one hostname per line; blank lines and '#' comments are ignored.
# IP defaults to $VERIFY_IP (required one way or the other); port to
# $VERIFY_PORT or 443 (use e.g. 8443 for the pre-cutover alternate-port run).
# --insecure skips chain verification in curl only (useful with the staging
# issuer); SAN and expiry are still checked from the served certificate.
#
# Per host it checks: HTTP status (<500; 401/403 are acceptable and flagged
# "auth"), the issuer (flags STAGING / Fake LE), that the served certificate's
# SAN list covers the hostname (exact, or "*.zone" matching exactly one label)
# and days until expiry (fail < 7, warn < 30). Exit status is non-zero if any
# host fails. Requires bash, curl and openssl.

set -u

HOST_RE='^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'
IP_RE='^[0-9A-Fa-f:.]+$'

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# san_match HOST SANLIST - SANLIST is the "DNS:a, DNS:*.b" text from openssl.
# Succeeds if HOST is covered. A wildcard covers exactly one label.
san_match() {
	local host list="$2" item pat suffix label
	host="$(lower "$1")"
	local IFS=','
	for item in $list; do
		item="${item#"${item%%[![:space:]]*}"}"
		item="${item%"${item##*[![:space:]]}"}"
		case "$item" in DNS:*) ;; *) continue ;; esac
		pat="${item#DNS:}"
		pat="$(lower "$pat")"
		if [[ "$pat" == "$host" ]]; then return 0; fi
		if [[ "$pat" == '*.'* ]]; then
			suffix="${pat#\*}" # ".zone"
			if [[ "$host" == *"$suffix" ]]; then
				label="${host%"$suffix"}"
				if [[ -n "$label" && "$label" != *.* ]]; then return 0; fi
			fi
		fi
	done
	return 1
}

# status_class CODE - prints "2xx" "3xx" "4xx" "auth" "5xx" or "none"; "auth"
# is 401/403. Returns non-zero for 5xx and "none" (no HTTP response).
status_class() {
	case "$1" in
	401 | 403) echo auth ;;
	2??) echo 2xx ;;
	3??) echo 3xx ;;
	4??) echo 4xx ;;
	5??) echo 5xx; return 1 ;;
	*) echo none; return 1 ;;
	esac
}

# issuer_flag ISSUER - prints STAGING or ok.
issuer_flag() {
	case "$1" in
	*"(STAGING)"* | *"Fake LE"*) echo STAGING ;;
	*) echo ok ;;
	esac
}

# expiry_state SECONDS_LEFT_OK7 SECONDS_LEFT_OK30 - maps -checkend results
# (0 = still valid at that horizon) to fail|warn|ok.
expiry_state() {
	if [[ "$1" != 0 ]]; then echo fail; elif [[ "$2" != 0 ]]; then echo warn; else echo ok; fi
}

days_left() { # days_left CERTFILE -> integer or "?"
	local end now e
	end="$(openssl x509 -in "$1" -noout -enddate 2>/dev/null)" || { echo '?'; return; }
	end="${end#notAfter=}"
	now="$(date -u +%s)"
	e="$(date -u -d "$end" +%s 2>/dev/null || date -u -j -f '%b %e %T %Y %Z' "$end" +%s 2>/dev/null)" || true
	if [[ -z "${e:-}" ]]; then echo '?'; else echo $(((e - now) / 86400)); fi
}

main() {
	local list="" ip="${VERIFY_IP:-}" port="${VERIFY_PORT:-443}" cacert="" insecure=0
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--resolve) ip="${2:-}"; shift 2 ;;
		--port) port="${2:-}"; shift 2 ;;
		--cacert) cacert="${2:-}"; shift 2 ;;
		--insecure) insecure=1; shift ;;
		-h | --help) sed -n '2,16p' "$0"; return 0 ;;
		-*) echo "verify: unknown option $1" >&2; return 2 ;;
		*) list="$1"; shift ;;
		esac
	done
	if [[ -z "$list" || ! -r "$list" ]]; then echo "verify: HOSTLIST file required and readable" >&2; return 2; fi
	if [[ -z "$ip" || ! "$ip" =~ $IP_RE ]]; then echo "verify: --resolve IP (or VERIFY_IP) required, and must be an IP address" >&2; return 2; fi
	if [[ ! "$port" =~ ^[0-9]{1,5}$ ]]; then echo "verify: invalid port" >&2; return 2; fi
	command -v curl >/dev/null || { echo "verify: curl not found" >&2; return 2; }
	command -v openssl >/dev/null || { echo "verify: openssl not found" >&2; return 2; }

	local tmp rc=0
	tmp="$(mktemp -d)" || return 2
	trap 'rm -rf "$tmp"' RETURN

	local connect="$ip:$port"
	[[ "$ip" == *:* ]] && connect="[$ip]:$port"
	local to=()
	command -v timeout >/dev/null && to=(timeout 20)

	local rows=() line host
	while IFS= read -r line || [[ -n "$line" ]]; do
		line="${line%%#*}"
		line="${line#"${line%%[![:space:]]*}"}"
		line="${line%"${line##*[![:space:]]}"}"
		[[ -z "$line" ]] && continue
		host="$line"
		if [[ ! "$host" =~ $HOST_RE ]]; then
			rows+=("$(printf '%s|-|-|-|-|-|FAIL (invalid hostname)' "${host//[^[:print:]]/?}")")
			rc=1
			continue
		fi
		local url="https://$host/"
		[[ "$port" != 443 ]] && url="https://$host:$port/"
		local copts=(-sS -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15 --resolve "$host:$port:$ip")
		[[ -n "$cacert" ]] && copts+=(--cacert "$cacert")
		[[ "$insecure" == 1 ]] && copts+=(-k)
		local code cerr
		code="$(curl "${copts[@]}" "$url" 2>"$tmp/curl.err")" || true
		cerr="$(head -c 200 "$tmp/curl.err" | tr '\n' ' ')"

		local result="ok" notes=() cls sclass
		cls="$(status_class "$code")" || { result=FAIL; notes+=("http $code ${cerr}"); }
		sclass="$cls"
		[[ "$cls" == auth ]] && notes+=("auth ($code)")

		local cert="$tmp/cert.pem" issuer="-" san="" dl="?" iflag="-" sanok="no"
		${to[@]+"${to[@]}"} openssl s_client -servername "$host" -connect "$connect" </dev/null 2>/dev/null |
			openssl x509 -out "$cert" 2>/dev/null
		if [[ -s "$cert" ]]; then
			issuer="$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null | sed 's/^issuer= *//')"
			san="$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | grep -E 'DNS:' | tr -d '\n')"
			iflag="$(issuer_flag "$issuer")"
			[[ "$iflag" == STAGING ]] && notes+=("STAGING issuer")
			if san_match "$host" "$san"; then sanok=yes; else result=FAIL; notes+=("SAN does not cover host"); fi
			dl="$(days_left "$cert")"
			local c7=0 c30=0
			openssl x509 -in "$cert" -noout -checkend $((7 * 86400)) >/dev/null 2>&1 || c7=1
			openssl x509 -in "$cert" -noout -checkend $((30 * 86400)) >/dev/null 2>&1 || c30=1
			case "$(expiry_state "$c7" "$c30")" in
			fail) result=FAIL; notes+=("expires in <7 days") ;;
			warn) [[ "$result" == ok ]] && result=WARN; notes+=("expires in <30 days") ;;
			esac
		else
			result=FAIL
			notes+=("no certificate served")
		fi
		[[ "$iflag" == STAGING && "$result" == ok ]] && result=WARN
		[[ "$result" == FAIL ]] && rc=1
		rows+=("$(printf '%s|%s|%s|%s|%s|%s|%s %s' "$host" "$code" "$sclass" "$iflag" "$sanok" "$dl" "$result" "${notes[*]-}")")
		echo "== $host" >&2
		echo "   issuer: $issuer" >&2
	done <"$list"

	{
		echo "HOST|HTTP|CLASS|ISSUER|SAN|DAYS|RESULT"
		printf '%s\n' ${rows[@]+"${rows[@]}"}
	} | column -t -s'|' 2>/dev/null || printf '%s\n' ${rows[@]+"${rows[@]}"}
	if [[ $rc -ne 0 ]]; then echo "verify: FAILED" >&2; else echo "verify: all hosts passed"; fi
	return $rc
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; exit $?; fi
