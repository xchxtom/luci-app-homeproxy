#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022-2023 ImmortalWrt.org
#
# Node fail-over for homeproxy.
#
# When the main node becomes unreachable, sing-box is still running and still
# listening on the DNS / mixed / redirect ports, but every DNS query handed to
# it has to wait for a dead upstream connection.  dnsmasq is configured with
# "no-resolv" and a single upstream, so the whole LAN loses name resolution -
# including for domains that are supposed to be resolved and routed directly.
# Traffic hijacked by nftables ends up in the same black hole.
#
# This watchdog probes the node through the local mixed inbound (which is not
# affected by the fail-over itself) and, after a few consecutive failures,
# temporarily removes the DNS hijack and the transparent proxy rules so that
# everything falls back to plain direct routing.  As soon as the node answers
# again the original rules are restored automatically.
#
# Usage: failover.sh [restore|status]

CONF="homeproxy"
HP_DIR="/etc/homeproxy"
RUN_DIR="/var/run/homeproxy"
DNSMASQ_DIR="/tmp/dnsmasq.d/dnsmasq-homeproxy.d"
LOG_PATH="$RUN_DIR/homeproxy.log"

STATE_FILE="$RUN_DIR/failover.state"
BACKUP_DIR="$RUN_DIR/failover-dnsmasq"
LOCK_DIR="$RUN_DIR/failover.lock"

log() {
	echo -e "$(date "+%Y-%m-%d %H:%M:%S") [FAILOVER] $*" >> "$LOG_PATH"
}

uci_get() {
	local value
	value="$(/sbin/uci -q get "$CONF.$1.$2" 2>/dev/null)"
	if [ -n "$value" ]; then
		echo "$value"
	else
		echo "$3"
	fi
}

is_uint() {
	case "$1" in
	''|*[!0-9]*) return 1 ;;
	esac
	[ "$1" -ge 1 ] 2>/dev/null
}

FAILOVER="$(uci_get config failover 1)"
INTERVAL="$(uci_get config failover_interval 5)"
THRESHOLD="$(uci_get config failover_threshold 3)"
RECOVER_COUNT="$(uci_get config failover_recover 2)"
TIMEOUT="$(uci_get config failover_timeout 3)"
PROBE_URL="$(uci_get config failover_probe_url 'http://www.gstatic.com/generate_204')"
MIXED_PORT="$(uci_get infra mixed_port 5330)"

is_uint "$INTERVAL" || INTERVAL=5
is_uint "$THRESHOLD" || THRESHOLD=3
is_uint "$RECOVER_COUNT" || RECOVER_COUNT=2
is_uint "$TIMEOUT" || TIMEOUT=3
is_uint "$MIXED_PORT" || MIXED_PORT=5330
# Only plain HTTP can be tunnelled through a mixed inbound with a simple
# absolute-form GET; silently downgrade a https:// URL configured by the user.
case "$PROBE_URL" in
https://*) PROBE_URL="http://${PROBE_URL#https://}" ;;
esac
case "$PROBE_URL" in
http://?*) ;;
*) PROBE_URL='http://www.gstatic.com/generate_204' ;;
esac

# Probe through the local mixed inbound.  A 2xx/3xx response means sing-box
# was able to establish a connection through the main node.  nc is part of the
# default BusyBox applet set; curl / wget are used as fallbacks.
probe_nc() {
	local rest hostport
	rest="${PROBE_URL#http://}"
	hostport="${rest%%/*}"

	printf 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' \
		"$PROBE_URL" "$hostport" |
		nc -w "$TIMEOUT" 127.0.0.1 "$MIXED_PORT" 2>/dev/null |
		head -c 256 | grep -qE '^HTTP/1\.[01] [23][0-9][0-9]'
}

probe_curl() {
	local code
	code="$(curl -s -m "$TIMEOUT" -x "http://127.0.0.1:$MIXED_PORT" \
		-o /dev/null -w '%{http_code}' "$PROBE_URL" 2>/dev/null)"
	case "$code" in
	2??|3??) return 0 ;;
	*) return 1 ;;
	esac
}

probe_wget() {
	http_proxy="http://127.0.0.1:$MIXED_PORT" \
		/usr/bin/wget --spider -q -T "$TIMEOUT" "$PROBE_URL" >/dev/null 2>&1
}

if command -v nc >/dev/null 2>&1; then
	PROBE=probe_nc
elif command -v curl >/dev/null 2>&1; then
	PROBE=probe_curl
elif [ -x /usr/bin/wget ]; then
	PROBE=probe_wget
else
	# Stay alive so procd does not enter a respawn loop. Without a probe we
	# never touch the rules, so direct traffic keeps working as usual.
	log "No usable probe tool (nc/curl/wget), fail-over disabled."
	while :; do sleep 300; done
fi

# ---------------------------------------------------------------------------
# Degraded mode: drop the DNS hijack and all transparent proxy rules.
# ---------------------------------------------------------------------------
degrade() {
	[ -f "$STATE_FILE" ] && return 0

	log "Main node is unreachable, falling back to direct connection."

	mkdir -p "$DNSMASQ_DIR"
	rm -rf "$BACKUP_DIR"
	mkdir -p "$BACKUP_DIR"
	cp -a "$DNSMASQ_DIR"/. "$BACKUP_DIR"/ 2>/dev/null
	# Removing the generated files also removes "no-resolv"/"no-poll", so
	# dnsmasq falls back to the system (WAN) resolvers again.
	rm -f "$DNSMASQ_DIR"/*.conf

	# Restart dnsmasq first: the removed .conf files also contain "nftset="
	# references to the homeproxy sets, which must be gone before fw4 drops
	# those sets.  An empty table-post include then makes fw4 rebuild the
	# ruleset without any homeproxy chain/set, so every packet is direct.
	/etc/init.d/dnsmasq restart >/dev/null 2>&1
	echo > "$RUN_DIR/fw4_post.nft"
	fw4 reload >/dev/null 2>&1

	echo degraded > "$STATE_FILE"
	log "Direct-connection fallback is active; waiting for the node to recover."
}

# ---------------------------------------------------------------------------
# Recovery: put back exactly the rules that the init script generated.
# ---------------------------------------------------------------------------
recover() {
	[ -f "$STATE_FILE" ] || return 0

	log "Main node recovered, restoring homeproxy rules."

	mkdir -p "$DNSMASQ_DIR"
	[ -d "$BACKUP_DIR" ] && cp -a "$BACKUP_DIR"/. "$DNSMASQ_DIR"/ 2>/dev/null

	# Rebuild the firewall rules before dnsmasq, because the restored config
	# references the homeproxy nft sets which have to exist at startup.
	utpl -S "$HP_DIR/scripts/firewall_post.ut" > "$RUN_DIR/fw4_post.nft"
	if [ ! -s "$RUN_DIR/fw4_post.nft" ]; then
		log "Failed to rebuild firewall rules, staying in direct mode."
		return 1
	fi
	fw4 reload >/dev/null 2>&1
	/etc/init.d/dnsmasq restart >/dev/null 2>&1

	rm -f "$STATE_FILE"
	rm -rf "$BACKUP_DIR"
	log "Proxy rules restored."
}

case "${1:-}" in
restore)
	recover
	exit 0
	;;
status)
	if [ -f "$STATE_FILE" ]; then
		echo "degraded"
	else
		echo "normal"
	fi
	exit 0
	;;
esac

[ "$FAILOVER" = "1" ] || exit 0

mkdir -p "$RUN_DIR"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
	log "Another fail-over instance is already running."
	exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT
trap 'rmdir "$LOCK_DIR" 2>/dev/null; exit 0' INT TERM

log "Watchdog started (probe=$PROBE interval=${INTERVAL}s threshold=$THRESHOLD recover=$RECOVER_COUNT)."

fails=0
oks=0
while :; do
	if $PROBE; then
		oks=$((oks + 1))
		fails=0
		if [ "$oks" -ge "$RECOVER_COUNT" ] && [ -f "$STATE_FILE" ]; then
			recover
			oks=0
		fi
	else
		fails=$((fails + 1))
		oks=0
		if [ "$fails" -ge "$THRESHOLD" ] && [ ! -f "$STATE_FILE" ]; then
			degrade
			fails=0
		fi
	fi
	sleep "$INTERVAL"
done
