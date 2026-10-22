#!/bin/bash
# Live integration test for ft_nmap on loopback. Needs root.
#   sudo bash tests/test_live.sh            (from the project root)
# Needs: python3, iptables (optional: firewall cases are skipped without it),
#        setpriv (optional), valgrind (optional).
# It starts its own servers, adds temporary iptables rules, and always cleans up.

BIN=./ft_nmap
PASS=0; FAIL=0; SKIP=0
TMP=$(mktemp -d)
PIDS=(); RULES=()

# Ports used (all below 33000, our source-port range starts at 33000)
P_TCP_OPEN=18000; P_CLOSED=18001; P_TCP_DROP=18002; P_UDP_OPEN=18003
P_UDP_DROP=18004; P_UDP_REJECT=18005; P_TCP_REJECT=18006

ok()   { printf "  [ OK ] %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  [FAIL] %s\n" "$1"; [ -n "$2" ] && printf "%s\n" "$2" | sed 's/^/         | /'; FAIL=$((FAIL+1)); }
skip() { printf "  [SKIP] %s\n" "$1"; SKIP=$((SKIP+1)); }

cleanup() {
	for r in "${RULES[@]}"; do iptables -D INPUT $r 2>/dev/null; done
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
	rm -rf "$TMP"
}
trap cleanup EXIT

add_rule() { iptables -A INPUT $1 2>/dev/null && RULES+=("$1"); }

# row <file> <port> -> "SYN(Open) NULL(...) ..." for that port
# New format includes service name and conclusion; extract just the results
row() { awk -v p="$2" '$1==p {$1=""; $2=""; $(NF)=""; sub(/^ +/, ""); sub(/ +$/, ""); print}' "$1"; }

check_row() {   # check_row <file> <port> <expected> <label>
	local got; got=$(row "$1" "$2")
	if [ "$got" == "$3" ]; then ok "$4"; else bad "$4" "expected: $3
got:      $got"; fi
}

if [ "$(id -u)" -ne 0 ]; then
	echo "This test needs root (raw sockets + pcap). Run:  sudo bash tests/test_live.sh"; exit 2
fi
command -v python3 >/dev/null || { echo "python3 is required"; exit 2; }
make -s >/dev/null 2>&1 || { echo "build failed"; exit 2; }
HAVE_FW=0; command -v iptables >/dev/null && HAVE_FW=1

echo "== setup: servers and firewall rules =="
python3 - "$P_TCP_OPEN" << 'PY' &
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(64); time.sleep(900)
PY
PIDS+=($!)
python3 - "$P_UDP_OPEN" << 'PY' &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    _, addr = s.recvfrom(2048)
    s.sendto(b"hi", addr)
PY
PIDS+=($!)
sleep 0.7
if [ $HAVE_FW -eq 1 ]; then
	add_rule "-i lo -p tcp --dport $P_TCP_DROP -j DROP"
	add_rule "-i lo -p udp --dport $P_UDP_DROP -j DROP"
	add_rule "-i lo -p udp --dport $P_UDP_REJECT -j REJECT --reject-with icmp-admin-prohibited"
	add_rule "-i lo -p tcp --dport $P_TCP_REJECT -j REJECT --reject-with icmp-admin-prohibited"
	echo "  firewall rules added (${#RULES[@]})"
else
	echo "  iptables not found: firewall cases will be skipped"
fi

echo "== 1. full scan, all 6 scan types, 7 ports with known behaviour =="
PORTS="$P_TCP_OPEN-$P_TCP_REJECT"
S=$(date +%s)
timeout 200 $BIN --ip 127.0.0.1 --ports $PORTS > "$TMP/full.txt" 2>&1; RC=$?
echo "  (took $(( $(date +%s) - S )) s)"
[ $RC -eq 0 ] && ok "exit code 0" || bad "exit code is $RC (want 0)" "$(tail -3 "$TMP/full.txt")"
grep -q "^Scan took [0-9.]* secs" "$TMP/full.txt" && ok "scan duration printed" || bad "'Scan took' line missing" "$(cat "$TMP/full.txt")"
[ "$(grep -cE '^180[0-9][0-9]? ' "$TMP/full.txt")" -eq 7 ] && ok "7 result rows" || bad "expected 7 result rows" "$(cat "$TMP/full.txt")"

check_row "$TMP/full.txt" $P_TCP_OPEN  "SYN(Open) NULL(Open|Filtered) FIN(Open|Filtered) XMAS(Open|Filtered) ACK(Unfiltered) UDP(Closed)" \
	"TCP port listening: SYN Open, NULL/FIN/XMAS silent, ACK Unfiltered, UDP Closed"
check_row "$TMP/full.txt" $P_CLOSED    "SYN(Closed) NULL(Closed) FIN(Closed) XMAS(Closed) ACK(Unfiltered) UDP(Closed)" \
	"nothing listening: everything Closed, ACK Unfiltered"
check_row "$TMP/full.txt" $P_UDP_OPEN  "SYN(Closed) NULL(Closed) FIN(Closed) XMAS(Closed) ACK(Unfiltered) UDP(Open)" \
	"UDP service answering: UDP Open (real UDP reply)"
if [ $HAVE_FW -eq 1 ]; then
	check_row "$TMP/full.txt" $P_TCP_DROP "SYN(Filtered) NULL(Open|Filtered) FIN(Open|Filtered) XMAS(Open|Filtered) ACK(Filtered) UDP(Closed)" \
		"TCP DROP firewall: SYN/ACK Filtered, NULL/FIN/XMAS Open|Filtered"
	check_row "$TMP/full.txt" $P_UDP_DROP "SYN(Closed) NULL(Closed) FIN(Closed) XMAS(Closed) ACK(Unfiltered) UDP(Open|Filtered)" \
		"UDP DROP firewall: UDP Open|Filtered (silence)"
	check_row "$TMP/full.txt" $P_UDP_REJECT "SYN(Closed) NULL(Closed) FIN(Closed) XMAS(Closed) ACK(Unfiltered) UDP(Filtered)" \
		"UDP REJECT (ICMP code 13): UDP Filtered"
	check_row "$TMP/full.txt" $P_TCP_REJECT "SYN(Filtered) NULL(Filtered) FIN(Filtered) XMAS(Filtered) ACK(Filtered) UDP(Closed)" \
		"TCP REJECT (ICMP code 13): all TCP scans Filtered"
else
	for n in "TCP DROP" "UDP DROP" "UDP REJECT" "TCP REJECT"; do skip "$n firewall case (no iptables)"; done
fi

echo "== 2. output options =="
timeout 60 $BIN --ip 127.0.0.1 --ports $P_UDP_OPEN,$P_CLOSED --scan UDP/SYN > "$TMP/sub.txt" 2>&1
check_row "$TMP/sub.txt" $P_CLOSED   "SYN(Closed) UDP(Closed)" "--scan UDP/SYN: only those scans, printed SYN first"
check_row "$TMP/sub.txt" $P_UDP_OPEN "SYN(Closed) UDP(Open)"   "second port row correct"
[ "$(grep -E '^180' "$TMP/sub.txt" | awk '{print $1}' | tr '\n' ' ')" == "$P_CLOSED $P_UDP_OPEN " ] \
	&& ok "ports listed in ascending order even if given reversed" || bad "ports not sorted" "$(cat "$TMP/sub.txt")"
timeout 60 $BIN --ip localhost --ports $P_CLOSED --scan ack > "$TMP/host.txt" 2>&1
check_row "$TMP/host.txt" $P_CLOSED "ACK(Unfiltered)" "hostname 'localhost' + lowercase scan name work"

echo "== 3. packets on the wire (raw sniffer on lo) =="
if python3 tests/capture_check.py 6 $P_CLOSED > "$TMP/cap.txt" 2>&1 &
then
	CAP=$!
	for _ in $(seq 1 30); do grep -q READY "$TMP/cap.txt" && break; sleep 0.1; done
	timeout 60 $BIN --ip 127.0.0.1 --ports $P_CLOSED > /dev/null 2>&1
	wait $CAP
	if ! grep -q READY "$TMP/cap.txt"; then skip "sniffer could not start: $(head -2 "$TMP/cap.txt")"
	else
		for want in "TCP flags=SYN cksum=VALID" "TCP flags=none cksum=VALID" "TCP flags=FIN cksum=VALID" \
					"TCP flags=FIN+PSH+URG cksum=VALID" "TCP flags=ACK cksum=VALID" "UDP cksum=VALID"; do
			grep -qx "$want" "$TMP/cap.txt" && ok "probe sent: $want" || bad "probe NOT seen: $want" "$(cat "$TMP/cap.txt")"
		done
		grep -q "BAD" "$TMP/cap.txt" && bad "some probe has a BAD checksum" "$(grep BAD "$TMP/cap.txt")" || ok "no probe has a bad checksum"
	fi
fi

echo "== 4. threads (--speedup) =="
# results must not depend on the thread count; reference = the full scan above (speedup 0)
grep -E '^180' "$TMP/full.txt" > "$TMP/ref.txt"
for n in 1 7 70 250; do
	timeout 200 $BIN --ip 127.0.0.1 --ports $PORTS --speedup $n > "$TMP/t$n.txt" 2>&1; RC=$?
	if [ $RC -eq 0 ] && diff -q "$TMP/ref.txt" <(grep -E '^180' "$TMP/t$n.txt") >/dev/null; then
		ok "--speedup $n: same results as --speedup 0 ($(grep -o 'took [0-9.]*' "$TMP/t$n.txt") s)"
	else
		bad "--speedup $n: results differ or rc=$RC" "$(diff "$TMP/ref.txt" <(grep -E '^180' "$TMP/t$n.txt"); tail -3 "$TMP/t$n.txt")"
	fi
done
T0=$(grep -o 'took [0-9]*' "$TMP/full.txt" | grep -o '[0-9]*$'); T70=$(grep -o 'took [0-9]*' "$TMP/t70.txt" | grep -o '[0-9]*$')
[ -n "$T0" ] && [ -n "$T70" ] && [ $((T70 * 4)) -le "$T0" ] && ok "--speedup 70 is at least 4x faster (${T70}s vs ${T0}s)" \
	|| bad "--speedup 70 not faster enough (${T70}s vs ${T0}s)"
timeout 200 $BIN --file tests/ips.txt --ports $P_CLOSED --scan SYN --speedup 3 > "$TMP/file.txt" 2>&1
[ "$(grep -c '^Scan took' "$TMP/file.txt")" -eq 1 ] && check_row "$TMP/file.txt" $P_CLOSED "SYN(Closed)" "--file: valid target scanned, bad one skipped" \
	|| bad "--file scan" "$(cat "$TMP/file.txt")"

echo "== 5. error paths =="
if command -v setpriv >/dev/null; then
	timeout 30 setpriv --reuid=65534 --regid=65534 --clear-groups $BIN --ip 127.0.0.1 --ports 80 --scan SYN > "$TMP/nr.txt" 2>&1; RC=$?
	[ $RC -eq 255 ] && ok "non-root: exit code 255" || bad "non-root: exit code $RC (want 255)" "$(cat "$TMP/nr.txt")"
	grep -q "try sudo" "$TMP/nr.txt" && ok "non-root: clear 'try sudo' message" || bad "non-root: no sudo hint" "$(cat "$TMP/nr.txt")"
	grep -qiE "segmentation|core dumped" "$TMP/nr.txt" && bad "non-root: crash" || ok "non-root: no crash"
else
	skip "non-root run (setpriv missing)"
fi
FT_NMAP_PARSE_ONLY=1 timeout 30 $BIN --ip 127.0.0.1 --ports 80 > "$TMP/gate.txt" 2>&1; RC=$?
[ $RC -eq 0 ] && ! grep -q "Scanning" "$TMP/gate.txt" && ok "FT_NMAP_PARSE_ONLY: parsing only, no packet sent" || bad "parse-only hook broken" "$(cat "$TMP/gate.txt")"

echo "== 6. memory and races (valgrind) =="
if command -v valgrind >/dev/null; then
	timeout 150 valgrind -q --suppressions=tests/valgrind.supp --leak-check=full --show-leak-kinds=all --error-exitcode=99 \
		$BIN --ip 127.0.0.1 --ports $P_CLOSED,$P_UDP_OPEN --scan SYN/UDP --speedup 4 > "$TMP/vg.txt" 2>&1; RC=$?
	if [ $RC -eq 99 ] || grep -qE "definitely lost|Invalid (read|write)|uninitialised" "$TMP/vg.txt"; then
		bad "valgrind reports errors or leaks" "$(grep -vE '^(Scan|Target|No of|Scans|Scanning|180)' "$TMP/vg.txt" | head -20)"
	else ok "valgrind: no leaks, no invalid access"; fi
	timeout 150 valgrind -q --tool=helgrind --error-exitcode=99 \
		$BIN --ip 127.0.0.1 --ports $P_TCP_OPEN-$P_UDP_OPEN --scan SYN/ACK/UDP --speedup 4 > "$TMP/hg.txt" 2>&1; RC=$?
	[ $RC -ne 99 ] && ! grep -q "Possible data race" "$TMP/hg.txt" && ok "helgrind: no data race with 4 threads" \
		|| bad "helgrind reports problems" "$(grep -vE '^(Scan|Target|No of|Scans|180)' "$TMP/hg.txt" | head -30)"
else
	skip "valgrind not installed"
fi
timeout 30 valgrind -q --leak-check=full --error-exitcode=99 $BIN --file tests/ips.txt --ports 1-20 > "$TMP/vg2.txt" 2>&1; RC=$?
[ $RC -eq 0 ] && ok "valgrind: parsing a target file leaks nothing" || bad "valgrind on parsing (rc=$RC)" "$(head -15 "$TMP/vg2.txt")"

echo
echo "Result: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
