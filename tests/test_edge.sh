#!/bin/bash
# Non-root edge-case tests for ft_nmap. Run from the project root.
BIN=./ft_nmap
export FT_NMAP_PARSE_ONLY=1
PASS=0; FAIL=0
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

t() {
	local name="$1" rc_exp="$2" pat="$3"; shift 3
	local out rc
	out=$("$BIN" "$@" 2>&1); rc=$?
	if [ "$rc" -eq "$rc_exp" ] && { [ -z "$pat" ] || echo "$out" | grep -qE "$pat"; }; then
		printf "  [ OK ] %s\n" "$name"; PASS=$((PASS+1))
	else
		printf "  [FAIL] %s (rc=%s, expected %s, pattern '%s')\n" "$name" "$rc" "$rc_exp" "$pat"
		echo "$out" | sed 's/^/         | /'; FAIL=$((FAIL+1))
	fi
}

echo "== duplicate and missing options =="
t "duplicate --ip"        255 "specified more than once" --ip 127.0.0.1 --ip localhost
t "duplicate --file"      255 "specified more than once" --file tests/ips.txt --file tests/ips.txt
t "duplicate --ports"     255 "specified more than once" --ip 127.0.0.1 --ports 80 --port 81
t "duplicate --speedup"   255 "specified more than once" --ip 127.0.0.1 --speedup 1 --speedup 2
t "duplicate --scan"      255 "specified more than once" --ip 127.0.0.1 --scan SYN --scan UDP
t "missing --ip value"    255 "requires an argument" --ip
t "missing --file value"  255 "requires an argument" --file
t "missing --scan value"  255 "requires an argument" --scan
t "missing --speedup value" 255 "requires an argument" --speedup
t "missing --ports value" 255 "requires an argument" --ports
t "ip and file together"  255 "same time" --ip 127.0.0.1 --file tests/ips.txt
t "option after target"    0 "No of threads : 3" --ip 127.0.0.1 --speedup 3
t "long option equals form" 0 "Ports to scan : 1$" --ip=127.0.0.1 --ports=80
t "short options combined"  0 "performed : UDP" -i 127.0.0.1 -p 53 -s 0 -S UDP
t "double dash positional" 255 "unexpected argument" --ip 127.0.0.1 -- --ports 80

echo "== boundaries and malformed values =="
t "speedup lower bound"   0 "No of threads : 0" --ip 127.0.0.1 --speedup 0
t "speedup upper bound"   0 "No of threads : 250" --ip 127.0.0.1 --speedup 250
t "port lower bound"      0 "Ports to scan : 1$" --ip 127.0.0.1 --ports 1
t "port upper bound"      0 "Ports to scan : 1$" --ip 127.0.0.1 --ports 65535
t "whitespace port"       255 "invalid port" --ip 127.0.0.1 --ports "80, 81"
t "leading comma"         255 "invalid port" --ip 127.0.0.1 --ports ",80"
t "trailing comma"        255 "invalid port" --ip 127.0.0.1 --ports "80,"
t "three-part range"      255 "invalid port" --ip 127.0.0.1 --ports 1-2-3
t "empty ip"              255 "no valid target" --ip ""
t "empty file path"       255 "cannot open|no valid target" --file ""
t "plus sign speedup"      255 "between 0 and 250" --ip 127.0.0.1 --speedup +1
t "leading zero speedup"   0 "No of threads : 7" --ip 127.0.0.1 --speedup 007
t "leading zero port"      0 "Ports to scan : 1$" --ip 127.0.0.1 --ports 00080
t "range with zero start"  255 "invalid port" --ip 127.0.0.1 --ports 0-10
t "range with high end"    255 "invalid port" --ip 127.0.0.1 --ports 65530-65536
t "overlapping ranges"     0 "Ports to scan : 7$" --ip 127.0.0.1 --ports 1-5,3-7
t "mixed separators scans" 0 "performed : SYN FIN UDP$" --ip 127.0.0.1 --scan "syn, FIN/udp"
t "space-separated scans"  0 "performed : SYN FIN UDP$" --ip 127.0.0.1 --scan "SYN FIN UDP"
t "duplicate scan in value" 0 "performed : SYN$" --ip 127.0.0.1 --scan SYN/SYN
t "scan separator only"    255 "empty scan type" --ip 127.0.0.1 --scan "/,"

echo "== target-file edge cases =="
printf '   # indented comment\n\n   127.0.0.1   \n' > "$TMP/comments.txt"
printf '%*s\n127.0.0.1\n' 4096 '' > "$TMP/long.txt"
printf 'bad..host\n' > "$TMP/bad.txt"
printf '127.0.0.1\r\nlocalhost\r\n' > "$TMP/crlf.txt"
printf '127.0.0.1' > "$TMP/no-newline.txt"
printf '127.0.0.1\n127.0.0.1\nlocalhost\n' > "$TMP/duplicates.txt"
printf '# comment\n   # another comment\n\n' > "$TMP/comments-only.txt"
printf '127.0.0.1\n' > "$TMP/one.txt"
t "indented comments and spaces" 0 "Target Ip-Address : 127.0.0.1" --file "$TMP/comments.txt"
t "long line does not crash"     0 "Target Ip-Address : 127.0.0.1" --file "$TMP/long.txt"
t "all invalid targets"          255 "no valid target" --file "$TMP/bad.txt"
t "CRLF target file"             0 "localhost" --file "$TMP/crlf.txt"
t "file without final newline"   0 "Target Ip-Address : 127.0.0.1" --file "$TMP/no-newline.txt"
t "duplicate targets are safe"   0 "Target Ip-Address : 127.0.0.1" --file "$TMP/duplicates.txt"
t "comments-only file"           255 "no valid target" --file "$TMP/comments-only.txt"
t "directory target rejected"    255 "cannot open|error reading|no valid target" --file "$TMP"
t "file with explicit scan"      0 "performed : ACK$" --file "$TMP/one.txt" --scan ACK
t "parse-only sends no packets"  0 "No of Ports to scan : 1" --ip 127.0.0.1 --ports 80

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
