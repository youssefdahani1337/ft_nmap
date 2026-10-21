#!/bin/bash
# Parsing tests for ft_nmap. Run from the project root: bash tests/test_parse.sh
BIN=./ft_nmap
# only check the parsing: no packet sent, no root needed
export FT_NMAP_PARSE_ONLY=1
PASS=0; FAIL=0
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# t "name" EXPECTED_RC "regex expected in stdout+stderr (or empty)" args...
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

echo "== help / missing args =="
t "--help"                    0 "Help Screen"                 --help
t "no arguments"              255 "you must give --ip or --file"
t "no target, only ports"     255 "you must give --ip or --file" --ports 80
t "--ip and --file together"  255 "cannot be used at the same time"     --ip 127.0.0.1 --file /dev/null

echo "== defaults =="
t "default ports = 1024"      0 "No of Ports to scan : 1024"  --ip 127.0.0.1
t "default threads = 0"       0 "No of threads : 0"           --ip 127.0.0.1
t "default scans = all"       0 "SYN NULL FIN XMAS ACK UDP"   --ip 127.0.0.1

echo "== ports =="
t "single port"               0 "Ports to scan : 1$"          --ip 127.0.0.1 --ports 80
t "--port alias"              0 "Ports to scan : 1$"          --ip 127.0.0.1 --port 80
t "list 1,2,3"                0 "Ports to scan : 3$"          --ip 127.0.0.1 --ports 1,2,3
t "range 70-90 (21 ports)"    0 "Ports to scan : 21$"         --ip 127.0.0.1 --ports 70-90
t "mix 1,5-15"                0 "Ports to scan : 12$"         --ip 127.0.0.1 --ports 1,5-15
t "duplicates 1-5,3-7"        0 "Ports to scan : 7$"          --ip 127.0.0.1 --ports 1-5,3-7
t "same port twice 80,80"     0 "Ports to scan : 1$"          --ip 127.0.0.1 --ports 80,80
t "port 65535"                0 "Ports to scan : 1$"          --ip 127.0.0.1 --ports 65535
t "exactly 1024 ports"        0 "Ports to scan : 1024$"       --ip 127.0.0.1 --ports 1-1024
t "1024 ports, high range"    0 "Ports to scan : 1024$"       --ip 127.0.0.1 --ports 60000-61023
t "1025 ports"                255 "too many ports"              --ip 127.0.0.1 --ports 1-1025
t "huge range"                255 "too many ports"              --ip 127.0.0.1 --ports 1-65535
t "port 0"                    255 "invalid port"                --ip 127.0.0.1 --ports 0
t "port 65536"                255 "invalid port"                --ip 127.0.0.1 --ports 65536
t "reversed range 10-1"       255 "invalid port"                --ip 127.0.0.1 --ports 10-1
t "letters"                   255 "invalid port"                --ip 127.0.0.1 --ports abc
t "negative"                  255 "invalid port"                --ip 127.0.0.1 --ports -5
t "open range 1-"             255 "invalid port"                --ip 127.0.0.1 --ports 1-
t "open range -5"             255 "invalid port"                --ip 127.0.0.1 --ports -5
t "empty string"              255 "invalid port"                --ip 127.0.0.1 --ports ""
t "only commas"               255 "invalid port"                --ip 127.0.0.1 --ports ,,,
t "trailing garbage 80x"      255 "invalid port"                --ip 127.0.0.1 --ports 80x
t "double dash 1--5"          255 "invalid port"                --ip 127.0.0.1 --ports 1--5
t "overflow number"           255 "invalid port"                --ip 127.0.0.1 --ports 99999999999999999999
t "missing value"             255 "requires an argument"        --ip 127.0.0.1 --ports

echo "== speedup =="
t "speedup 0"                 0 "No of threads : 0"           --ip 127.0.0.1 --speedup 0
t "speedup 70"                0 "No of threads : 70"          --ip 127.0.0.1 --speedup 70
t "speedup 250 (max)"         0 "No of threads : 250"         --ip 127.0.0.1 --speedup 250
t "speedup 251"               255 "between 0 and 250"           --ip 127.0.0.1 --speedup 251
t "speedup -1"                255 "between 0 and 250"           --ip 127.0.0.1 --speedup -1
t "speedup abc"               255 "between 0 and 250"           --ip 127.0.0.1 --speedup abc
t "speedup 5x"                255 "between 0 and 250"           --ip 127.0.0.1 --speedup 5x
t "speedup empty"             255 "between 0 and 250"           --ip 127.0.0.1 --speedup ""

echo "== scan types =="
t "SYN only"                  0 "performed : SYN$"            --ip 127.0.0.1 --scan SYN
t "NULL only"                 0 "performed : NULL$"           --ip 127.0.0.1 --scan NULL
t "ACK only"                  0 "performed : ACK$"            --ip 127.0.0.1 --scan ACK
t "FIN only"                  0 "performed : FIN$"            --ip 127.0.0.1 --scan FIN
t "XMAS only"                 0 "performed : XMAS$"           --ip 127.0.0.1 --scan XMAS
t "UDP only"                  0 "performed : UDP$"            --ip 127.0.0.1 --scan UDP
t "lowercase"                 0 "performed : SYN$"            --ip 127.0.0.1 --scan syn
t "combo with /"              0 "performed : SYN UDP$"        --ip 127.0.0.1 --scan SYN/UDP
t "combo with ,"              0 "performed : SYN FIN XMAS$"   --ip 127.0.0.1 --scan syn,fin,xmas
t "all six explicit"          0 "SYN NULL FIN XMAS ACK UDP"   --ip 127.0.0.1 --scan SYN/NULL/FIN/XMAS/ACK/UDP
t "duplicate scan SYN/SYN"    0 "performed : SYN$"            --ip 127.0.0.1 --scan SYN/SYN
t "unknown scan"              255 "unknown scan type"           --ip 127.0.0.1 --scan FOO
t "valid + unknown"           255 "unknown scan type"           --ip 127.0.0.1 --scan SYN/FOO
t "empty scan"                255 "empty scan type|unknown"     --ip 127.0.0.1 --scan ""
t "only separators"           255 "empty scan type"             --ip 127.0.0.1 --scan "//"

echo "== --ip =="
t "IPv4"                      0 "Target Ip-Address : 1.2.3.4" --ip 1.2.3.4
t "localhost hostname"        0 "127.0.0.1 \(localhost\)"     --ip localhost
t "invalid IP"                255 "no valid target"             --ip 999.1.1.1
t "garbage hostname"          255 "no valid target"             --ip bad..host
t "IPv6 rejected"             255 "no valid target"             --ip ::1

echo "== --file =="
printf '127.0.0.1\n# comment\n\n   localhost   \n' > "$TMP/ok.txt"
printf '127.0.0.1\nbad..host\n8.8.8.8\n'            > "$TMP/mixed.txt"
printf 'bad..host\n999.9.9.9\n'                     > "$TMP/allbad.txt"
: > "$TMP/empty.txt"
printf '# only comments\n\n\n'                      > "$TMP/comments.txt"
printf '127.0.0.1'                                  > "$TMP/nonewline.txt"
printf '127.0.0.1\r\nlocalhost\r\n'                 > "$TMP/crlf.txt"
t "ips.txt: 1 good + 1 wrong"  0 "Target Ip-Address : 127.0.0.1" --file tests/ips.txt
t "ips.txt: wrong IP warned"  0 "cannot resolve '999.999.1.1'" --file tests/ips.txt
t "valid file (2 targets)"    0 "\(localhost\)"               --file "$TMP/ok.txt"
t "mixed file keeps valid"    0 "warning: cannot resolve 'bad..host'" --file "$TMP/mixed.txt"
t "all-bad file"              255 "no valid target"             --file "$TMP/allbad.txt"
t "empty file"                255 "no valid target"             --file "$TMP/empty.txt"
t "comments-only file"        255 "no valid target"             --file "$TMP/comments.txt"
t "no trailing newline"       0 "Target Ip-Address : 127.0.0.1" --file "$TMP/nonewline.txt"
t "CRLF line endings"         0 "\(localhost\)"               --file "$TMP/crlf.txt"
t "missing file"              255 "cannot open"                 --file "$TMP/nope.txt"
t "directory as file"         255 ""                            --file "$TMP"

echo "== misc =="
t "unknown option"            255 "unrecognized option"         --ip 127.0.0.1 --bogus
t "short -p accepted"        0 "Ports to scan : 1$"          -p 80 --ip 127.0.0.1
t "short -s -S accepted"      0 "performed : UDP"            -s 5 -S udp -i 127.0.0.1
t "unknown short option"      255 "invalid option"            -z --ip 127.0.0.1
t "extra positional arg"      255 "unexpected argument"         --ip 127.0.0.1 extra
t "abbrev --spee"             0 "No of threads : 9"           --ip 127.0.0.1 --spee 9
# --ports and --port share the same value, so glibc does NOT treat --p as ambiguous
t "abbrev --p (ports/port)"   0 "Ports to scan : 1$"          --ip 127.0.0.1 --p 80
t "abbrev --s is ambiguous"   255 "ambiguous"                   --ip 127.0.0.1 --s 80
t "option order independent"  0 "No of threads : 5"           --speedup 5 --scan UDP --ports 22 --ip 127.0.0.1
t "--help before bad option"  0 "Help Screen"                 --help --speedup 999
t "bad option before --help"  255 "between 0 and 250"           --speedup 999 --help

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
