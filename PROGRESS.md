# ft_nmap: progress and handoff notes

Last updated: 2026-10-21

Sources: the full claude.ai conversation, which the user pasted in, and an
analysis of the code in this repository plus a test run.

---

## 1. Subject summary (what is graded)

- **Language and build:** C with a Makefile (`all clean fclean re`, no needless relinking). Only libc, `-lpcap` and `-lpthread` are allowed (other libraries only for bonuses, with a justification). Calling the real nmap is forbidden. Work in a Linux VM with a kernel newer than 3.14. Only the git repository content is graded.
- **No crashes ever** (segfault, bus error, double free). Handle every error.
- **Options**
  - `--help`
  - `--ip <IPv4|hostname>` or `--file <file>` (one target per line)
  - `--ports`, plus the alias `--port`, because the subject's example uses `--port`. Accepts `80`, `1,2,3`, `1-10` or `1,5-15`. Default 1-1024, at most 1024 ports.
  - `--speedup N` with N from 0 to 250 (default 0)
  - `--scan`: any combination of SYN, NULL, ACK, FIN, XMAS, UDP. Default is all six.
- **Service name** for each port, e.g. http (the version isn't needed).
- **Expected output:**
  ```
  Scan Configurations
  Target Ip-Address : x.x.x.x
  No of Ports to scan : N
  Scans to be performed : SYN NULL ...
  No of threads : N
  Scanning..
  ........
  Scan took X secs
  IP address: x.x.x.x
  Open ports:
  Port Service Name (if applicable) Results                        Conclusion
  ----------------------------------------------------------------------------
  80   http                         SYN(Open) NULL(Open|Filtered) ... Open

  Closed/Filtered/Unfiltered ports:
  Port Service Name (if applicable) Results                        Conclusion
  ----------------------------------------------------------------------------
  ...
  ```
  The Conclusion is Open, Closed or Filtered.
- **Bonus**, only once the mandatory part is perfect: version or DNS detection, OS detection (TTL and window fingerprint), IDS or firewall evasion, decoy or spoofed source, extra flags. `-v` and `-V` don't count.

## 2. Roadmap (13 steps, agreed in the conversation)

| # | Step | Status |
|---|---|---|
| 1 | Setup: VM, libpcap-dev, Makefile, `includes/` and `srcs/` | ✅ |
| 2 | Argument parsing with `getopt_long` | ✅ (82 tests) |
| 3 | Packet basics: raw sockets, headers, checksums, source IP | ✅ |
| 4 | TCP flags for each scan | ✅ |
| 5 | Reply interpretation table | ✅ |
| 6 | pcap capture: filter, link header, matching, timeouts | ✅ |
| 7 | `scan_port()` for one port, without threads | ✅ |
| — | Big live test suite (`test_live.sh`) | ✅ |
| 8 | Threading (`--speedup`) | ✅ 2026-10-21 (see §6) |
| 9 | Service names (`getservbyport`) | ✅ 2026-10-22 |
| 10 | Conclusion, timing and the two output tables | ✅ 2026-10-22 |
| 11 | Robustness review: every return value, frees, non-root | ⬜ (partly done) |
| 12 | Full test campaign (thread counts, valgrind, helgrind) | ⬜ |
| 13 | Bonus | ⬜ |

## 3. Code architecture (current files)

| File | Role |
|---|---|
| `includes/ft_nmap.h` | All system includes plus `_GNU_SOURCE`. Holds `t_nmap` (config), `t_target {name, addr}`, `t_scan_type` bit flags (`SCAN_SYN=1<<0, NULL, ACK, FIN, XMAS, UDP`), `SCAN_ALL`, `MAX_PORTS 1024`, `MAX_THREADS 250` and `EXIT_FAILURE_CODE 255`. |
| `srcs/parse_args.c` | `parse_args` (returns void and exits by itself on error), `parse_ports` (dedup and sort through `seen[65536]`), `parse_scans` (separators `/` `,` and space, case-insensitive), `add_target` (`getaddrinfo` AF_INET), `load_targets_file`, `free_config`, `print_usage(FILE*)`, `exit_error(code)`, `scan_name`. All errors go through `fail(cfg)`, which calls `free_config` and then `exit_error(255)`. |
| `includes/packet.h`, `srcs/packet.c` | `checksum` (RFC 1071), `l4_checksum` (with the pseudo-header), `build_tcp` (20 bytes, random seq, window 1024, flags chosen by scan type), `build_udp` (8 bytes, empty; a checksum of 0 is sent as 0xFFFF), `get_source_ip` (UDP connect plus getsockname), `open_raw_socket` (prints a "try sudo" hint), `send_probe` (sendto, port 0) |
| `includes/scan.h`, `srcs/capture.c` | `t_result`, `t_probe`, `t_scanner` (one pcap handle plus TCP and UDP raw sockets each). `scanner_init(sc, dst, sport_base)` finds the device from the source IP, opens pcap **before sending**, gets the link header length from `pcap_datalink` and sets the BPF filter `icmp or (src host DST and (tcp or udp))`, in **non-blocking mode with poll()**. `parse_reply` is bounds-checked and matches ICMP errors through the quoted inner header. Also `wait_reply` / `drain_packets`. |
| `srcs/scan.c` | `scan_port(sc, dport, scan, &res)`: a unique source port per probe (wraps at 65000), one retry on the same port, a 1 s timeout per attempt, and `no_reply_result`. Also `result_name`. |
| `includes/threads.h`, `srcs/threads.c` | The thread engine: `run_scan(cfg, dst, results)` fills one `t_port_result` per port (see §6). |
| `srcs/main.c` | Prints the "Scan Configurations" block. `scan_all()` always runs: it scans **every** target with `run_scan`, prints `Scanning IP (name)..`, `Scan took X secs`, then raw `PORT SYN(Open) ...` lines (temporary `print_raw()`, until the output step). Test hook: if `FT_NMAP_PARSE_ONLY` is set, it stops after the config, so `test_parse.sh` runs without root. |
| `tests/valgrind.supp` | Suppresses a libpcap false positive (the `pcap_findalldevs` Bluetooth ioctl) |
| `tests/test_parse.sh` | 82 parsing tests, no root needed |
| `tests/test_reply.c` | Reply-classification unit tests on hand-made packets (`make test_reply`, about 32 checks). They were clean under ASan and UBSan. |
| `tests/test_live.sh` + `tests/capture_check.py` | Live loopback test, needs root: its own Python servers on ports 18000-18006, iptables DROP and REJECT (icmp-admin-prohibited) rules, an on-wire sniffer for flags and checksums, the non-root path through `setpriv`, valgrind, and cleanup on exit |
| `tests/ips.txt` | `127.0.0.1` (valid) and `999.999.1.1` (invalid, warned about and skipped) |

### Reply classification (implemented and tested)

| Scan | Reply | Result |
|---|---|---|
| SYN | SYN+ACK | Open |
| SYN | RST | Closed |
| SYN, ACK | nothing | Filtered |
| NULL/FIN/XMAS | RST | Closed |
| NULL/FIN/XMAS/UDP | nothing | Open\|Filtered |
| ACK | RST | Unfiltered |
| UDP | UDP reply | Open |
| UDP | ICMP 3/3 (port unreachable) | Closed |
| any | ICMP 3 with code 1, 2, 3 (TCP), 9, 10 or 13 | Filtered |

The live results on loopback in the conversation matched this table: open,
closed and DROP ports all gave the expected rows.

## 4. Decisions taken (don't re-litigate)

**Parsing**
- `getopt_long` with short options **enabled**: `"hp:i:f:s:S:"`, so `-p`, `-i`, `-f`, `-s` and `-S` work. The user chose this, and the tests accept `-p` and `-s -S` and reject `-z`.
- `--ip` together with `--file` is an **error**, with the message `--ip and --file cannot be used at the same time` (the user's wording).
- **Reversed ranges (`80-10`) are rejected**. Claude recommended keeping this strict, and the user didn't ask to change it. The swap alternative is documented in the conversation if it's ever needed.
- If `--ports` is given more than once, the last one wins.
- `70-90` counts 21 ports (both ends included). The subject's example says 20, which looks like a miscount in the subject.
- IPv6 is rejected (the subject says IPv4 only).
- A bad `--ip` is a fatal error. A bad line in `--file` prints a warning and is skipped, and it's an error only if no valid target is left.
- Every error exits with code 255 after printing `Try './ft_nmap --help' for more information.` `--help` exits with 0.
- Options are handled left to right, so `--speedup 999 --help` is an error while `--help --speedup 999` prints help. Abbreviations: `--spee` works, `--p` works (`--ports` and `--port` share the same val), and `--s` is ambiguous.

**Packets**
- **Option A**: no `IP_HDRINCL`, so the kernel builds the IP header and we build only the TCP or UDP header. Option B (building the IP header yourself) is kept for the bonuses (spoofing, decoys, TTL). `checksum()` is already tested and ready for it.
- Linux `tcphdr` field names are used (`source`, `dest`, `doff`, `syn`, ...).
- TCP and UDP builders live in `packet.c` as separate functions. Claude offered to split them into `checksum.c`, `tcp.c`, `udp.c` and `net.c`, but **the user never answered**, so this is optional.

**Scanning**
- One probe, then wait (1 s), retransmit once, then apply the no-reply rule. The speed has to come from threads, not from nmap-style congestion windows. A sender and receiver split with a pending-probe table was mentioned as a possible later optimisation.
- Source ports are 33000 and up. The live tests use ports 18000-18006, below that range, on purpose.

## 5. Bugs and lessons from the conversation

- **pcap hang**: blocking `pcap_next_ex` can block forever on an idle link even with a read timeout. Fixed with `pcap_setnonblock` plus `poll()` on `pcap_get_selectable_fd` and our own timeout. **Keep this pattern in threads.**
- Open the pcap handle *before* sending, or replies get missed and the port is wrongly reported as Filtered.
- On loopback, the kernel's own SYN+ACK shows a "bad checksum" because of checksum offload, and the kernel sends an RST after SYN+ACK because no socket owns our port. Both are normal.
- In test scripts, `pkill -f` can kill your own shell. Track PIDs instead.

## 6. Threading: DONE (2026-10-21)

Implemented in `includes/threads.h` and `srcs/threads.c`, following the agreed design:

- `t_port_result {port, res[NB_SCAN_TYPES]}`. Slots are indexed like `g_scan_order` (SYN NULL FIN XMAS ACK UDP), which is defined in `parse_args.c` and declared in `ft_nmap.h`. Slots of scans that weren't requested stay `RES_NONE`.
- `t_job_ctx`: job `j` is port `j / nb_scans` with scan `scan_slot[j % nb_scans]`. `next_job` and `error` are protected by the mutex. Each result slot is written by exactly one job, so it needs no lock.
- Worker count = `min(speedup, nb_jobs)`, with speedup 0 meaning one worker run in the main thread.
- Source ports 33000-64999 are split evenly between the workers (`span = 32000 / n`, at least 128 ports each). `scanner_init(sc, dst, base, count)` now takes a range, and `next_sport` wraps inside it.
- **Each pcap handle's BPF filter only accepts its own port range** (`dst portrange base-last`, plus all ICMP), so the kernel doesn't copy every reply to all 250 handles.
- **Scanner 0 is opened in the main thread before any thread starts.** The usual failure (not root) then prints a single message and exits with 255. Each other thread opens and closes its own scanner, because the kernel waits about 15-25 ms on every capture ring setup and teardown (PACKET_RX_RING, `close`). Done sequentially, 250 handles added about 10 s.
- `pcap_create` replaces `pcap_open_live`, with a 256 KB buffer (`PCAP_BUFFER_SIZE`; the default 2 MB × 250 would be too much) and **immediate mode**. Without immediate mode, TPACKET_V3 delays replies until its timeout.
- If `pthread_create` fails, the error flag is set, the threads already started are joined, and everything is closed and freed.

Measured on loopback (inside `unshare -rn`):
- The default scan (1024 ports × 6 scans) with `--speedup 250` takes about **1 s**, using about 68 MB RSS.
- The `test_live.sh` ports: 18 s with speedup 0 or 1, 4 s with 7, and 2 s with 70 or 250. The 2 s floor is the silent probes: 1 s timeout plus one retry.
- UDP on closed ports is limited by the kernel's ICMP rate limiting, which affects real nmap too.

## 7. Service Names (step 9, DONE 2026-10-22)

Implemented in `srcs/main.c`:
- Added `get_service_name(port)` helper using `getservbyport(htons(port), "tcp")`
- Returns service name (e.g., "http", "ssh") or "Unassigned" for unknown ports
- Updated `print_raw()` to display service names alongside ports
- Verified with standard ports: 80→http, 443→https, 22→ssh

## 8. Conclusion and Output Tables (step 10, DONE 2026-10-22)

Implemented in `srcs/main.c`:
- **`get_conclusion()`**: Determines Open/Filtered/Closed based on scan results
  - Open if any scan says Open
  - Filtered if SYN (index 0) says Filtered
  - Otherwise Closed
- **`print_results()`**: Outputs IP address followed by two tables
- **`print_table()`**: Formats separate tables for Open vs Closed/Filtered/Unfiltered
- **`print_port_row()`**: Formats one port with all scan results and conclusion
- Replaced `print_raw()` with new table-based output
- Timing already done: `"Scan took X.XXXXX secs"` from `gettimeofday()`
- **Updated `tests/test_live.sh`**: Modified `row()` function to parse new table format
  - Removes port, service name, and conclusion fields
  - Extracts just the scan results for comparison

Output format:
```
IP address: x.x.x.x
Open ports:
Port Service Name (if applicable) Results                        Conclusion
---------------------------------------------------------------------------
80   http                         SYN(Open) NULL(...) ...        Open

Closed/Filtered/Unfiltered ports:
...
```

## 9. Next steps (step 11-13)

- Robustness: check every return value (malloc, pcap_*, pthread_*, sendto), handle unreachable hosts, and free everything.
- Full test campaign with various thread counts and memory checkers.

## 10. Repository housekeeping (found during analysis)

- [x] **`tests/test_packet.c` restored** (2026-10-22). Created with 21 unit tests:
  - Checksum consistency tests
  - L4 checksum tests for TCP and UDP
  - build_tcp() tests for all scan types with flag verification
  - build_udp() tests including zero-checksum handling
  - All tests passing
- [ ] `CLAUDE.md` (the project briefing written in the conversation) isn't in the repo either.
- [x] **`.gitignore` added** (2026-10-22): excludes `*.o`, `ft_nmap`, test binaries, and editor temp files.
- [ ] Nothing is committed beyond the initial README, which is a stub.

## 11. Test status (2026-10-22, after output tables)

| Command | Root | Result |
|---|---|---|
| `bash tests/test_parse.sh` | no | ✅ 82/82 |
| `make test_reply` | no | ✅ all passed |
| `make test_packet` / `make test` | no | ✅ 21 tests + 82 parsing tests |
| `sudo bash tests/test_live.sh` | yes | ✅ 32/34 inside `unshare -rn`. The 2 failures are the `setpriv` non-root case, which can't work in a namespace that only maps uid 0. The non-root path was checked separately: exit code 255 and the "try sudo" message. Run it with real sudo to confirm all 34. |
| helgrind with 20 threads, memcheck with 20 threads | yes | ✅ no races, no leaks |

**Testing without sudo:** `unshare -rn bash -c 'ip link set lo up && bash tests/test_live.sh'`
gives root inside a private network namespace. Raw sockets, pcap and iptables
all work there, on a private loopback.

## 12. How to resume

```bash
make
bash tests/test_parse.sh
make test_reply
sudo bash tests/test_live.sh
sudo ./ft_nmap --ip 127.0.0.1 --ports 20-25 --scan SYN/UDP --speedup 10
```

Suggested order: update §11 (test_live.sh for new output format), then §12 (robustness review).

Only scan machines you own or have permission to scan.
