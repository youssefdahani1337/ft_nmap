# ft_nmap Architecture

## System Overview

The program follows a parse, resolve, schedule, probe, capture, classify, and
report pipeline:

```text
command line / target file
          |
          v
    parse_args.c  ---- resolve IPv4 targets
          |
          v
       main.c  ---- configuration and report lifecycle
          |
          v
      threads.c ---- port/scan jobs and worker ownership
          |
          +----------------------+
          |                      |
          v                      v
      packet.c              capture.c
   build/check/send       pcap/filter/parse
          |                      |
          +-----------> scan.c <-+
                         result classification
```

Each target is scanned independently. A target scan creates a result array,
executes every requested port/scan job, prints the report, and then moves to
the next target.

## Module Responsibilities

| Module | Responsibility |
| --- | --- |
| `srcs/main.c` | Program entry point, configuration display, monotonic timing, service names, result aggregation, and report output. |
| `srcs/parse_args.c` | `getopt_long` option parsing, duplicate detection, port grammar, scan grammar, IPv4/hostname resolution, target-file loading, and cleanup of parsed targets. |
| `srcs/packet.c` | Source-address discovery, raw TCP/UDP socket creation, TCP/UDP header construction, IPv4 pseudo-header checksums, and probe transmission. |
| `srcs/capture.c` | Interface discovery, libpcap configuration, link-layer offsets, BPF filtering, nonblocking capture, timeout polling, and TCP/UDP/ICMP reply parsing. |
| `srcs/scan.c` | Per-probe lifecycle, source-port allocation, retransmission, timeout mapping, and scan-specific no-reply results. |
| `srcs/threads.c` | Worker allocation, job queue synchronization, per-thread scanner ownership, result writes, joins, and failure propagation. |
| `includes/ft_nmap.h` | CLI constants, scan flags, targets, and global configuration. |
| `includes/packet.h` | Packet-builder and raw-socket interfaces. |
| `includes/scan.h` | Scanner state, probe state, result values, and capture interfaces. |
| `includes/threads.h` | Worker context, result storage, source-port ranges, and scheduler interface. |

## Input And Configuration

`parse_args()` initializes a zeroed `t_nmap` configuration, then validates:

- Exactly one of `--ip` and `--file`.
- A port expression containing individual ports, comma-separated values,
  ranges, or mixtures. Ports are deduplicated, sorted, and limited to 1024.
- A thread count from 0 through 250. Zero selects sequential execution.
- One or more scan names from SYN, NULL, FIN, XMAS, ACK, and UDP. A single
  `--scan` option may contain slash-, comma-, or space-separated names.
- Duplicate option occurrences, missing values, unknown options, and extra
  positional arguments.

Target resolution uses `getaddrinfo()` with `AF_INET`, so only IPv4 results are
accepted. File lines are read with `getline()`, trimmed, and skipped when they
are blank or begin with `#`. Invalid entries are warned about and skipped; a
file with no valid target is an error.

## Packet Construction

The raw sockets use the kernel to construct the IPv4 header. The program
constructs only the transport header:

- TCP SYN, NULL, FIN, XMAS, and ACK probes use a 20-byte TCP header.
- UDP probes use an 8-byte UDP header.
- TCP and UDP checksums include the IPv4 pseudo-header.
- Every probe gets a source port from the scanner's assigned source-port
  range. Retransmissions reuse that source port so late replies remain
  matchable.

The destination port is stored in the transport header because raw sockets are
used without `IP_HDRINCL`. A failed socket or `sendto()` call aborts the scan
cleanly and closes owned resources.

## Capture And Reply Matching

Each worker owns one pcap handle plus one raw TCP socket and one raw UDP socket.
The handle is opened before that worker sends a probe. The capture filter accepts
ICMP errors and TCP/UDP packets addressed to the worker's source-port range.

The interface is found from the selected source IPv4 address. The parser gets
the link-layer offset from `pcap_datalink()` instead of assuming Ethernet:

- Ethernet: 14 bytes
- Linux loopback/null: 4 bytes
- Raw IP: 0 bytes
- Linux cooked capture: 16 or 20 bytes

TCP and UDP replies must come from the target and match the expected source and
destination ports. ICMP destination-unreachable messages are matched by
validating the embedded original IPv4 header, protocol, addresses, and ports.
All packet parsers check captured lengths before reading fields.
Malformed TCP data offsets, invalid UDP lengths, nonzero IPv4 fragment fields,
and direct replies addressed to another local IP are rejected rather than
classified as scan results.

Capture is nonblocking and uses `poll()` with a monotonic deadline. This keeps
an idle interface from blocking a worker forever. Each probe gets one retry and
then maps silence according to the scan type.

## Scan Result Rules

| Scan | Positive reply | Silence |
| --- | --- | --- |
| SYN | SYN/ACK = Open; RST = Closed | Filtered |
| NULL | RST = Closed | Open\|Filtered |
| FIN | RST = Closed | Open\|Filtered |
| XMAS | RST = Closed | Open\|Filtered |
| ACK | RST = Unfiltered | Filtered |
| UDP | UDP reply = Open; ICMP port unreachable = Closed | Open\|Filtered |

Relevant ICMP unreachable codes are classified as Filtered, except UDP code 3
(port unreachable), which is Closed. Unexpected packets are ignored until the
probe deadline expires.

When multiple scan types produce results for one port, the report applies:

```text
Open > Unfiltered > Filtered > Open|Filtered > Closed
```

## Threading Model

The scheduler creates one job for each requested `(port, scan type)` pair. The
number of workers is the requested speedup, capped by the number of jobs. A
worker takes the next job while holding the shared mutex, then performs the
network operation using only its own scanner state.

Shared state is limited to the next job index, the error flag, and the result
array. Each job writes a distinct result slot, so result writes do not require
the scheduler mutex. Worker threads are joined before scanner resources and
the job context are destroyed. A worker or thread API failure causes the target
scan to fail rather than being reported as a successful scan.

## Resource And Error Handling

The normal cleanup path closes pcap handles and raw sockets, joins started
threads, destroys the mutex, frees target names, and frees result storage.
Input and network failures produce diagnostics and the project failure status
(`255` for argument/privilege failures). Packet parsing rejects malformed or
truncated data without dereferencing it.

## Test Architecture

- `tests/test_packet.c` checks TCP/UDP header fields and checksums.
- `tests/test_reply.c` checks all scan result mappings and truncated-packet
  safety.
- `tests/test_parse.sh` checks the normal command-line and target-file matrix.
- `tests/test_edge.sh` checks complex option combinations, duplicate options,
  boundaries, malformed expressions, and unusual files without root.
- `tests/test_live.sh` performs authorized loopback integration tests with
  local services, firewall rules, packet sniffing, multiple thread counts,
  Valgrind, and Helgrind.

Run the non-root suite with `make test`. Run the live suite with
`sudo make test_live` in an authorized Linux test environment.