# ft_nmap

`ft_nmap` is a Linux IPv4 port scanner written in C. It uses raw sockets to
send probes, libpcap to capture replies, and pthreads to distribute scan jobs.
The project implements the mandatory scan types only: SYN, NULL, FIN, XMAS,
ACK, and UDP. DNS/version detection, OS detection, evasion, and spoofing are
outside the project scope.

The detailed design is documented in [ARCHITECTURE.md](ARCHITECTURE.md).

## Requirements

- Linux with IPv4 support
- GCC or a compatible C compiler
- libpcap development headers and library
- pthread support
- Root privileges, or suitable `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities,
  for live raw-socket and packet-capture scans

## Build And Clean

```sh
make
```

The executable is `ft_nmap`. Unit and parser tests do not require root:

```sh
make test
```

Other Make targets are:

```sh
make clean       # remove object files
make fclean      # remove objects, executable, and unit-test binaries
make re          # clean and rebuild
make test_edge   # run only the extended non-root edge-case suite
```

Live scans need raw-socket and packet-capture privileges. The simplest option
is to run the program through sudo:

```sh
sudo ./ft_nmap --ip 127.0.0.1 --ports 1-1024 --scan SYN --speedup 4
```

On systems where libpcap permits capabilities, the equivalent is:

```sh
sudo setcap cap_net_raw,cap_net_admin+eip ./ft_nmap
./ft_nmap --ip 127.0.0.1 --ports 1-1024 --scan SYN
sudo setcap -r ./ft_nmap
```

## Usage

```text
ft_nmap [--help] [--ports PORTS] --ip ADDRESS [--speedup N] [--scan TYPES]
ft_nmap [--help] [--ports PORTS] --file FILE [--speedup N] [--scan TYPES]
```

`--port` is accepted as an alias for `--ports`. Ports accept individual
values, comma-separated lists, ranges, and mixes, with a maximum of 1024
unique ports. The default is `1-1024`. `--scan` accepts slash-, comma-, or
space-separated names; when omitted, all six scans run. `--speedup 0` runs
sequentially and values up to 250 use worker threads.

Examples:

```sh
# Scan the default 1-1024 range with every scan type.
sudo ./ft_nmap --ip 127.0.0.1

# Scan selected ports with a SYN scan and seven workers.
sudo ./ft_nmap --ip localhost --ports 22,80,443,8000-8003 --scan SYN --speedup 7

# Run several scan types against every target in a file.
sudo ./ft_nmap --file tests/ips.txt --ports 1-128 --scan SYN/ACK/UDP --speedup 4
```

`--ip` accepts an IPv4 address or an IPv4-resolvable hostname. `--file`
accepts one address or hostname per line; blank lines and lines beginning with
`#` are ignored. The two target options are mutually exclusive.

For each port, the report uses the service name from the system service table
and falls back to `Unassigned`. The conclusion priority is:
`Open > Unfiltered > Filtered > Open|Filtered > Closed`.

Targets are IPv4 addresses or IPv4-resolvable hostnames. File input accepts
one target per line; blank lines and lines beginning with `#` are ignored.

## Output And Results

The report prints the configuration, target, number of ports, requested scans,
thread count, duration, and one result row per port. Ports are sorted in
ascending order. Service names come from the system service database and use
`Unassigned` when no name is available.

For a port scanned with multiple methods, the final conclusion uses this
priority:

```text
Open > Unfiltered > Filtered > Open|Filtered > Closed
```

The port is placed in the `Open ports` table only when the final conclusion is
`Open`; all other conclusions appear in the second table.

## Privileges

Without the required privileges, the program exits with status `255` and
prints a clear `try sudo` message. The usual approach is:

```sh
sudo ./ft_nmap --ip 127.0.0.1 --ports 80 --scan SYN
```

On systems where libpcap allows file capabilities:

```sh
sudo setcap cap_net_raw,cap_net_admin+eip ./ft_nmap
./ft_nmap --ip 127.0.0.1 --ports 80 --scan SYN
sudo setcap -r ./ft_nmap
```

Only scan loopback, systems you own, or systems for which you have explicit
authorization.

## Testing

The non-root suite is deterministic and runs in parse-only mode where packet
transmission is not needed:

```sh
make test
```

This runs packet-builder tests, reply-parser tests, 45 extended edge cases,
and the existing parser suite. The live suite starts local TCP/UDP services,
checks packet flags and checksums, exercises firewall behavior, compares
thread counts, and runs Valgrind/Helgrind when available:

```sh
sudo make test_live
```

The live tests modify loopback firewall rules temporarily and clean them up on
exit. They must only be run in an environment where that is permitted.
