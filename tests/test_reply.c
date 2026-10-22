/* Reply-parsing unit tests on hand-made packets (no root, no network).
** Build & run:  make test_reply */
#include "../includes/scan.h"

static int	fails;
static struct in_addr	SRC, DST, ROUTER;

#define CHECK(got, want, msg) do { t_result g_ = (got); \
	if (g_ == (want)) printf("  [ OK ] %s\n", msg); \
	else { printf("  [FAIL] %s (got %s, want %s)\n", msg, result_name(g_), result_name(want)); fails++; } } while (0)

static void	wr16(uint8_t *b, uint16_t v) { b[0] = v >> 8; b[1] = v & 0xFF; }

static size_t	mk_ip(uint8_t *b, uint8_t proto, struct in_addr s, struct in_addr d)
{
	memset(b, 0, 20);
	b[0] = 0x45; b[8] = 64; b[9] = proto;
	memcpy(b + 12, &s.s_addr, 4);
	memcpy(b + 16, &d.s_addr, 4);
	return (20);
}

/* TCP reply from the target: its sport = scanned port, dport = our port */
static size_t	mk_tcp_reply(uint8_t *b, uint16_t sport, uint16_t dport, uint8_t flags)
{
	size_t	n = mk_ip(b, IPPROTO_TCP, DST, SRC);

	memset(b + n, 0, 20);
	wr16(b + n, sport); wr16(b + n + 2, dport);
	b[n + 12] = 0x50; b[n + 13] = flags;
	return (n + 20);
}

static size_t	mk_udp_reply(uint8_t *b, uint16_t sport, uint16_t dport)
{
	size_t	n = mk_ip(b, IPPROTO_UDP, DST, SRC);

	memset(b + n, 0, 8);
	wr16(b + n, sport); wr16(b + n + 2, dport); wr16(b + n + 4, 8);
	return (n + 8);
}

/* ICMP unreachable quoting OUR probe (src -> dst, sport -> dport) */
static size_t	mk_icmp(uint8_t *b, struct in_addr from, uint8_t code, uint8_t inner_proto,
					uint16_t sport, uint16_t dport)
{
	size_t	n = mk_ip(b, IPPROTO_ICMP, from, SRC);

	memset(b + n, 0, 8);
	b[n] = 3; b[n + 1] = code;
	n += 8;
	n += mk_ip(b + n, inner_proto, SRC, DST);
	memset(b + n, 0, 8);
	wr16(b + n, sport); wr16(b + n + 2, dport);
	return (n + 8);
}

#define SPORT 33000
#define DPORT 80
static t_probe	probe(t_scan_type s) { t_probe p = {SRC, DST, SPORT, DPORT, s}; return (p); }

int	main(void)
{
	uint8_t		b[200];
	size_t		n;
	t_probe		p;

	inet_pton(AF_INET, "192.168.1.10", &SRC);
	inet_pton(AF_INET, "10.0.0.7", &DST);
	inet_pton(AF_INET, "10.0.0.1", &ROUTER);

	puts("SYN");
	p = probe(SCAN_SYN);
	n = mk_tcp_reply(b, DPORT, SPORT, 0x12); CHECK(parse_reply(b, n, &p), RES_OPEN, "SYN+ACK -> Open");
	n = mk_tcp_reply(b, DPORT, SPORT, 0x14); CHECK(parse_reply(b, n, &p), RES_CLOSED, "RST+ACK -> Closed");
	n = mk_tcp_reply(b, DPORT, SPORT, 0x04); CHECK(parse_reply(b, n, &p), RES_CLOSED, "RST -> Closed");
	n = mk_tcp_reply(b, DPORT, SPORT, 0x10); CHECK(parse_reply(b, n, &p), RES_NONE, "plain ACK -> ignored");
	n = mk_tcp_reply(b, 81, SPORT, 0x12);    CHECK(parse_reply(b, n, &p), RES_NONE, "other port -> ignored");
	n = mk_tcp_reply(b, DPORT, SPORT + 1, 0x12); CHECK(parse_reply(b, n, &p), RES_NONE, "other source port -> ignored");
	n = mk_icmp(b, ROUTER, 13, IPPROTO_TCP, SPORT, DPORT); CHECK(parse_reply(b, n, &p), RES_FILTERED, "ICMP code 13 from router -> Filtered");
	n = mk_icmp(b, DST, 3, IPPROTO_TCP, SPORT, DPORT);     CHECK(parse_reply(b, n, &p), RES_FILTERED, "ICMP code 3 (TCP scan) -> Filtered");
	n = mk_icmp(b, DST, 0, IPPROTO_TCP, SPORT, DPORT);     CHECK(parse_reply(b, n, &p), RES_FILTERED, "ICMP code 0 -> Filtered");
	n = mk_icmp(b, DST, 3, IPPROTO_TCP, SPORT, 81);        CHECK(parse_reply(b, n, &p), RES_NONE, "ICMP about another port -> ignored");
	n = mk_icmp(b, DST, 3, IPPROTO_UDP, SPORT, DPORT);     CHECK(parse_reply(b, n, &p), RES_NONE, "ICMP about UDP during TCP scan -> ignored");

	puts("NULL / FIN / XMAS");
	for (int i = 0; i < 3; i++)
	{
		t_scan_type s[3] = {SCAN_NULL, SCAN_FIN, SCAN_XMAS};
		p = probe(s[i]);
		n = mk_tcp_reply(b, DPORT, SPORT, 0x04); CHECK(parse_reply(b, n, &p), RES_CLOSED, "RST -> Closed");
		n = mk_tcp_reply(b, DPORT, SPORT, 0x12); CHECK(parse_reply(b, n, &p), RES_NONE, "SYN+ACK -> ignored");
		n = mk_icmp(b, ROUTER, 10, IPPROTO_TCP, SPORT, DPORT); CHECK(parse_reply(b, n, &p), RES_FILTERED, "ICMP code 10 -> Filtered");
	}

	puts("ACK");
	p = probe(SCAN_ACK);
	n = mk_tcp_reply(b, DPORT, SPORT, 0x04); CHECK(parse_reply(b, n, &p), RES_UNFILTERED, "RST -> Unfiltered");
	n = mk_icmp(b, ROUTER, 1, IPPROTO_TCP, SPORT, DPORT); CHECK(parse_reply(b, n, &p), RES_FILTERED, "ICMP code 1 -> Filtered");

	puts("UDP");
	p = probe(SCAN_UDP);
	n = mk_udp_reply(b, DPORT, SPORT);       CHECK(parse_reply(b, n, &p), RES_OPEN, "UDP reply -> Open");
	n = mk_udp_reply(b, 81, SPORT);          CHECK(parse_reply(b, n, &p), RES_NONE, "UDP other port -> ignored");
	n = mk_icmp(b, DST, 3, IPPROTO_UDP, SPORT, DPORT);    CHECK(parse_reply(b, n, &p), RES_CLOSED, "ICMP port unreachable -> Closed");
	n = mk_icmp(b, ROUTER, 13, IPPROTO_UDP, SPORT, DPORT); CHECK(parse_reply(b, n, &p), RES_FILTERED, "ICMP code 13 -> Filtered");
	n = mk_icmp(b, ROUTER, 9, IPPROTO_UDP, SPORT, DPORT);  CHECK(parse_reply(b, n, &p), RES_FILTERED, "ICMP code 9 -> Filtered");
	n = mk_tcp_reply(b, DPORT, SPORT, 0x04); CHECK(parse_reply(b, n, &p), RES_NONE, "TCP RST during UDP scan -> ignored");

	puts("Robustness (exact-size heap copies: ASan catches any over-read)");
	{
		uint8_t	*h;
		size_t	full = mk_icmp(b, DST, 3, IPPROTO_UDP, SPORT, DPORT);
		int		bad = 0;

		/* IP(20) + ICMP(8) + quoted IP(20) + 4 port bytes = 52: the minimum we need */
		for (size_t l = 0; l <= full; l++)
		{
			h = malloc(l ? l : 1);
			memcpy(h, b, l);
			if (parse_reply(h, l, &p) != (l >= 52 ? RES_CLOSED : RES_NONE))
				bad++;
			free(h);
		}
		CHECK(bad ? RES_NONE : RES_OPEN, RES_OPEN, "truncated ICMP: rejected below 52 bytes, parsed from 52, never over-reads");
		b[0] = 0x4F;					/* absurd IP header length (60) on a short packet */
		CHECK(parse_reply(b, 30, &p), RES_NONE, "bad IP header length -> ignored");
		b[0] = 0x65;					/* not IPv4 */
		CHECK(parse_reply(b, full, &p), RES_NONE, "non-IPv4 -> ignored");
		CHECK(parse_reply(NULL, 0, &p), RES_NONE, "NULL packet -> ignored");
		n = mk_tcp_reply(b, DPORT, SPORT, 0x12);
		b[32] = 0x40;
		CHECK(parse_reply(b, n, &p), RES_NONE, "short TCP data offset -> ignored");
		n = mk_udp_reply(b, DPORT, SPORT);
		wr16(b + 24, 4);
		CHECK(parse_reply(b, n, &p), RES_NONE, "short UDP length -> ignored");
		n = mk_tcp_reply(b, DPORT, SPORT, 0x12);
		b[16] = ROUTER.s_addr & 0xFF;
		CHECK(parse_reply(b, n, &p), RES_NONE, "wrong destination IP -> ignored");
		n = mk_tcp_reply(b, DPORT, SPORT, 0x12);
		b[6] = 0x20;
		CHECK(parse_reply(b, n, &p), RES_NONE, "fragmented IPv4 reply -> ignored");
	}
	printf("%s\n", fails ? "SOME TESTS FAILED" : "All reply tests passed");
	return (fails != 0);
}
