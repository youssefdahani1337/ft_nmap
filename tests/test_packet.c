/* Packet building and checksum unit tests (no root, no network).
** Build & run:  make test_packet */
#include "../includes/packet.h"

static int	fails;

#define CHECK(got, want, msg) do { \
	if ((got) == (want)) printf("  [ OK ] %s\n", msg); \
	else { printf("  [FAIL] %s (got %u, want %u)\n", msg, (unsigned)(got), (unsigned)(want)); fails++; } } while (0)

#define CHECK_SIZE(got, want, msg) do { \
	if ((got) == (want)) printf("  [ OK ] %s\n", msg); \
	else { printf("  [FAIL] %s (got %zu, want %zu)\n", msg, (size_t)(got), (size_t)(want)); fails++; } } while (0)

/* Checksum consistency test (verify deterministic and idempotent) */
int	test_checksum_consistency(void)
{
	uint8_t		data[4] = {0x45, 0x4e, 0x00, 0x1c};
	uint16_t	result1, result2;

	puts("checksum() - consistency");
	result1 = checksum(data, sizeof(data));
	result2 = checksum(data, sizeof(data));
	CHECK(result1, result2, "Checksum is deterministic (same input -> same output)");
	CHECK(result1 != 0, 1, "Checksum is non-zero for typical packet data");
	return (fails);
}

/* Test basic IP header checksum (simplified, just the format) */
int	test_checksum_ip_header(void)
{
	uint8_t		ip_hdr[20];
	uint16_t	chk;

	puts("checksum() - IP header");
	memset(ip_hdr, 0, 20);
	ip_hdr[0] = 0x45;		/* IPv4, 20-byte header */
	ip_hdr[9] = IPPROTO_TCP;
	/* typical source and dest: 192.168.1.1 and 8.8.8.8 */
	ip_hdr[12] = 0xc0; ip_hdr[13] = 0xa8; ip_hdr[14] = 0x01; ip_hdr[15] = 0x01;
	ip_hdr[16] = 0x08; ip_hdr[17] = 0x08; ip_hdr[18] = 0x08; ip_hdr[19] = 0x08;
	chk = checksum(ip_hdr, 20);
	CHECK(chk != 0, 1, "IP header checksum is non-zero");
	return (fails);
}

int	test_l4_checksum_tcp(void)
{
	struct in_addr	src, dst;
	uint8_t			tcp_buf[20];
	uint16_t		chk, chk2;

	puts("l4_checksum() - TCP");
	inet_pton(AF_INET, "192.168.1.1", &src);
	inet_pton(AF_INET, "8.8.8.8", &dst);
	memset(tcp_buf, 0, 20);
	/* sport, dport, seq, ack, doff/flags, window */
	tcp_buf[0] = 0x80; tcp_buf[1] = 0x00;	/* sport 32768 */
	tcp_buf[2] = 0x00; tcp_buf[3] = 0x50;	/* dport 80 */
	tcp_buf[4] = 0x00; tcp_buf[5] = 0x00;	/* seq */
	tcp_buf[6] = 0x00; tcp_buf[7] = 0x01;
	tcp_buf[8] = 0x00; tcp_buf[9] = 0x00;	/* ack */
	tcp_buf[10] = 0x00; tcp_buf[11] = 0x00;
	tcp_buf[12] = 0x50; tcp_buf[13] = 0x02;	/* doff=5, flags=SYN */
	tcp_buf[14] = 0x20; tcp_buf[15] = 0x00;	/* window 8192 */
	tcp_buf[16] = 0x00; tcp_buf[17] = 0x00;	/* checksum field (before compute) */
	tcp_buf[18] = 0x00; tcp_buf[19] = 0x00;	/* urgent */
	chk = l4_checksum(src, dst, IPPROTO_TCP, tcp_buf, 20);
	CHECK(chk != 0, 1, "TCP L4 checksum is non-zero");
	/* Verify idempotence: running it again gives the same result */
	chk2 = l4_checksum(src, dst, IPPROTO_TCP, tcp_buf, 20);
	CHECK(chk, chk2, "TCP L4 checksum is deterministic");
	return (fails);
}

int	test_l4_checksum_udp(void)
{
	struct in_addr	src, dst;
	uint8_t			udp_buf[8];
	uint16_t		chk;

	puts("l4_checksum() - UDP");
	inet_pton(AF_INET, "192.168.1.1", &src);
	inet_pton(AF_INET, "8.8.8.8", &dst);
	memset(udp_buf, 0, 8);
	udp_buf[0] = 0x80; udp_buf[1] = 0x00;	/* sport 32768 */
	udp_buf[2] = 0x00; udp_buf[3] = 0x35;	/* dport 53 (DNS) */
	udp_buf[4] = 0x00; udp_buf[5] = 0x08;	/* length 8 */
	udp_buf[6] = 0x00; udp_buf[7] = 0x00;	/* checksum (before compute) */
	chk = l4_checksum(src, dst, IPPROTO_UDP, udp_buf, 8);
	CHECK(chk != 0, 1, "UDP L4 checksum is non-zero");
	return (fails);
}

int	test_build_tcp_sizes(void)
{
	struct in_addr	src, dst;
	uint8_t			buf[64];
	size_t			size;

	puts("build_tcp() - sizes");
	inet_pton(AF_INET, "192.168.1.1", &src);
	inet_pton(AF_INET, "8.8.8.8", &dst);

	size = build_tcp(buf, src, dst, 33000, 80, SCAN_SYN);
	CHECK_SIZE(size, TCP_PROBE_LEN, "SYN scan returns TCP_PROBE_LEN");

	size = build_tcp(buf, src, dst, 33000, 80, SCAN_NULL);
	CHECK_SIZE(size, TCP_PROBE_LEN, "NULL scan returns TCP_PROBE_LEN");

	size = build_tcp(buf, src, dst, 33000, 80, SCAN_FIN);
	CHECK_SIZE(size, TCP_PROBE_LEN, "FIN scan returns TCP_PROBE_LEN");

	size = build_tcp(buf, src, dst, 33000, 80, SCAN_XMAS);
	CHECK_SIZE(size, TCP_PROBE_LEN, "XMAS scan returns TCP_PROBE_LEN");

	size = build_tcp(buf, src, dst, 33000, 80, SCAN_ACK);
	CHECK_SIZE(size, TCP_PROBE_LEN, "ACK scan returns TCP_PROBE_LEN");

	size = build_tcp(buf, src, dst, 33000, 80, SCAN_UDP);
	CHECK_SIZE(size, 0, "UDP scan type returns 0");

	size = build_tcp(NULL, src, dst, 33000, 80, SCAN_SYN);
	CHECK_SIZE(size, 0, "NULL buffer returns 0");

	return (fails);
}

int	test_build_tcp_flags(void)
{
	struct in_addr	src, dst;
	struct tcphdr	*tcp;
	uint8_t			buf[64];

	puts("build_tcp() - flags");
	inet_pton(AF_INET, "192.168.1.1", &src);
	inet_pton(AF_INET, "8.8.8.8", &dst);

	/* SYN scan */
	build_tcp(buf, src, dst, 33000, 80, SCAN_SYN);
	tcp = (struct tcphdr *)buf;
	CHECK(tcp->syn, 1, "SYN scan has SYN flag");
	CHECK(tcp->fin, 0, "SYN scan has no FIN flag");
	CHECK(tcp->ack, 0, "SYN scan has no ACK flag");
	CHECK(tcp->psh, 0, "SYN scan has no PSH flag");
	CHECK(tcp->urg, 0, "SYN scan has no URG flag");

	/* NULL scan */
	build_tcp(buf, src, dst, 33000, 80, SCAN_NULL);
	tcp = (struct tcphdr *)buf;
	CHECK(tcp->syn, 0, "NULL scan has no SYN flag");
	CHECK(tcp->fin, 0, "NULL scan has no FIN flag");
	CHECK(tcp->ack, 0, "NULL scan has no ACK flag");
	CHECK(tcp->psh, 0, "NULL scan has no PSH flag");
	CHECK(tcp->urg, 0, "NULL scan has no URG flag");

	/* FIN scan */
	build_tcp(buf, src, dst, 33000, 80, SCAN_FIN);
	tcp = (struct tcphdr *)buf;
	CHECK(tcp->fin, 1, "FIN scan has FIN flag");
	CHECK(tcp->syn, 0, "FIN scan has no SYN flag");

	/* XMAS scan */
	build_tcp(buf, src, dst, 33000, 80, SCAN_XMAS);
	tcp = (struct tcphdr *)buf;
	CHECK(tcp->fin, 1, "XMAS scan has FIN flag");
	CHECK(tcp->psh, 1, "XMAS scan has PSH flag");
	CHECK(tcp->urg, 1, "XMAS scan has URG flag");
	CHECK(tcp->syn, 0, "XMAS scan has no SYN flag");

	/* ACK scan */
	build_tcp(buf, src, dst, 33000, 80, SCAN_ACK);
	tcp = (struct tcphdr *)buf;
	CHECK(tcp->ack, 1, "ACK scan has ACK flag");
	CHECK(tcp->syn, 0, "ACK scan has no SYN flag");

	return (fails);
}

int	test_build_tcp_fields(void)
{
	struct in_addr	src, dst;
	struct tcphdr	*tcp;
	uint8_t			buf[64];
	uint16_t		sport = 33000, dport = 80;

	puts("build_tcp() - port and header fields");
	inet_pton(AF_INET, "192.168.1.1", &src);
	inet_pton(AF_INET, "8.8.8.8", &dst);

	build_tcp(buf, src, dst, sport, dport, SCAN_SYN);
	tcp = (struct tcphdr *)buf;

	CHECK(ntohs(tcp->source), sport, "sport is set correctly");
	CHECK(ntohs(tcp->dest), dport, "dport is set correctly");
	CHECK(tcp->doff, 5, "doff is 5 (20 bytes / 4)");
	CHECK(ntohs(tcp->window), 1024, "window is 1024");
	CHECK(tcp->check != 0, 1, "checksum is non-zero");
	CHECK(tcp->seq != 0, 1, "sequence number is non-zero (randomized)");

	return (fails);
}

int	test_build_udp_sizes(void)
{
	struct in_addr	src, dst;
	uint8_t			buf[64];
	size_t			size;

	puts("build_udp() - sizes");
	inet_pton(AF_INET, "192.168.1.1", &src);
	inet_pton(AF_INET, "8.8.8.8", &dst);

	size = build_udp(buf, src, dst, 33000, 53);
	CHECK_SIZE(size, UDP_PROBE_LEN, "UDP returns UDP_PROBE_LEN");

	size = build_udp(NULL, src, dst, 33000, 53);
	CHECK_SIZE(size, 0, "NULL buffer returns 0");

	return (fails);
}

int	test_build_udp_fields(void)
{
	struct in_addr	src, dst;
	struct udphdr	*udp;
	uint8_t			buf[64];
	uint16_t		sport = 33000, dport = 53;

	puts("build_udp() - port and header fields");
	inet_pton(AF_INET, "192.168.1.1", &src);
	inet_pton(AF_INET, "8.8.8.8", &dst);

	build_udp(buf, src, dst, sport, dport);
	udp = (struct udphdr *)buf;

	CHECK(ntohs(udp->source), sport, "sport is set correctly");
	CHECK(ntohs(udp->dest), dport, "dport is set correctly");
	CHECK(ntohs(udp->len), UDP_PROBE_LEN, "length is UDP_PROBE_LEN");
	CHECK(udp->check != 0, 1, "checksum is non-zero (0xFFFF for zero checksum)");

	return (fails);
}

int	test_build_udp_zero_checksum(void)
{
	struct in_addr	src, dst;
	struct udphdr	*udp;
	uint8_t			buf[64];

	puts("build_udp() - zero checksum handling");
	inet_pton(AF_INET, "0.0.0.0", &src);
	inet_pton(AF_INET, "0.0.0.0", &dst);

	/* With matching src/dst, the checksum might be 0; UDP maps 0 to 0xFFFF */
	build_udp(buf, src, dst, 1000, 2000);
	udp = (struct udphdr *)buf;
	CHECK(udp->check == 0xFFFF || udp->check != 0, 1, "checksum is never 0 (maps to 0xFFFF)");

	return (fails);
}

int	main(void)
{
	fails = 0;

	fails += test_checksum_consistency();
	fails += test_checksum_ip_header();
	fails += test_l4_checksum_tcp();
	fails += test_l4_checksum_udp();
	fails += test_build_tcp_sizes();
	fails += test_build_tcp_flags();
	fails += test_build_tcp_fields();
	fails += test_build_udp_sizes();
	fails += test_build_udp_fields();
	fails += test_build_udp_zero_checksum();

	printf("%s\n", fails ? "SOME TESTS FAILED" : "All packet tests passed");
	return (fails != 0);
}
