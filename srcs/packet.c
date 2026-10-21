#include "../includes/packet.h"

/* Pseudo-header used ONLY to compute the TCP/UDP checksum (never sent). */
struct pseudo_hdr
{
	uint32_t	src;
	uint32_t	dst;
	uint8_t		zero;
	uint8_t		proto;
	uint16_t	len;
} __attribute__((packed));

/* Sum 16-bit words as they sit in memory (network byte order bytes). */
static uint32_t	sum16(const void *data, size_t len, uint32_t sum)
{
	const uint8_t	*p = data;
	uint16_t		word;

	while (len > 1)
	{
		memcpy(&word, p, 2);
		sum += word;
		p += 2;
		len -= 2;
	}
	if (len == 1)
	{
		uint8_t	last[2] = {*p, 0};

		memcpy(&word, last, 2);
		sum += word;
	}
	return (sum);
}

static uint16_t	fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return ((uint16_t)~sum);
}

uint16_t	checksum(const void *data, size_t len)
{
	return (fold(sum16(data, len, 0)));
}

/* Checksum of a TCP/UDP segment = pseudo-header + header + payload. */
uint16_t	l4_checksum(struct in_addr src, struct in_addr dst, uint8_t proto,
				const void *segment, size_t len)
{
	struct pseudo_hdr	ph;
	uint32_t			sum;

	ph.src = src.s_addr;
	ph.dst = dst.s_addr;
	ph.zero = 0;
	ph.proto = proto;
	ph.len = htons((uint16_t)len);
	sum = sum16(&ph, sizeof(ph), 0);
	sum = sum16(segment, len, sum);
	return (fold(sum));
}

/* ------------------------------------------------------------- builders -- */

size_t	build_tcp(uint8_t *buf, struct in_addr src, struct in_addr dst,
			uint16_t sport, uint16_t dport, t_scan_type scan)
{
	struct tcphdr	*tcp = (struct tcphdr *)buf;

	if (!buf || scan == SCAN_UDP)
		return (0);
	memset(buf, 0, TCP_PROBE_LEN);
	tcp->source = htons(sport);
	tcp->dest = htons(dport);
	tcp->seq = htonl(((uint32_t)rand() << 16) ^ (uint32_t)rand());
	tcp->doff = TCP_PROBE_LEN / 4;		/* header length in 32-bit words */
	tcp->window = htons(1024);
	switch (scan)
	{
	case SCAN_SYN:	tcp->syn = 1; break ;
	case SCAN_NULL:	break ;			/* no flag at all */
	case SCAN_FIN:	tcp->fin = 1; break ;
	case SCAN_XMAS:	tcp->fin = 1; tcp->psh = 1; tcp->urg = 1; break ;
	case SCAN_ACK:	tcp->ack = 1; break ;
	default:		return (0);
	}
	tcp->check = 0;						/* must be 0 while computing */
	tcp->check = l4_checksum(src, dst, IPPROTO_TCP, buf, TCP_PROBE_LEN);
	return (TCP_PROBE_LEN);
}

size_t	build_udp(uint8_t *buf, struct in_addr src, struct in_addr dst,
			uint16_t sport, uint16_t dport)
{
	struct udphdr	*udp = (struct udphdr *)buf;
	uint16_t		sum;

	if (!buf)
		return (0);
	memset(buf, 0, UDP_PROBE_LEN);
	udp->source = htons(sport);
	udp->dest = htons(dport);
	udp->len = htons(UDP_PROBE_LEN);
	udp->check = 0;
	sum = l4_checksum(src, dst, IPPROTO_UDP, buf, UDP_PROBE_LEN);
	udp->check = sum ? sum : 0xFFFF;	/* 0 means "no checksum" in UDP */
	return (UDP_PROBE_LEN);
}

/* -------------------------------------------------------------- network -- */

/* Which local IP would the kernel use to reach dst? (nothing is sent) */
int	get_source_ip(struct in_addr dst, struct in_addr *src)
{
	struct sockaddr_in	peer, local;
	socklen_t			len = sizeof(local);
	int					fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return (perror("ft_nmap: socket"), -1);
	memset(&peer, 0, sizeof(peer));
	peer.sin_family = AF_INET;
	peer.sin_addr = dst;
	peer.sin_port = htons(53);
	if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) < 0
		|| getsockname(fd, (struct sockaddr *)&local, &len) < 0)
	{
		perror("ft_nmap: cannot find source address");
		close(fd);
		return (-1);
	}
	close(fd);
	*src = local.sin_addr;
	return (0);
}

int	open_raw_socket(int proto)
{
	int	fd = socket(AF_INET, SOCK_RAW, proto);

	if (fd < 0)
	{
		if (errno == EPERM || errno == EACCES)
			fprintf(stderr, "ft_nmap: raw sockets need root privileges (try sudo)\n");
		else
			perror("ft_nmap: socket");
		return (-1);
	}
	return (fd);
}

int	send_probe(int sock, struct in_addr dst, const uint8_t *buf, size_t len)
{
	struct sockaddr_in	to;

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = dst;		/* sin_port stays 0: it is in the L4 header */
	if (sendto(sock, buf, len, 0, (struct sockaddr *)&to, sizeof(to)) < 0)
	{
		perror("ft_nmap: sendto");
		return (-1);
	}
	return (0);
}
