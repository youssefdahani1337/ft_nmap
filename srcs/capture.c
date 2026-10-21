#include "../includes/scan.h"
#include <time.h>
#include <poll.h>

/* TCP flag bits (byte 13 of the TCP header) */
#define F_SYN	0x02
#define F_RST	0x04
#define F_ACK	0x10

/* ---------------------------------------------------------------- setup -- */

/* Name of the interface that owns the IPv4 address `src` ("lo" for 127.0.0.1). */
static int	find_device(struct in_addr src, char *dev, size_t size)
{
	char			errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t		*all, *d;
	pcap_addr_t		*a;
	int				found = 0;

	if (pcap_findalldevs(&all, errbuf) < 0)
		return (fprintf(stderr, "ft_nmap: pcap_findalldevs: %s\n", errbuf), -1);
	for (d = all; d && !found; d = d->next)
		for (a = d->addresses; a && !found; a = a->next)
			if (a->addr && a->addr->sa_family == AF_INET
				&& ((struct sockaddr_in *)a->addr)->sin_addr.s_addr == src.s_addr)
			{
				snprintf(dev, size, "%s", d->name);
				found = 1;
			}
	pcap_freealldevs(all);
	if (!found)
		fprintf(stderr, "ft_nmap: no network interface has address %s\n", inet_ntoa(src));
	return (found ? 0 : -1);
}

/* The link-layer header size depends on the interface type: never hard-code 14. */
static int	link_header_len(pcap_t *handle)
{
	switch (pcap_datalink(handle))
	{
	case DLT_EN10MB:		return (14);
	case DLT_NULL:
	case DLT_LOOP:			return (4);
	case DLT_RAW:			return (0);
	case DLT_LINUX_SLL:		return (16);
#ifdef DLT_LINUX_SLL2
	case DLT_LINUX_SLL2:	return (20);
#endif
	default:				return (-1);
	}
}

/* Only replies to OUR source ports reach this handle, so with many threads the
** kernel drops the other threads' replies instead of copying them to everyone. */
static int	set_filter(pcap_t *handle, const t_scanner *sc)
{
	struct bpf_program	prog;
	char				filter[160], dst_str[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &sc->dst, dst_str, sizeof(dst_str));
	/* ICMP errors may come from a router (not from the target), so accept any icmp */
	snprintf(filter, sizeof(filter), "icmp or (src host %s and (tcp or udp) and dst portrange %u-%u)",
		dst_str, sc->base_port, sc->last_port);
	if (pcap_compile(handle, &prog, filter, 1, PCAP_NETMASK_UNKNOWN) < 0)
		return (fprintf(stderr, "ft_nmap: pcap_compile: %s\n", pcap_geterr(handle)), -1);
	if (pcap_setfilter(handle, &prog) < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_setfilter: %s\n", pcap_geterr(handle));
		pcap_freecode(&prog);
		return (-1);
	}
	pcap_freecode(&prog);
	return (0);
}

void	scanner_close(t_scanner *sc)
{
	if (sc->handle)
		pcap_close(sc->handle);
	if (sc->tcp_sock >= 0)
		close(sc->tcp_sock);
	if (sc->udp_sock >= 0)
		close(sc->udp_sock);
	sc->handle = NULL;
	sc->tcp_sock = -1;
	sc->udp_sock = -1;
}

/* Same as pcap_open_live(), but with a small capture buffer: with up to 250
** threads, each owning a handle, the 2MB default would cost ~500MB. */
static pcap_t	*open_handle(const char *dev)
{
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*handle;
	int		rc;

	handle = pcap_create(dev, errbuf);
	if (!handle)
		return (fprintf(stderr, "ft_nmap: pcap_create(%s): %s\n", dev, errbuf), NULL);
	pcap_set_snaplen(handle, SNAPLEN);
	pcap_set_promisc(handle, 0);
	pcap_set_timeout(handle, PCAP_READ_MS);
	pcap_set_buffer_size(handle, PCAP_BUFFER_SIZE);
	pcap_set_immediate_mode(handle, 1);	/* deliver each reply at once, not per 50ms block */
	rc = pcap_activate(handle);
	if (rc < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_activate(%s): %s\n", dev, pcap_geterr(handle));
		if (rc == PCAP_ERROR_PERM_DENIED)
			fprintf(stderr, "ft_nmap: capturing packets needs root privileges (try sudo)\n");
		pcap_close(handle);
		return (NULL);
	}
	return (handle);
}

/* The pcap handle is opened HERE, before any probe is sent, so no reply is missed.
** Probes use the source ports [sport_base, sport_base + sport_count - 1]. */
int	scanner_init(t_scanner *sc, struct in_addr dst, uint16_t sport_base,
		uint16_t sport_count)
{
	char	errbuf[PCAP_ERRBUF_SIZE];
	int		link;

	memset(sc, 0, sizeof(*sc));
	sc->fd = -1;
	sc->tcp_sock = -1;
	sc->udp_sock = -1;
	sc->dst = dst;
	sc->base_port = sport_base;
	sc->last_port = (uint16_t)(sport_base + (sport_count ? sport_count - 1 : 0));
	sc->next_sport = sport_base;
	if (get_source_ip(dst, &sc->src) < 0 || find_device(sc->src, sc->dev, sizeof(sc->dev)) < 0)
		return (-1);
	sc->handle = open_handle(sc->dev);
	if (!sc->handle)
		return (-1);
	link = link_header_len(sc->handle);
	if (link < 0)
	{
		fprintf(stderr, "ft_nmap: unsupported link type on %s\n", sc->dev);
		return (scanner_close(sc), -1);
	}
	sc->link_len = (size_t)link;
	/* Blocking pcap_next_ex() may never return on an idle link (libpcap quirk):
	** use non-blocking mode and poll() with OUR OWN timeout instead. */
	if (pcap_setnonblock(sc->handle, 1, errbuf) < 0)
	{
		fprintf(stderr, "ft_nmap: pcap_setnonblock: %s\n", errbuf);
		return (scanner_close(sc), -1);
	}
	sc->fd = pcap_get_selectable_fd(sc->handle);
	if (set_filter(sc->handle, sc) < 0
		|| (sc->tcp_sock = open_raw_socket(IPPROTO_TCP)) < 0
		|| (sc->udp_sock = open_raw_socket(IPPROTO_UDP)) < 0)
		return (scanner_close(sc), -1);
	return (0);
}

/* -------------------------------------------------------------- parsing -- */

static uint16_t	rd16(const uint8_t *p)
{
	return ((uint16_t)((p[0] << 8) | p[1]));
}

static int	same_ip(const uint8_t *raw, struct in_addr ip)
{
	return (memcmp(raw, &ip.s_addr, 4) == 0);
}

/* TCP reply: its source port is the port we probed, its dest port is our source port */
static t_result	parse_tcp(const uint8_t *tcp, size_t len, const t_probe *p)
{
	uint8_t	flags;

	if (p->scan == SCAN_UDP || len < 14)
		return (RES_NONE);
	if (rd16(tcp) != p->dport || rd16(tcp + 2) != p->sport)
		return (RES_NONE);
	flags = tcp[13];
	if (p->scan == SCAN_SYN)
	{
		if ((flags & F_SYN) && (flags & F_ACK))
			return (RES_OPEN);
		if (flags & F_RST)
			return (RES_CLOSED);
	}
	else if (p->scan == SCAN_ACK)
	{
		if (flags & F_RST)
			return (RES_UNFILTERED);
	}
	else if (flags & F_RST)		/* NULL, FIN, XMAS */
		return (RES_CLOSED);
	return (RES_NONE);
}

static t_result	parse_udp(const uint8_t *udp, size_t len, const t_probe *p)
{
	if (p->scan != SCAN_UDP || len < 8)
		return (RES_NONE);
	if (rd16(udp) != p->dport || rd16(udp + 2) != p->sport)
		return (RES_NONE);
	return (RES_OPEN);
}

/* ICMP error: the payload holds the IP header + first bytes of OUR original probe */
static t_result	parse_icmp(const uint8_t *icmp, size_t len, const t_probe *p)
{
	const uint8_t	*in;
	size_t			inlen, ihl;
	uint8_t			code, want_proto;

	if (len < 8 + 20 || icmp[0] != 3)		/* type 3 = destination unreachable */
		return (RES_NONE);
	code = icmp[1];
	in = icmp + 8;
	inlen = len - 8;
	if ((in[0] >> 4) != 4)
		return (RES_NONE);
	ihl = (size_t)(in[0] & 0x0F) * 4;
	if (ihl < 20 || inlen < ihl + 4)
		return (RES_NONE);
	want_proto = (p->scan == SCAN_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
	if (in[9] != want_proto || !same_ip(in + 12, p->src) || !same_ip(in + 16, p->dst))
		return (RES_NONE);
	if (rd16(in + ihl) != p->sport || rd16(in + ihl + 2) != p->dport)
		return (RES_NONE);
	if (p->scan == SCAN_UDP && code == 3)	/* port unreachable = closed */
		return (RES_CLOSED);
	if (code == 1 || code == 2 || code == 3 || code == 9 || code == 10 || code == 13)
		return (RES_FILTERED);
	return (RES_NONE);
}

/* `ip` points at the IP header (link header already skipped). Never reads past `len`. */
t_result	parse_reply(const uint8_t *ip, size_t len, const t_probe *p)
{
	size_t	ihl;

	if (!ip || !p || len < 20 || (ip[0] >> 4) != 4)
		return (RES_NONE);
	ihl = (size_t)(ip[0] & 0x0F) * 4;
	if (ihl < 20 || len < ihl)
		return (RES_NONE);
	if (ip[9] == IPPROTO_ICMP)
		return (parse_icmp(ip + ihl, len - ihl, p));
	if (!same_ip(ip + 12, p->dst))		/* TCP/UDP replies must come from the target */
		return (RES_NONE);
	if (ip[9] == IPPROTO_TCP)
		return (parse_tcp(ip + ihl, len - ihl, p));
	if (ip[9] == IPPROTO_UDP)
		return (parse_udp(ip + ihl, len - ihl, p));
	return (RES_NONE);
}

/* -------------------------------------------------------------- waiting -- */

static long	elapsed_ms(const struct timespec *start)
{
	struct timespec	now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return ((now.tv_sec - start->tv_sec) * 1000L + (now.tv_nsec - start->tv_nsec) / 1000000L);
}

/* Handle every packet currently available. Returns 1 if one answers the probe
** (stored in *out), 0 if none does, -1 on a pcap error. */
static int	drain_packets(t_scanner *sc, const t_probe *p, t_result *out)
{
	struct pcap_pkthdr	*hdr;
	const u_char		*data;
	t_result			res;
	int					rc;

	while ((rc = pcap_next_ex(sc->handle, &hdr, &data)) == 1)
	{
		if (hdr->caplen <= sc->link_len)
			continue ;
		res = parse_reply(data + sc->link_len, hdr->caplen - sc->link_len, p);
		if (res != RES_NONE)
		{
			*out = res;
			return (1);
		}
	}
	if (rc < 0)
		return (fprintf(stderr, "ft_nmap: pcap: %s\n", pcap_geterr(sc->handle)), -1);
	return (0);
}

/* Wait until a packet answers the probe or `timeout_ms` expires.
** Returns 0 (with *out = RES_NONE on timeout) or -1 on a pcap error. */
int	wait_reply(t_scanner *sc, const t_probe *p, int timeout_ms, t_result *out)
{
	struct timespec	start;
	struct pollfd	pfd;
	long			left;
	int				ret;

	*out = RES_NONE;
	clock_gettime(CLOCK_MONOTONIC, &start);
	pfd.fd = sc->fd;
	pfd.events = POLLIN;
	while ((left = timeout_ms - elapsed_ms(&start)) > 0)
	{
		if ((ret = drain_packets(sc, p, out)) != 0)
			return (ret < 0 ? -1 : 0);
		if (sc->fd >= 0)
			poll(&pfd, 1, left > PCAP_READ_MS ? PCAP_READ_MS : (int)left);
		else
			usleep(1000);
	}
	return (drain_packets(sc, p, out) < 0 ? -1 : 0);	/* last look before giving up */
}
