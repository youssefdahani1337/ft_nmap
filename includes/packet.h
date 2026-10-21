#ifndef PACKET_H
# define PACKET_H

# include "ft_nmap.h"
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <unistd.h>

# define TCP_PROBE_LEN	sizeof(struct tcphdr)	/* 20: no options, no payload */
# define UDP_PROBE_LEN	sizeof(struct udphdr)	/* 8:  empty datagram */
# define PROBE_BUF_LEN	64

/* checksum.c part: 16-bit one's complement, result already in network order */
uint16_t	checksum(const void *data, size_t len);
uint16_t	l4_checksum(struct in_addr src, struct in_addr dst, uint8_t proto,
				const void *segment, size_t len);

/* Builders: write the L4 header into buf (>= PROBE_BUF_LEN), return its size,
** or 0 on invalid arguments. The kernel adds the IP header (no IP_HDRINCL). */
size_t		build_tcp(uint8_t *buf, struct in_addr src, struct in_addr dst,
				uint16_t sport, uint16_t dport, t_scan_type scan);
size_t		build_udp(uint8_t *buf, struct in_addr src, struct in_addr dst,
				uint16_t sport, uint16_t dport);

/* Network helpers */
int			get_source_ip(struct in_addr dst, struct in_addr *src);
int			open_raw_socket(int proto);		/* IPPROTO_TCP or IPPROTO_UDP */
int			send_probe(int sock, struct in_addr dst, const uint8_t *buf, size_t len);

#endif
