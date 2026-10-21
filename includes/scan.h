#ifndef FT_SCAN_H
# define FT_SCAN_H

# include "packet.h"
# include <pcap/pcap.h>

# define SCAN_TIMEOUT_MS	1000	/* wait for a reply this long per attempt */
# define SCAN_RETRIES		1		/* extra attempts after the first one */
# define SNAPLEN			256		/* enough for eth + ip + icmp + inner ip + l4 */
# define PCAP_READ_MS		50		/* pcap read timeout (keeps loops responsive) */
# define PCAP_BUFFER_SIZE	(256 * 1024)	/* per handle: 250 threads x 2MB default is too much */

typedef enum e_result
{
	RES_NONE = 0,		/* "no usable reply yet" (internal) */
	RES_OPEN,
	RES_CLOSED,
	RES_FILTERED,
	RES_UNFILTERED,
	RES_OPEN_FILTERED
}	t_result;

/* Everything needed to recognise the answer to ONE probe */
typedef struct s_probe
{
	struct in_addr	src;
	struct in_addr	dst;
	uint16_t		sport;		/* our source port (unique per probe) */
	uint16_t		dport;		/* scanned port */
	t_scan_type		scan;
}	t_probe;

/* One scanner = one pcap handle + raw sockets. One per thread. */
typedef struct s_scanner
{
	pcap_t			*handle;
	int				fd;				/* selectable fd of the handle, for poll() */
	size_t			link_len;		/* size of the link-layer header */
	int				tcp_sock;
	int				udp_sock;
	struct in_addr	src;
	struct in_addr	dst;
	uint16_t		base_port;		/* this scanner's source ports: */
	uint16_t		last_port;		/* [base_port, last_port] */
	uint16_t		next_sport;
	char			dev[64];
}	t_scanner;

/* capture.c */
int			scanner_init(t_scanner *sc, struct in_addr dst, uint16_t sport_base,
				uint16_t sport_count);
void		scanner_close(t_scanner *sc);
t_result	parse_reply(const uint8_t *ip, size_t len, const t_probe *p);
int			wait_reply(t_scanner *sc, const t_probe *p, int timeout_ms, t_result *out);

/* scan.c */
int			scan_port(t_scanner *sc, uint16_t dport, t_scan_type scan, t_result *out);
const char	*result_name(t_result r);

#endif
