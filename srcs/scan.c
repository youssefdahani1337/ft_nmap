#include "../includes/scan.h"

const char	*result_name(t_result r)
{
	switch (r)
	{
	case RES_OPEN:			return ("Open");
	case RES_CLOSED:		return ("Closed");
	case RES_FILTERED:		return ("Filtered");
	case RES_UNFILTERED:	return ("Unfiltered");
	case RES_OPEN_FILTERED:	return ("Open|Filtered");
	default:				return ("?");
	}
}

/* Each new probe gets its own source port, so a late reply to an old probe
** can never be mistaken for the answer to the current one. */
static uint16_t	next_sport(t_scanner *sc)
{
	uint16_t	s = sc->next_sport;

	sc->next_sport = (s >= sc->last_port) ? sc->base_port : (uint16_t)(s + 1);
	return (s);
}

/* What it means when NOTHING came back, per scan type. */
static t_result	no_reply_result(t_scan_type scan)
{
	if (scan == SCAN_SYN || scan == SCAN_ACK)
		return (RES_FILTERED);
	return (RES_OPEN_FILTERED);		/* NULL, FIN, XMAS, UDP */
}

/* Probe ONE port with ONE scan type. Returns 0 and sets *out, or -1 on error.
** Retransmissions reuse the same source port. */
int	scan_port(t_scanner *sc, uint16_t dport, t_scan_type scan, t_result *out)
{
	t_probe	p;
	uint8_t	buf[PROBE_BUF_LEN];
	size_t	len;
	int		sock;

	p.src = sc->src;
	p.dst = sc->dst;
	p.sport = next_sport(sc);
	p.dport = dport;
	p.scan = scan;
	sock = (scan == SCAN_UDP) ? sc->udp_sock : sc->tcp_sock;
	for (int attempt = 0; attempt <= SCAN_RETRIES; attempt++)
	{
		if (scan == SCAN_UDP)
			len = build_udp(buf, p.src, p.dst, p.sport, p.dport);
		else
			len = build_tcp(buf, p.src, p.dst, p.sport, p.dport, scan);
		if (len == 0 || send_probe(sock, p.dst, buf, len) < 0)
			return (-1);
		if (wait_reply(sc, &p, SCAN_TIMEOUT_MS, out) < 0)
			return (-1);
		if (*out != RES_NONE)
			return (0);
	}
	*out = no_reply_result(scan);
	return (0);
}
