#ifndef FT_NMAP_H
# define FT_NMAP_H

# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <strings.h>
# include <ctype.h>
# include <errno.h>
# include <stdint.h>
# include <stddef.h>
# include <getopt.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>

# define MAX_PORTS          1024
# define MAX_THREADS        250
# define DEFAULT_PORT_FIRST 1
# define DEFAULT_PORT_LAST  1024
# define EXIT_FAILURE_CODE  255

/* Scan types are bit flags, so several can be combined: SCAN_SYN | SCAN_UDP */
typedef enum e_scan_type
{
	SCAN_SYN  = 1 << 0,
	SCAN_NULL = 1 << 1,
	SCAN_ACK  = 1 << 2,
	SCAN_FIN  = 1 << 3,
	SCAN_XMAS = 1 << 4,
	SCAN_UDP  = 1 << 5
}	t_scan_type;

# define SCAN_ALL (SCAN_SYN | SCAN_NULL | SCAN_ACK | SCAN_FIN | SCAN_XMAS | SCAN_UDP)
# define NB_SCAN_TYPES 6

/* Display order of the scans; results are stored at these indexes */
extern const t_scan_type	g_scan_order[NB_SCAN_TYPES];

/* One scan target (name as typed by the user + resolved IPv4) */
typedef struct s_target
{
	char			*name;
	struct in_addr	addr;
}	t_target;

/* Everything the scan engine needs, filled by parse_args() */
typedef struct s_nmap
{
	const char	*ip_arg;				/* value of --ip   (points into argv) */
	const char	*file_arg;				/* value of --file (points into argv) */
	t_target	*targets;				/* heap array, freed by free_config() */
	size_t		nb_targets;
	uint16_t	ports[MAX_PORTS];		/* unique, sorted ascending */
	int			nb_ports;
	uint8_t		scans;					/* OR of t_scan_type flags */
	int			speedup;				/* number of threads (0 = no thread) */
}	t_nmap;

/* parse_args.c */
void		parse_args(int argc, char **argv, t_nmap *cfg);
void		free_config(t_nmap *cfg);
void		print_usage(FILE *fd);
void		exit_error(int code);
const char	*scan_name(t_scan_type type);

#endif
