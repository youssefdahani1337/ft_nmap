#include "../includes/ft_nmap.h"

static const struct
{
	const char	*name;
	t_scan_type	flag;
}	g_scans[] = {
	{"SYN", SCAN_SYN},
	{"NULL", SCAN_NULL},
	{"ACK", SCAN_ACK},
	{"FIN", SCAN_FIN},
	{"XMAS", SCAN_XMAS},
	{"UDP", SCAN_UDP},
	{NULL, 0}
};

const t_scan_type	g_scan_order[NB_SCAN_TYPES] = {
	SCAN_SYN, SCAN_NULL, SCAN_FIN, SCAN_XMAS, SCAN_ACK, SCAN_UDP
};

const char	*scan_name(t_scan_type type)
{
	for (int i = 0; g_scans[i].name; i++)
		if (g_scans[i].flag == type)
			return (g_scans[i].name);
	return ("?");
}

void	print_usage(FILE *fd)
{
	fputs("Help Screen\n"
		"ft_nmap [OPTIONS]\n"
		" --help    Print this help screen\n"
		" --ports   ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n"
		" --ip      ip addresses to scan in dot format\n"
		" --file    File name containing IP addresses to scan,\n"
		" --speedup [250 max] number of parallel threads to use\n"
		" --scan    SYN/NULL/FIN/XMAS/ACK/UDP\n", fd);
}

/* Single exit point for every error: same message, same code. */
void	exit_error(int code)
{
	fputs("Try './ft_nmap --help' for more information.\n", stderr);
	exit(code);
}

void	free_config(t_nmap *cfg)
{
	for (size_t i = 0; i < cfg->nb_targets; i++)
		free(cfg->targets[i].name);
	free(cfg->targets);
	cfg->targets = NULL;
	cfg->nb_targets = 0;
}

/* Free what was allocated so far, then leave with the error code. */
static void	fail(t_nmap *cfg)
{
	free_config(cfg);
	exit_error(EXIT_FAILURE_CODE);
}

/* Strict number parser: digits only, within [min, max]. Returns 0 on success. */
static int	parse_long(const char *s, long min, long max, long *out)
{
	char	*end;
	long	val;

	if (!s || !isdigit((unsigned char)*s))
		return (-1);
	errno = 0;
	val = strtol(s, &end, 10);
	if (errno || *end != '\0' || val < min || val > max)
		return (-1);
	*out = val;
	return (0);
}

/* ---------------------------------------------------------------- ports -- */

/* Accepts "80", "1-10", "1,2,3", "1,5-15". Duplicates removed, result sorted. */
static int	parse_ports(const char *arg, t_nmap *cfg)
{
	unsigned char	seen[65536] = {0};
	char			*copy, *tok, *save = NULL, *dash;
	long			lo = 0, hi = 0;
	int				count = 0;

	copy = strdup(arg);
	if (!copy)
		return (perror("ft_nmap: strdup"), -1);
	for (tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save))
	{
		dash = strchr(tok, '-');
		if (dash)
		{
			*dash = '\0';
			if (parse_long(tok, 1, 65535, &lo) || parse_long(dash + 1, 1, 65535, &hi) || lo > hi)
				goto bad;
		}
		else if (parse_long(tok, 1, 65535, &lo))
			goto bad;
		else
			hi = lo;
		for (long p = lo; p <= hi; p++)
			if (!seen[p])
			{
				seen[p] = 1;
				count++;
			}
	}
	if (count == 0)
		goto bad;
	if (count > MAX_PORTS)
	{
		fprintf(stderr, "ft_nmap: too many ports (%d), maximum is %d\n", count, MAX_PORTS);
		free(copy);
		return (-1);
	}
	cfg->nb_ports = 0;
	for (int p = 1; p <= 65535; p++)
		if (seen[p])
			cfg->ports[cfg->nb_ports++] = (uint16_t)p;
	free(copy);
	return (0);
bad:
	fprintf(stderr, "ft_nmap: invalid port specification '%s'\n", arg);
	free(copy);
	return (-1);
}

/* ---------------------------------------------------------------- scans -- */

/* Accepts "SYN", "SYN/UDP", "syn,fin,xmas", case-insensitive. */
static int	parse_scans(const char *arg, t_nmap *cfg)
{
	char	*copy, *tok, *save = NULL;
	int		i, found;

	copy = strdup(arg);
	if (!copy)
		return (perror("ft_nmap: strdup"), -1);
	for (tok = strtok_r(copy, "/, ", &save); tok; tok = strtok_r(NULL, "/, ", &save))
	{
		found = 0;
		for (i = 0; g_scans[i].name; i++)
			if (strcasecmp(tok, g_scans[i].name) == 0)
			{
				cfg->scans |= g_scans[i].flag;
				found = 1;
				break ;
			}
		if (!found)
		{
			fprintf(stderr, "ft_nmap: unknown scan type '%s'\n", tok);
			free(copy);
			return (-1);
		}
	}
	free(copy);
	if (cfg->scans == 0)
		return (fprintf(stderr, "ft_nmap: empty scan type\n"), -1);
	return (0);
}

/* -------------------------------------------------------------- targets -- */

/* Resolve one IPv4 address/hostname and append it. 0 = ok (or skipped), -1 = fatal */
static int	add_target(t_nmap *cfg, const char *name)
{
	struct addrinfo	hints, *res = NULL;
	t_target		*tmp;
	int				ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(name, NULL, &hints, &res);
	if (ret != 0 || !res)
	{
		fprintf(stderr, "ft_nmap: warning: cannot resolve '%s' (%s), skipped\n", name, gai_strerror(ret));
		return (0);
	}
	tmp = realloc(cfg->targets, sizeof(t_target) * (cfg->nb_targets + 1));
	if (!tmp)
		return (freeaddrinfo(res), perror("ft_nmap: realloc"), -1);
	cfg->targets = tmp;
	cfg->targets[cfg->nb_targets].name = strdup(name);
	if (!cfg->targets[cfg->nb_targets].name)
		return (freeaddrinfo(res), perror("ft_nmap: strdup"), -1);
	cfg->targets[cfg->nb_targets].addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
	cfg->nb_targets++;
	freeaddrinfo(res);
	return (0);
}

/* One target per line. Blank lines and lines starting with '#' are ignored. */
static int	load_targets_file(t_nmap *cfg, const char *path)
{
	FILE	*fp;
	char	*line = NULL, *start, *end;
	size_t	cap = 0;
	int		ret = 0;

	fp = fopen(path, "r");
	if (!fp)
	{
		fprintf(stderr, "ft_nmap: cannot open '%s': %s\n", path, strerror(errno));
		return (-1);
	}
	while (getline(&line, &cap, fp) != -1)
	{
		start = line;
		while (*start && isspace((unsigned char)*start))
			start++;
		end = start + strlen(start);
		while (end > start && isspace((unsigned char)end[-1]))
			*--end = '\0';
		if (*start == '\0' || *start == '#')
			continue ;
		if (add_target(cfg, start) != 0)
		{
			ret = -1;
			break ;
		}
	}
	free(line);
	fclose(fp);
	return (ret);
}

/* ----------------------------------------------------------------- main -- */

void	parse_args(int argc, char **argv, t_nmap *cfg)
{
	static const struct option	long_opts[] = {
		{"help", no_argument, NULL, 'h'},
		{"ports", required_argument, NULL, 'p'},
		{"port", required_argument, NULL, 'p'},	/* alias: the subject uses both */
		{"ip", required_argument, NULL, 'i'},
		{"file", required_argument, NULL, 'f'},
		{"speedup", required_argument, NULL, 's'},
		{"scan", required_argument, NULL, 'S'},
		{NULL, 0, NULL, 0}
	};
	int		opt;
	long	val;
	int		ports_given = 0;

	memset(cfg, 0, sizeof(*cfg));
	optind = 1;
	opterr = 1;
	while ((opt = getopt_long(argc, argv, "hp:i:f:s:S:", long_opts, NULL)) != -1)
	{
		switch (opt)
		{
		case 'h':
			print_usage(stdout);
			exit(0);
		case 'p':
			if (parse_ports(optarg, cfg) != 0)
				fail(cfg);
			ports_given = 1;
			break ;
		case 'i':
			cfg->ip_arg = optarg;
			break ;
		case 'f':
			cfg->file_arg = optarg;
			break ;
		case 's':
			if (parse_long(optarg, 0, MAX_THREADS, &val) != 0)
			{
				fprintf(stderr, "ft_nmap: speedup must be a number between 0 and %d\n", MAX_THREADS);
				fail(cfg);
			}
			cfg->speedup = (int)val;
			break ;
		case 'S':
			if (parse_scans(optarg, cfg) != 0)
				fail(cfg);
			break ;
		default:	/* getopt_long already printed the error */
			fail(cfg);
		}
	}
	if (optind < argc)
	{
		fprintf(stderr, "ft_nmap: unexpected argument '%s'\n", argv[optind]);
		fail(cfg);
	}

	/* --ip XOR --file */
	if (!cfg->ip_arg && !cfg->file_arg)
	{
		fprintf(stderr, "ft_nmap: you must give --ip or --file\n");
		fail(cfg);
	}
	if (cfg->ip_arg && cfg->file_arg)
	{
		fprintf(stderr, "ft_nmap: --ip and --file cannot be used at the same time\n");
		fail(cfg);
	}

	/* Defaults */
	if (!ports_given)
		for (int p = DEFAULT_PORT_FIRST; p <= DEFAULT_PORT_LAST; p++)
			cfg->ports[cfg->nb_ports++] = (uint16_t)p;
	if (cfg->scans == 0)
		cfg->scans = SCAN_ALL;

	/* Targets */
	if (cfg->ip_arg)
	{
		if (add_target(cfg, cfg->ip_arg) != 0)
			fail(cfg);
	}
	else if (load_targets_file(cfg, cfg->file_arg) != 0)
		fail(cfg);
	if (cfg->nb_targets == 0)
	{
		fprintf(stderr, "ft_nmap: no valid target to scan\n");
		fail(cfg);
	}
}
