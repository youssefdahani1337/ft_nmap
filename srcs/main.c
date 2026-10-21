#include "../includes/threads.h"
#include <time.h>
#include <sys/time.h>

static void	print_config(const t_nmap *cfg)
{
	printf("Scan Configurations\n");
	for (size_t i = 0; i < cfg->nb_targets; i++)
		printf("Target Ip-Address : %s (%s)\n", inet_ntoa(cfg->targets[i].addr), cfg->targets[i].name);
	printf("No of Ports to scan : %d\n", cfg->nb_ports);
	printf("Scans to be performed :");
	for (int i = 0; i < NB_SCAN_TYPES; i++)
		if (cfg->scans & g_scan_order[i])
			printf(" %s", scan_name(g_scan_order[i]));
	printf("\nNo of threads : %d\n", cfg->speedup);
}

static double	now_sec(void)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);
	return ((double)tv.tv_sec + (double)tv.tv_usec / 1e6);
}

/* TEMPORARY raw output (one "PORT SYN(Open) ..." line per port), replaced by
** the Open / Closed tables in the output step. */
static void	print_raw(const t_nmap *cfg, const t_port_result *results)
{
	for (int i = 0; i < cfg->nb_ports; i++)
	{
		printf("%-6u", results[i].port);
		for (int s = 0; s < NB_SCAN_TYPES; s++)
			if (cfg->scans & g_scan_order[s])
				printf(" %s(%s)", scan_name(g_scan_order[s]), result_name(results[i].res[s]));
		printf("\n");
	}
}

static int	scan_all(const t_nmap *cfg)
{
	t_port_result	*results;
	double			start;
	int				ret = 0;

	results = calloc((size_t)cfg->nb_ports, sizeof(*results));
	if (!results)
		return (perror("ft_nmap: calloc"), -1);
	for (size_t t = 0; t < cfg->nb_targets && ret == 0; t++)
	{
		printf("Scanning %s (%s)..\n", inet_ntoa(cfg->targets[t].addr), cfg->targets[t].name);
		fflush(stdout);
		start = now_sec();
		ret = run_scan(cfg, cfg->targets[t].addr, results);
		if (ret == 0)
		{
			printf("Scan took %.5f secs\n", now_sec() - start);
			print_raw(cfg, results);
		}
	}
	free(results);
	return (ret);
}

int	main(int argc, char **argv)
{
	t_nmap	cfg;
	int		ret = 0;

	srand((unsigned)time(NULL) ^ (unsigned)getpid());
	parse_args(argc, argv, &cfg);
	print_config(&cfg);
	/* Test hook: tests/test_parse.sh sets it to check parsing without root */
	if (!getenv("FT_NMAP_PARSE_ONLY"))
		ret = scan_all(&cfg);
	free_config(&cfg);
	return (ret < 0 ? EXIT_FAILURE_CODE : 0);
}
