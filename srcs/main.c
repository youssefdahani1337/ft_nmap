#include "../includes/threads.h"
#include <time.h>
#include <sys/time.h>
#include <netdb.h>

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

/* Get service name for a port, or "Unassigned" if not found */
static const char	*get_service_name(uint16_t port)
{
	struct servent	*se;

	se = getservbyport(htons(port), "tcp");
	return (se ? se->s_name : "Unassigned");
}

/* Determine conclusion: Open if any scan says Open, else Filtered if SYN says
** Filtered (SYN is at index 0 in g_scan_order), else Closed. */
static t_result	get_conclusion(const t_port_result *pr)
{
	for (int s = 0; s < NB_SCAN_TYPES; s++)
		if (pr->res[s] == RES_OPEN)
			return (RES_OPEN);
	if (pr->res[0] == RES_FILTERED)
		return (RES_FILTERED);
	return (RES_CLOSED);
}

/* Print one table row with results for all requested scans */
static void	print_port_row(const t_nmap *cfg, const t_port_result *pr, t_result conclusion)
{
	printf("%-6u %-15s", pr->port, get_service_name(pr->port));
	for (int s = 0; s < NB_SCAN_TYPES; s++)
	{
		if (cfg->scans & g_scan_order[s])
		{
			if (pr->res[s] == RES_NONE)
				printf(" %s(-)", scan_name(g_scan_order[s]));
			else
				printf(" %s(%s)", scan_name(g_scan_order[s]), result_name(pr->res[s]));
		}
	}
	printf(" %s\n", result_name(conclusion));
}

/* Print table of ports with the given conclusion status */
static void	print_table(const t_nmap *cfg, const t_port_result *results,
				t_result table_type)
{
	const char	*title = NULL;
	int			header_printed = 0;

	if (table_type == RES_OPEN)
		title = "Open ports:";
	else
		title = "Closed/Filtered/Unfiltered ports:";

	for (int i = 0; i < cfg->nb_ports; i++)
	{
		t_result	conclusion = get_conclusion(&results[i]);

		if ((table_type == RES_OPEN && conclusion == RES_OPEN)
			|| (table_type != RES_OPEN && conclusion != RES_OPEN))
		{
			if (!header_printed)
			{
				printf("%s\n", title);
				printf("Port Service Name (if applicable) Results");
				printf("%*s Conclusion\n", 30, "");
				printf("----------------------------------------------------------------------------\n");
				header_printed = 1;
			}
			print_port_row(cfg, &results[i], conclusion);
		}
	}
	if (header_printed)
		printf("\n");
}

/* Print formatted output tables (Open and Closed/Filtered) */
static void	print_results(const t_nmap *cfg, struct in_addr target, const t_port_result *results)
{
	printf("IP address: %s\n", inet_ntoa(target));
	print_table(cfg, results, RES_OPEN);
	print_table(cfg, results, RES_CLOSED);
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
		printf("Scanning..");
		fflush(stdout);
		start = now_sec();
		ret = run_scan(cfg, cfg->targets[t].addr, results);
		if (ret == 0)
		{
			printf("\n");
			printf("Scan took %.5f secs\n", now_sec() - start);
			print_results(cfg, cfg->targets[t].addr, results);
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
