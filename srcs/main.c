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

static int	now_sec(double *seconds)
{
	struct timespec	ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (perror("ft_nmap: clock_gettime"), -1);
	*seconds = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
	return (0);
}

/* Get service name for a port, or "Unassigned" if not found */
static const char	*get_service_name(uint16_t port, const t_nmap *cfg)
{
	struct servent	*se;
	const char	*proto = (cfg->scans == SCAN_UDP) ? "udp" : "tcp";

	se = getservbyport(htons(port), proto);
	return (se ? se->s_name : "Unassigned");
}

/* Conclusion priority is Open > Unfiltered > Filtered > Open|Filtered > Closed. */
static t_result	get_conclusion(const t_port_result *pr)
{
	for (int s = 0; s < NB_SCAN_TYPES; s++)
		if (pr->res[s] == RES_OPEN)
			return (RES_OPEN);
	for (int s = 0; s < NB_SCAN_TYPES; s++)
		if (pr->res[s] == RES_UNFILTERED)
			return (RES_UNFILTERED);
	for (int s = 0; s < NB_SCAN_TYPES; s++)
		if (pr->res[s] == RES_FILTERED)
			return (RES_FILTERED);
	for (int s = 0; s < NB_SCAN_TYPES; s++)
		if (pr->res[s] == RES_OPEN_FILTERED)
			return (RES_OPEN_FILTERED);
	return (RES_CLOSED);
}

/* Print one table row with results for all requested scans */
static void	print_port_row(const t_nmap *cfg, const t_port_result *pr, t_result conclusion)
{
	printf("%-6u %-15s", pr->port, get_service_name(pr->port, cfg));
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
	double			finish;
	int				ret = 0;

	results = calloc((size_t)cfg->nb_ports, sizeof(*results));
	if (!results)
		return (perror("ft_nmap: calloc"), -1);
	for (size_t t = 0; t < cfg->nb_targets && ret == 0; t++)
	{
		printf("Scanning..");
		fflush(stdout);
		if (now_sec(&start) < 0)
		{
			ret = -1;
			break ;
		}
		ret = run_scan(cfg, cfg->targets[t].addr, results);
		if (ret == 0)
		{
			if (now_sec(&finish) < 0)
				ret = -1;
			else
			{
				printf("\n");
				printf("Scan took %.5f secs\n", finish - start);
				print_results(cfg, cfg->targets[t].addr, results);
			}
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
