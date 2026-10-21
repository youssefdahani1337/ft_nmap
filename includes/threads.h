#ifndef THREADS_H
# define THREADS_H

# include "scan.h"
# include <pthread.h>

# define SPORT_FIRST	33000	/* source ports used by our probes: */
# define SPORT_LAST		64999	/* split into one range per thread */

/* Results of one port, one slot per scan type (indexed like g_scan_order).
** Slots of scans that were not requested stay RES_NONE. */
typedef struct s_port_result
{
	uint16_t	port;
	t_result	res[NB_SCAN_TYPES];
}	t_port_result;

/* Shared by every worker. Only next_job and error are shared writes, both
** under `lock`. Each job writes its own results slot, so that needs no lock. */
typedef struct s_job_ctx
{
	const t_nmap	*cfg;
	t_port_result	*results;
	int				scan_slot[NB_SCAN_TYPES];	/* requested scans, as g_scan_order indexes */
	int				nb_scans;
	size_t			nb_jobs;					/* nb_ports * nb_scans */
	size_t			next_job;
	int				error;						/* set by a failing worker: everyone stops */
	pthread_mutex_t	lock;
}	t_job_ctx;

typedef struct s_worker
{
	t_job_ctx		*ctx;
	t_scanner		sc;
	int				ready;			/* sc already opened (worker 0, by run_scan) */
	struct in_addr	dst;
	uint16_t		sport_base;
	uint16_t		sport_count;
	pthread_t		tid;
}	t_worker;

/* threads.c */
int	run_scan(const t_nmap *cfg, struct in_addr dst, t_port_result *results);

#endif
