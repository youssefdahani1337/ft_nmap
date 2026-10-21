#include "../includes/threads.h"

/* Take the next job under the lock. Returns its index, or -1 when there is
** nothing left or another worker failed. */
static long	take_job(t_job_ctx *ctx)
{
	long	job = -1;

	pthread_mutex_lock(&ctx->lock);
	if (!ctx->error && ctx->next_job < ctx->nb_jobs)
		job = (long)ctx->next_job++;
	pthread_mutex_unlock(&ctx->lock);
	return (job);
}

static void	set_error(t_job_ctx *ctx)
{
	pthread_mutex_lock(&ctx->lock);
	ctx->error = 1;
	pthread_mutex_unlock(&ctx->lock);
}

/* Job j = port index j / nb_scans, scan j % nb_scans: every scan of a port is
** queued together, so a port's results are complete early. */
static void	*worker(void *arg)
{
	t_worker	*w = arg;
	t_job_ctx	*ctx = w->ctx;
	long		job;
	int			port_i, slot;
	t_result	res;

	if (!w->ready && scanner_init(&w->sc, w->dst, w->sport_base, w->sport_count) < 0)
	{
		set_error(ctx);
		return (NULL);
	}
	w->ready = 1;
	while ((job = take_job(ctx)) >= 0)
	{
		port_i = (int)(job / ctx->nb_scans);
		slot = ctx->scan_slot[job % ctx->nb_scans];
		if (scan_port(&w->sc, ctx->cfg->ports[port_i], g_scan_order[slot], &res) < 0)
		{
			set_error(ctx);
			break ;
		}
		ctx->results[port_i].res[slot] = res;
	}
	scanner_close(&w->sc);		/* closed by its own thread too: see open_workers() */
	w->ready = 0;
	return (NULL);
}

static void	init_ctx(t_job_ctx *ctx, const t_nmap *cfg, t_port_result *results)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->cfg = cfg;
	ctx->results = results;
	for (int s = 0; s < NB_SCAN_TYPES; s++)
		if (cfg->scans & g_scan_order[s])
			ctx->scan_slot[ctx->nb_scans++] = s;
	ctx->nb_jobs = (size_t)cfg->nb_ports * (size_t)ctx->nb_scans;
	for (int i = 0; i < cfg->nb_ports; i++)
	{
		results[i].port = cfg->ports[i];
		for (int s = 0; s < NB_SCAN_TYPES; s++)
			results[i].res[s] = RES_NONE;
	}
}

/* Never more workers than jobs; speedup 0 still means one worker (the main thread). */
static int	worker_count(const t_nmap *cfg, size_t nb_jobs)
{
	size_t	n = cfg->speedup > 0 ? (size_t)cfg->speedup : 1;

	if (n > nb_jobs)
		n = nb_jobs;
	return ((int)n);
}

static void	close_workers(t_worker *w, int n)
{
	for (int i = 0; i < n; i++)
		if (w[i].ready)
			scanner_close(&w[i].sc);
	free(w);
}

/* Opening (and closing) a pcap capture ring costs ~20ms of kernel waiting, so
** 250 scanners opened one after the other would take seconds: each thread opens
** and closes its own, in parallel. Only worker 0 is opened here, before any
** thread starts, so the usual failure (not root) prints a single message. */
static t_worker	*open_workers(t_job_ctx *ctx, struct in_addr dst, int n)
{
	t_worker	*w;
	uint16_t	span = (uint16_t)((SPORT_LAST - SPORT_FIRST + 1) / n);

	w = calloc((size_t)n, sizeof(*w));
	if (!w)
		return (perror("ft_nmap: calloc"), NULL);
	for (int i = 0; i < n; i++)
	{
		w[i].ctx = ctx;
		w[i].dst = dst;
		w[i].sport_base = (uint16_t)(SPORT_FIRST + i * span);
		w[i].sport_count = span;
	}
	if (scanner_init(&w[0].sc, dst, w[0].sport_base, span) < 0)
		return (free(w), NULL);
	w[0].ready = 1;
	return (w);
}

/* Scan every port of cfg with every requested scan, against one target, using
** cfg->speedup threads (0 = in the calling thread). Fills results[nb_ports].
** Returns 0, or -1 on error (everything is closed and freed either way). */
int	run_scan(const t_nmap *cfg, struct in_addr dst, t_port_result *results)
{
	t_job_ctx	ctx;
	t_worker	*w;
	int			n, started = 0;

	init_ctx(&ctx, cfg, results);
	if (ctx.nb_jobs == 0)
		return (0);
	n = worker_count(cfg, ctx.nb_jobs);
	if (pthread_mutex_init(&ctx.lock, NULL) != 0)
		return (fprintf(stderr, "ft_nmap: pthread_mutex_init failed\n"), -1);
	w = open_workers(&ctx, dst, n);
	if (!w)
		return (pthread_mutex_destroy(&ctx.lock), -1);
	if (cfg->speedup == 0)
		worker(&w[0]);
	else
	{
		for (; started < n; started++)
			if ((errno = pthread_create(&w[started].tid, NULL, worker, &w[started])) != 0)
			{
				perror("ft_nmap: pthread_create");
				set_error(&ctx);
				break ;
			}
		for (int i = 0; i < started; i++)
			pthread_join(w[i].tid, NULL);
	}
	close_workers(w, n);
	pthread_mutex_destroy(&ctx.lock);
	return (ctx.error ? -1 : 0);
}
