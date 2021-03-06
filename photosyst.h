/*
** ATOP - System & Process Monitor
**
** The program 'atop' offers the possibility to view the activity of
** the system on system-level as well as process-level.
**
** Include-file describing system-level counters maintained.
** ================================================================
** Author:      Gerlof Langeveld
** E-mail:      gerlof.langeveld@atoptool.nl
** Date:        November 1996
** LINUX-port:  June 2000
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of the GNU General Public License as published by the
** Free Software Foundation; either version 2, or (at your option) any
** later version.
**
** This program is distributed in the hope that it will be useful, but
** WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
** See the GNU General Public License for more details.
*/
#include "netstats.h"

#define	MAXCPUS		2048
#define	MAXDSK		512
#define	MAXLVM		1024
#define	MAXMDD		256
#define	MAXINTF		128

#define	MAXDKNAM	32

/************************************************************************/

struct	memstat {
	count_t	physmem;	/* number of physical pages 	*/
	count_t	freemem;	/* number of free     pages	*/
	count_t	buffermem;	/* number of buffer   pages	*/
	count_t	slabmem;	/* number of slab     pages	*/
	count_t	cachemem;	/* number of cache    pages	*/
	count_t	cachedrt;	/* number of cache    pages (dirty)	*/

	count_t	totswap;	/* number of pages in swap	*/
	count_t	freeswap;	/* number of free swap pages	*/

	count_t	pgscans;	/* number of page scans		*/
	count_t	pgsteal;	/* number of page steals	*/
	count_t	allocstall;	/* try to free pages forced	*/
	count_t	swouts;		/* number of pages swapped out	*/
	count_t	swins;		/* number of pages swapped in	*/

	count_t	commitlim;	/* commit limit in pages	*/
	count_t	committed;	/* number of reserved pages	*/

	count_t	shmem;		/* tot shmem incl. tmpfs (pag)	*/
	count_t	shmrss;		/* resident shared memory (pag)	*/
	count_t	shmswp;		/* swapped shared memory (pag)	*/

	count_t	slabreclaim;	/* reclaimable slab (pages)     */
};

/************************************************************************/

struct	netstat {
	struct ipv4_stats	ipv4;
	struct icmpv4_stats	icmpv4;
	struct udpv4_stats	udpv4;

	struct ipv6_stats	ipv6;
	struct icmpv6_stats	icmpv6;
	struct udpv6_stats	udpv6;

	struct tcp_stats	tcp;
};

/************************************************************************/

struct freqcnt {
        count_t maxfreq;/* frequency in MHz                    */
        count_t cnt;    /* number of clock ticks times state   */
        count_t ticks;  /* number of total clock ticks         */
                        /* if zero, cnt is actul freq          */
};

struct percpu {
	int		cpunr;
	count_t		stime;	/* system  time in clock ticks		*/
	count_t		utime;	/* user    time in clock ticks		*/
	count_t		ntime;	/* nice    time in clock ticks		*/
	count_t		itime;	/* idle    time in clock ticks		*/
	count_t		wtime;	/* iowait  time in clock ticks		*/
	count_t		Itime;	/* irq     time in clock ticks		*/
	count_t		Stime;	/* softirq time in clock ticks		*/
	count_t		steal;	/* steal   time in clock ticks		*/
	count_t		guest;	/* guest   time in clock ticks		*/
        struct freqcnt	freqcnt;/* frequency scaling info  		*/
	count_t		cfuture[1];	/* reserved for future use	*/
};

struct	cpustat {
	count_t	nrcpu;	/* number of cpu's 			*/
	count_t	devint;	/* number of device interrupts 		*/
	count_t	csw;	/* number of context switches		*/
	count_t	nprocs;	/* number of processes started          */
	float	lavg1;	/* load average last    minute          */
	float	lavg5;	/* load average last  5 minutes         */
	float	lavg15;	/* load average last 15 minutes         */
	count_t	cfuture[4];	/* reserved for future use	*/

	struct percpu   all;
	struct percpu   cpu[MAXCPUS];
};

/************************************************************************/

struct	perdsk {
        char	name[MAXDKNAM];	/* empty string for last        */
        count_t	nread;	/* number of read  transfers            */
        count_t	nrsect;	/* number of sectors read               */
        count_t	nwrite;	/* number of write transfers            */
        count_t	nwsect;	/* number of sectors written            */
        count_t	io_ms;	/* number of millisecs spent for I/O    */
        float	busy_pct;	/* absolute %of busy time  */
        count_t	avque;	/* average queue length                 */
	count_t	cfuture[4];	/* reserved for future use	*/
};

struct dskstat {
	int		ndsk;	/* number of physical disks	*/
	int		nmdd;	/* number of md volumes		*/
	int		nlvm;	/* number of logical volumes	*/
	struct perdsk	dsk[MAXDSK];
	struct perdsk	mdd[MAXMDD];
	struct perdsk	lvm[MAXLVM];
};

/************************************************************************/

struct	perintf {
        char	name[16];	/* empty string for last        */

        count_t	rbyte;	/* number of read bytes                 */
        count_t	rpack;	/* number of read packets               */
	count_t rerrs;  /* receive errors                       */
	count_t rdrop;  /* receive drops                        */
	count_t rfifo;  /* receive fifo                         */
	count_t rframe; /* receive framing errors               */
	count_t rcompr; /* receive compressed                   */
	count_t rmultic;/* receive multicast                    */
	count_t	rfuture[4];	/* reserved for future use	*/

        count_t	sbyte;	/* number of written bytes              */
        count_t	spack;	/* number of written packets            */
	count_t serrs;  /* transmit errors                      */
	count_t sdrop;  /* transmit drops                       */
	count_t sfifo;  /* transmit fifo                        */
	count_t scollis;/* collisions                           */
	count_t scarrier;/* transmit carrier                    */
	count_t scompr; /* transmit compressed                  */
	count_t	sfuture[4];	/* reserved for future use	*/

	long 	speed;	/* interface speed in megabits/second	*/
	char	duplex;	/* full duplex (boolean) 		*/
	count_t	cfuture[4];	/* reserved for future use	*/
};

struct intfstat {
	int		nrintf;
	struct perintf	intf[MAXINTF];
};

/************************************************************************/
/*
** experimental stuff for access to local HTTP daemons
*/
#define	HTTPREQ	"GET /server-status?auto HTTP/1.1\nHost: localhost\n\n"

struct wwwstat {
	count_t	accesses;	/* total number of HTTP-requests	*/
	count_t	totkbytes;	/* total kbytes transfer for HTTP-req   */
	count_t	uptime;		/* number of seconds since startup	*/
	int	bworkers;	/* number of busy httpd-daemons		*/
	int	iworkers;	/* number of idle httpd-daemons		*/
};

#if	HTTPSTATS
int	getwwwstat(unsigned short, struct wwwstat *);
#endif
/************************************************************************/

struct	sstat {
	struct cpustat	cpu;
	struct memstat	mem;
	struct netstat	net;
	struct intfstat	intf;
	struct dskstat  dsk;

	struct wwwstat	www;
};

/*
** prototypes
*/
void	photosyst (struct sstat *);
void	deviatsyst(struct sstat *, struct sstat *, struct sstat *);
void	totalsyst (char,           struct sstat *, struct sstat *);
