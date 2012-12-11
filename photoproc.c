/*
** ATOP - System & Process Monitor 
** 
** The program 'atop' offers the possibility to view the activity of
** the system on system-level as well as process-/thread-level.
** 
** This source-file contains functions to read the process-administration
** of every running process from kernel-space and extract the required
** activity-counters.
** ==========================================================================
** Author:      Gerlof Langeveld
** E-mail:      gerlof.langeveld@atoptool.nl
** Date:        November 1996
** LINUX-port:  June 2000
** --------------------------------------------------------------------------
** Copyright (C) 2000-2010 Gerlof Langeveld
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
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
** --------------------------------------------------------------------------
**
** $Log: photoproc.c,v $
** Revision 1.33  2010/04/23 12:19:35  gerlof
** Modified mail-address in header.
**
** Revision 1.32  2009/11/27 13:44:00  gerlof
** euid, suid, fsuid, egid, sgid and fsgid also registered.
**
** Revision 1.31  2008/03/06 08:38:14  gerlof
** Register/show ppid of a process.
**
** Revision 1.30  2008/01/18 07:36:29  gerlof
** Gather information about the state of the individual threads.
**
** Revision 1.29  2007/11/05 12:26:10  gerlof
** Detect disappearing /proc/stat file  when process exits
** (credits: Rene Rebe).
**
** Revision 1.28  2007/03/27 10:53:59  gerlof
** Bug-solution: only allow IOSTAT when patches are not installed.
**
** Revision 1.27  2007/03/21 14:21:37  gerlof
** Handle io counters maintained from 2.6.20
**
** Revision 1.26  2007/02/13 10:32:34  gerlof
** Removal of external declarations.
**
** Revision 1.25  2007/01/15 09:00:14  gerlof
** Add new function to count actual number of processes.
**
** Revision 1.24  2006/02/07 06:47:35  gerlof
** Removed swap-counter.
**
** Revision 1.23  2005/10/21 09:49:57  gerlof
** Per-user accumulation of resource consumption.
**
** Revision 1.22  2004/12/14 15:05:58  gerlof
** Implementation of patch-recognition for disk and network-statistics.
**
** Revision 1.21  2004/09/23 09:07:49  gerlof
** Solved segmentation fault by checking tval.
**
** Revision 1.20  2004/09/08 06:01:01  gerlof
** Correct the priority of a process by adding 100 (the kernel
** subtracts 100 when showing the value via /proc).
**
** Revision 1.19  2004/09/02 10:49:45  gerlof
** Added sleep-average to process-info.
**
** Revision 1.18  2004/08/31 09:51:36  gerlof
** Gather information about underlying threads.
**
** Revision 1.17  2003/07/07 09:26:59  gerlof
** Cleanup code (-Wall proof).
**
** Revision 1.16  2003/06/30 11:30:43  gerlof
** Enlarge counters to 'long long'.
**
** Revision 1.15  2003/02/06 12:09:23  gerlof
** Exchange tab-character in command-line by space.
**
** Revision 1.14  2003/01/24 14:19:39  gerlof
** Exchange newline byte in command-line by space.
**
** Revision 1.13  2003/01/17 14:21:41  root
** Change-directory to /proc to optimize opening /proc-files
** via relative path-names i.s.o. absolute path-names.
**
** Revision 1.12  2003/01/17 07:31:29  gerlof
** Store the full command-line for every process.
**
** Revision 1.11  2003/01/06 13:03:09  gerlof
** Improved command-name parsing (command-names containing a close-bracket
** were not parsed correctly).
**
** Revision 1.10  2002/10/03 11:12:39  gerlof
** Modify (effective) uid/gid to real uid/gid.
**
** Revision 1.9  2002/07/24 11:13:31  gerlof
** Changed to ease porting to other UNIX-platforms.
**
** Revision 1.8  2002/07/08 09:27:45  gerlof
** Avoid buffer overflow during sprintf by using snprintf.
**
** Revision 1.7  2002/01/22 13:39:53  gerlof
** Support for number of cpu's.
**
** Revision 1.6  2001/11/22 08:33:43  gerlof
** Add priority per process.
**
** Revision 1.5  2001/11/13 08:26:15  gerlof
** Small bug-fixes.
**
** Revision 1.4  2001/11/07 09:18:43  gerlof
** Use /proc instead of /dev/kmem for process-level statistics.
**
** Revision 1.3  2001/10/04 13:57:34  gerlof
** Explicit include of sched.h (i.s.o. linux/sched.h via linux/mm.h).
**
** Revision 1.2  2001/10/04 08:47:26  gerlof
** Improved verification of kernel-symbol addresses
**
** Revision 1.1  2001/10/02 10:43:29  gerlof
** Initial revision
**
*/

static const char rcsid[] = "$Id: photoproc.c,v 1.33 2010/04/23 12:19:35 gerlof Exp $";

#include <sys/types.h>
#include <sys/param.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#ifdef FREEBSD 
 #include <kvm.h>
 #include <sys/sysctl.h>
 #include <sys/user.h>
 extern  kvm_t *kd;
 extern char	filterkernel;
#endif

#include "atop.h"
#include "photoproc.h"

#define	SCANSTAT 	"%c   %d   %*d  %*d  %*d  %*d  "	\
			"%*d  %lld %*d  %lld %*d  %lld "	\
			"%lld %*d  %*d  %d   %d   %*d  "	\
			"%*d  %ld %lld %lld %*d  %*d  "	\
			"%*d  %*d  %*d  %*d  %*d  %*d  " 	\
			"%*d  %*d  %*d  %*d  %*d  %*d  "	\
			"%d   %d   %d "

/* ATOP-extension line of /proc/pid/stat */
#define ATOPSTAT	"%lld %llu %lld %llu %lld %llu %lld %llu "	\
			"%lld %llu %lld %llu %lld %lld"

#ifdef linux
static int	procstat(struct tstat *, unsigned long long, char);
static void	proccmd(struct tstat *);
static int	procstatus(struct tstat *);
static int	procio(struct tstat *);
#elif defined(FREEBSD)
static void	proccmd(struct tstat *curtask, struct kinfo_proc *pp);
static int	procstat(struct tstat *, unsigned long long, char, struct kinfo_proc *);
#endif

#ifdef linux
int
photoproc(struct tstat *tasklist, int maxtask)
{
	static int			firstcall = 1;
	static unsigned long long	bootepoch;

	register struct tstat	*curtask;

	FILE		*fp;
	DIR		*dirp;
	struct dirent	*entp;
	char		origdir[1024];
	int		tval=0;

	/*
	** one-time initialization stuff
	*/
	if (firstcall)
	{
		/*
		** check if this kernel offers io-statistics per task
		*/
		regainrootprivs();

		if ( (fp = fopen("/proc/1/io", "r")) )
		{
			supportflags |= IOSTAT;
			fclose(fp);
		}

		if (! droprootprivs())
			cleanstop(42);

		/*
 		** find epoch time of boot moment
		*/
		bootepoch = getboot();

		firstcall = 0;
	}

	/*
	** probe if the netatop module and (optionally) the
	** netatopd daemon are active
	*/
	regainrootprivs();

	netatop_probe();

	if (! droprootprivs())
		cleanstop(42);

	/*
	** read all subdirectory-names below the /proc directory
	*/
	if ( getcwd(origdir, sizeof origdir) == NULL)
		cleanstop(53);

	if ( chdir("/proc") == -1)
		cleanstop(53);

	dirp = opendir(".");

	while ( (entp = readdir(dirp)) && tval < maxtask )
	{
		/*
		** skip non-numerical names
		*/
		if (!isdigit(entp->d_name[0]))
			continue;

		/*
		** change to the process' subdirectory
		*/
		if ( chdir(entp->d_name) != 0 )
			continue;

		/*
 		** gather process-level information
		*/
		curtask	= tasklist+tval;

		if ( !procstat(curtask, bootepoch, 1)) /* from /proc/pid/stat */
		{
			if ( chdir("..") == -1);
			continue;
		}

		if ( !procstatus(curtask) )	    /* from /proc/pid/status  */
		{
			if ( chdir("..") == -1);
			continue;
		}

		if ( !procio(curtask) )		    /* from /proc/pid/io      */
		{
			if ( chdir("..") == -1);
			continue;
		}

		proccmd(curtask);		    /* from /proc/pid/cmdline */

		// read network stats from netatop
		netatop_gettask(curtask->gen.tgid, 'g', curtask);

		tval++;		/* increment for process-level info */

		/*
 		** if needed (when number of threads is larger than 0):
		**   read and fill new entries with thread-level info
		*/
		if (curtask->gen.nthr > 1)
		{
			DIR		*dirtask;
			struct dirent	*tent;

			curtask->gen.nthrrun  = 0;
			curtask->gen.nthrslpi = 0;
			curtask->gen.nthrslpu = 0;
			
			/*
			** open underlying task directory
			*/
			if ( chdir("task") == 0 )
			{
				dirtask = opendir(".");
	
				while ((tent=readdir(dirtask)) && tval<maxtask)
				{
					struct tstat *curthr = tasklist+tval;

					/*
					** change to the thread's subdirectory
					*/
					if ( tent->d_name[0] == '.'  ||
					     chdir(tent->d_name) != 0 )
						continue;

					if ( !procstat(curthr, bootepoch, 0))
					{
						if ( chdir("..") == -1);
						continue;
					}
			
					if ( !procstatus(curthr) )
					{
						if ( chdir("..") == -1);
						continue;
					}

					if ( !procio(curthr) )
					{
						if ( chdir("..") == -1);
						continue;
					}

					switch (curthr->gen.state)
					{
	   		   		   case 'R':
						curtask->gen.nthrrun  += 1;
						break;
	   		   		   case 'S':
						curtask->gen.nthrslpi += 1;
						break;
	   		   		   case 'D':
						curtask->gen.nthrslpu += 1;
						break;
					}

					curthr->gen.nthr = 1;

					// read network stats from netatop
					netatop_gettask(curthr->gen.pid, 't',
									curthr);

					// all stats read now
					tval++;	    /* increment thread-level */
					if ( chdir("..") == -1); /* thread */
				}

				closedir(dirtask);
				if ( chdir("..") == -1); /* leave task */
			}
		}

		if ( chdir("..") == -1); /* leave process-level directry */
	}

	closedir(dirp);

	if ( chdir(origdir) == -1)
		cleanstop(53);

	return tval;
}

#elif defined(FREEBSD)

static void
proccmd(struct tstat *curtask, struct kinfo_proc *pp){
	static char     string[CMDLEN];
	char          **argv;
	string[0] = 0;
	
	argv = kvm_getargv(kd, pp, sizeof(string));
	while (argv && *argv) {
		if (string[0] != 0)
			strcat(string, " ");
		strcat(string, *argv);
		argv++;
	}
	memset(curtask->gen.cmdline, 0, CMDLEN+1);

	// enable display of long kernel processes
	if (!strlen(string) && 
	    ((pp->ki_flag & P_SYSTEM ) || (pp->ki_flag & P_KTHREAD)))
		/* kernel process, show with {name} */
		snprintf(curtask->gen.cmdline, CMDLEN-1, "{%s}", pp->ki_comm);
	else
	    strncpy(curtask->gen.cmdline, string, CMDLEN);
}

static void
procthr(struct tstat *curtask, struct kinfo_proc *pp){
	snprintf(curtask->gen.cmdline, CMDLEN-1, "[%s]",
		strlen(pp->ki_ocomm) ? pp->ki_ocomm : pp->ki_comm);
}

int
photoproc(struct tstat *tasklist, int maxtask)
{
	static int			firstcall = 1;
	static unsigned long long	bootepoch;
	
	register struct tstat	*curtask = NULL, *prev_curtask = NULL, *temp_proc = NULL;
	
	int		tval=0;
	
	/*
	** one-time initialization stuff
	*/
	if (firstcall)
	{
		/*
		** check if this kernel offers io-statistics per task
		*/
		regainrootprivs();
		
		supportflags |= IOSTAT;
		
		if (! droprootprivs())
			cleanstop(42);
		
		/*
 		** find epoch time of boot moment
		*/
		bootepoch = getboot();
		
		firstcall = 0;
	}
	
	/*
	** probe if the netatop module and (optionally) the
	** netatopd daemon are active
	*/
	regainrootprivs();
	
	// netatop_probe();
	
	if (! droprootprivs())
		cleanstop(42);
	
	struct kinfo_proc *pbase;
	int nproc, prev_pid, i;
	pbase = kvm_getprocs(kd, KERN_PROC_ALL, 0, &nproc);
	prev_pid = 0;
	struct tstat *curthr;
	
	
	for (i = nproc; --i >= 0; ++pbase) {
		
		if(pbase->ki_pid)  {
			if (filterkernel && ((pbase->ki_flag & P_SYSTEM ) || (pbase->ki_flag & P_KTHREAD)))
				continue;
			
			/*
			** gather process-level information
			*/
			
			
			if(prev_pid==pbase->ki_pid && prev_curtask) {	
				/*
				** process thread. Use previous process to fill thread data 
				*/
				curthr = tasklist+tval ;
				temp_proc=prev_curtask;
				curtask->gen.nthrrun  = 0;
				curtask->gen.nthrslpi = 0;
				curtask->gen.nthrslpu = 0;
				procthr(curthr, pbase);
				procstat(curthr, bootepoch, 0, pbase);
			}
			else {
				curtask = tasklist+tval;
				temp_proc=curtask;
				proccmd(curtask, pbase);
				procstat(curtask, bootepoch, 1, pbase);
			}
			/* count threads */
			switch (pbase->ki_stat) {
	    		case SRUN:
	    			curtask->gen.nthrrun++;
	    			break;
			case SSLEEP:
			case SIDL:
			case SSTOP:
			case SLOCK:
				curtask->gen.nthrslpi++;
				break;
			case SWAIT:
				curtask->gen.nthrslpu++;
				break;
			default: 
				curtask->gen.nthrrun++;
			}
			prev_pid=pbase->ki_pid;
			prev_curtask=curtask;
			tval++;
		}
		if(tval == maxtask)  /* do not write more procs then allocated memory */
			break;
		
	}
	return tval;
}
#endif // FREEBSD

/*
** count number of processes currently running
*/
unsigned int
countprocs(void)
{
	unsigned int	nr=0;
#ifdef linux
	DIR		*dirp;
	struct dirent	*entp;
	char		origdir[1024];
	if ( getcwd(origdir, sizeof origdir) == NULL)
		cleanstop(53);

	if ( chdir("/proc") == -1)
		cleanstop(53);

	dirp = opendir(".");

	while ( (entp = readdir(dirp)) )
	{
		/*
		** count subdirectory-names starting with a digit
		*/
		if (isdigit(entp->d_name[0]))
			nr++;
	}

	closedir(dirp);

	if ( chdir(origdir) == -1)
		cleanstop(53);
#elif defined(FREEBSD)
	int nproc_all = 0, i = 0;
	struct kinfo_proc *pbase;
	/* 
	** Result of the function is used to (re)allocte memory for the proc
	** structure.
	*/
	pbase = kvm_getprocs(kd, KERN_PROC_ALL, 0, &nproc_all);
	for (i = nproc_all; --i >= 0; ++pbase) {
	    if(pbase->ki_pid)  {
		if (filterkernel && ((pbase->ki_flag & P_SYSTEM ) || (pbase->ki_flag & P_KTHREAD))) 
		    continue;
		nr++;
	    }
	}
#endif
	return nr;
}

#ifdef linux
/*
** open file "stat" and obtain required info
*/
static int
procstat(struct tstat *curtask, unsigned long long bootepoch, char isproc)
{
	FILE	*fp;
	int	nr;
	char	line[4096], *cmdhead, *cmdtail;

	if ( (fp = fopen("stat", "r")) == NULL)
		return 0;

	if (fgets(line, sizeof line, fp) == NULL)
	{
		fclose(fp);
		return 0;
	}

	/*
    	** fetch command name
	*/
	cmdhead = strchr (line, '(');
	cmdtail = strrchr(line, ')');
	if ( (nr = cmdtail-cmdhead-1) > PNAMLEN)
		nr = PNAMLEN;

	memcpy(curtask->gen.name, cmdhead+1, nr);
	*(curtask->gen.name+nr) = 0;

	/*
  	** fetch other values
  	*/
	curtask->gen.isproc = isproc;
	curtask->cpu.rtprio  = 0;
	curtask->cpu.policy  = 0;
	curtask->gen.excode  = 0;

	sscanf(line, "%d", &(curtask->gen.pid));  /* fetch pid */

	nr = sscanf(cmdtail+2, SCANSTAT,
		&(curtask->gen.state), 	&(curtask->gen.ppid),
		&(curtask->mem.minflt),	&(curtask->mem.majflt),
		&(curtask->cpu.utime),	&(curtask->cpu.stime),
		&(curtask->cpu.prio),	&(curtask->cpu.nice),
		&(curtask->gen.btime),
		&(curtask->mem.vmem),	&(curtask->mem.rmem),
		&(curtask->cpu.curcpu),	&(curtask->cpu.rtprio),
		&(curtask->cpu.policy));

	if (nr < 12)		/* parsing failed? */
	{
		fclose(fp);
		return 0;
	}

	/*
 	** normalization
	*/
	curtask->gen.btime   = (curtask->gen.btime+bootepoch)/hertz;
	curtask->cpu.prio   += 100; 	/* was subtracted by kernel */
	curtask->mem.vmem   /= 1024;
	curtask->mem.rmem   *= pagesize/1024;

	fclose(fp);

	switch (curtask->gen.state)
	{
  	   case 'R':
		curtask->gen.nthrrun  = 1;
		break;
  	   case 'S':
		curtask->gen.nthrslpi = 1;
		break;
  	   case 'D':
		curtask->gen.nthrslpu = 1;
		break;
	}

	return 1;
}
#elif defined(FREEBSD)
// write all process related activity, except I/O
static int
procstat(struct tstat *curtask, unsigned long long bootepoch, char isproc, struct kinfo_proc *pp)
{
	if (isproc){
		if ((pp->ki_flag & P_SYSTEM ) || (pp->ki_flag & P_KTHREAD))
			/* kernel process, show with {name} */
			snprintf(curtask->gen.name,PNAMLEN-1, "{%s}", pp->ki_comm);
		else
			strncpy(curtask->gen.name, pp->ki_comm, PNAMLEN-1);
		curtask->gen.name[PNAMLEN] = 0;
	}
	else {
		snprintf(curtask->gen.name,PNAMLEN-1, "[%s]", strlen(pp->ki_ocomm) ? pp->ki_ocomm : pp->ki_comm);
	}
	/* 
	 * FIXME need to review http://www.unix.com/man-page/all/2/rtprio/ one more time 
	 Probably we need to change labels in FreeBSD atop as well to make it look more native
	*/
	switch (PRI_BASE(pp->ki_pri.pri_class)) {
	    case PRI_REALTIME:
	    curtask->cpu.rtprio = ((pp->ki_flag & P_KTHREAD) ? pp->ki_pri.pri_native :
		        pp->ki_pri.pri_user) - PRI_MIN_REALTIME;
	    break;
	    case PRI_IDLE:
	    curtask->cpu.rtprio = ((pp->ki_flag & P_KTHREAD) ? pp->ki_pri.pri_native :
		        pp->ki_pri.pri_user) - PRI_MIN_IDLE;
	    break;
	    default: 
		curtask->cpu.rtprio = 0;
	}
	
	/*
	 *   generate "STATE" field, emulating linux
	 *   - see http://linux.die.net/man/5/proc
	 */
	curtask->gen.state = ' ';
	switch (pp->ki_stat) {
	case SRUN:
		curtask->gen.state = 'R';
		break;
	case SLOCK: /* Blocked on a lock. */
		curtask->gen.state = 'L';
		break;
	case SSLEEP:
		curtask->gen.state = 'S';
		break;
	case SIDL: /* Process being created by fork. */ 
		curtask->gen.state = 'I';
		break;
	case SSTOP: /* Process debugging or suspension. */ 
		curtask->gen.state = 'T';
		break;
	case SZOMB:
		curtask->gen.state = 'Z';
		break;
	case SWAIT:
		curtask->gen.state = 'D';
		break;
	}
	// gen
	curtask->gen.tgid     = pp->ki_pid; /* FreeBSD is not using thread groups */
	curtask->gen.pid      = (isproc) ? pp->ki_pid : pp->ki_tid;
	curtask->gen.ppid     = pp->ki_ppid;
	curtask->gen.ruid     = pp->ki_ruid;
	curtask->gen.euid     = pp->ki_uid;;
	curtask->gen.suid     = pp->ki_svuid;;
	curtask->gen.fsuid    = 0; /* we don`t have it on BSD? */
	curtask->gen.rgid     = pp->ki_rgid;
	curtask->gen.egid     = pp->ki_pgid;
	curtask->gen.sgid     = pp->ki_svgid;
	curtask->gen.fsgid    = 0; /* we don`t have it on BSD? */
	curtask->gen.jid      = pp->ki_jid;
	curtask->gen.nthr     = (isproc) ? pp->ki_numthreads : 1;
	curtask->gen.isproc   = isproc;
	curtask->gen.excode   = 0;
	curtask->gen.btime    = pp->ki_start.tv_sec;
	curtask->gen.fsgid    = 0; /* we don`t have it on BSD? */
	// cpu
	curtask->cpu.utime    = pp->ki_rusage.ru_utime.tv_sec * 1000 + pp->ki_rusage.ru_utime.tv_usec / 1000;
	curtask->cpu.stime    = pp->ki_rusage.ru_stime.tv_sec * 1000 + pp->ki_rusage.ru_stime.tv_usec / 1000;
	curtask->cpu.prio     = pp->ki_pri.pri_level - PZERO; /* from freebsd top */
	curtask->cpu.nice     = pp->ki_nice;
	curtask->cpu.policy   = pp->ki_pri.pri_class; // it is different value then in Linux
	curtask->cpu.curcpu   = (int)pp->ki_lastcpu;
	// mem
	curtask->mem.minflt   = pp->ki_rusage.ru_minflt;
	curtask->mem.majflt   = pp->ki_rusage.ru_majflt;
	curtask->mem.vexec    = pp->ki_tsize * (pagesize/1024);
	curtask->mem.vmem     = pp->ki_size / 1024;
	curtask->mem.rmem     = pp->ki_rssize * (pagesize/1024);
	curtask->mem.vgrow    = 0;	/* calculated later */
	curtask->mem.rgrow    = 0;	/* calculated later */
	curtask->mem.vdata    = pp->ki_dsize * (pagesize/1024);
	curtask->mem.vstack   = pp->ki_ssize * (pagesize/1024);
	curtask->mem.vlibs    = (pp->ki_size/pagesize - pp->ki_dsize - 
		pp->ki_ssize -pp->ki_tsize - 1) * (pagesize/1024); // from linprocfs.c
	curtask->mem.vswap    = 0; // XXX, no idea how to get it on BSD
	// disk
	curtask->dsk.rio      = pp->ki_rusage.ru_inblock; /* Available data is in blocks only */
	curtask->dsk.rsz      = pp->ki_rusage.ru_inblock;
	curtask->dsk.wio      = pp->ki_rusage.ru_oublock;
	curtask->dsk.wsz      = pp->ki_rusage.ru_oublock;

	/* 
	* sleepavg value currently is not used by atop 
	* and not directly provided by FreeBSD kernel 
	*/ 
	curtask->cpu.sleepavg = 0;
	return 1;
}

#endif

#ifdef linux
/*
** open file "status" and obtain required info
*/
static int
procstatus(struct tstat *curtask)
{
	FILE	*fp;
	char	line[4096];

	if ( (fp = fopen("status", "r")) == NULL)
		return 0;

	curtask->gen.nthr     = 1;	/* for compat with 2.4 */
	curtask->cpu.sleepavg = 0;	/* for compat with 2.4 */
	curtask->mem.vgrow    = 0;	/* calculated later */
	curtask->mem.rgrow    = 0;	/* calculated later */

	while (fgets(line, sizeof line, fp))
	{
		if (memcmp(line, "Tgid:", 5) ==0)
		{
			sscanf(line, "Tgid: %d", &(curtask->gen.tgid));
			continue;
		}

		if (memcmp(line, "Pid:", 4) ==0)
		{
			sscanf(line, "Pid: %d", &(curtask->gen.pid));
			continue;
		}

		if (memcmp(line, "SleepAVG:", 9)==0)
		{
			sscanf(line, "SleepAVG: %d%%",
				&(curtask->cpu.sleepavg));
			continue;
		}

		if (memcmp(line, "Uid:", 4)==0)
		{
			sscanf(line, "Uid: %d %d %d %d",
				&(curtask->gen.ruid), &(curtask->gen.euid),
				&(curtask->gen.suid), &(curtask->gen.fsuid));
			continue;
		}

		if (memcmp(line, "Gid:", 4)==0)
		{
			sscanf(line, "Gid: %d %d %d %d",
				&(curtask->gen.rgid), &(curtask->gen.egid),
				&(curtask->gen.sgid), &(curtask->gen.fsgid));
			continue;
		}

		if (memcmp(line, "Threads:", 8)==0)
		{
			sscanf(line, "Threads: %d", &(curtask->gen.nthr));
			continue;
		}

		if (memcmp(line, "VmData:", 7)==0)
		{
			sscanf(line, "VmData: %lld", &(curtask->mem.vdata));
			continue;
		}

		if (memcmp(line, "VmStk:", 6)==0)
		{
			sscanf(line, "VmStk: %lld", &(curtask->mem.vstack));
			continue;
		}

		if (memcmp(line, "VmExe:", 6)==0)
		{
			sscanf(line, "VmExe: %lld", &(curtask->mem.vexec));
			continue;
		}

		if (memcmp(line, "VmLib:", 6)==0)
		{
			sscanf(line, "VmLib: %lld", &(curtask->mem.vlibs));
			continue;
		}

		if (memcmp(line, "VmSwap:", 7)==0)
		{
			sscanf(line, "VmSwap: %lld", &(curtask->mem.vswap));
			continue;
		}

		if (memcmp(line, "SigQ:", 5)==0)
			break;
	}

	fclose(fp);
	return 1;
}

/*
** open file "io" (>= 2.6.20) and obtain required info
*/
#define	IO_READ		"read_bytes:"
#define	IO_WRITE	"write_bytes:"
#define	IO_CWRITE	"cancelled_write_bytes:"
static int
procio(struct tstat *curtask)
{
	FILE	*fp;
	char	line[4096];
	count_t	dskrsz=0, dskwsz=0, dskcwsz=0;

	if (supportflags & IOSTAT)
	{
		regainrootprivs();

		if ( (fp = fopen("io", "r")) )
		{
			while (fgets(line, sizeof line, fp))
			{
				if (memcmp(line, IO_READ,
						sizeof IO_READ -1) == 0)
				{
					sscanf(line, "%*s %llu", &dskrsz);
					dskrsz /= 512;		// in sectors
					continue;
				}

				if (memcmp(line, IO_WRITE,
						sizeof IO_WRITE -1) == 0)
				{
					sscanf(line, "%*s %llu", &dskwsz);
					dskwsz /= 512;		// in sectors
					continue;
				}

				if (memcmp(line, IO_CWRITE,
						sizeof IO_CWRITE -1) == 0)
				{
					sscanf(line, "%*s %llu", &dskcwsz);
					dskcwsz /= 512;		// in sectors
					continue;
				}
			}

			fclose(fp);

			curtask->dsk.rsz	= dskrsz;
			curtask->dsk.rio	= dskrsz;  // to enable sort
			curtask->dsk.wsz	= dskwsz;
			curtask->dsk.wio	= dskwsz;  // to enable sort
			curtask->dsk.cwsz	= dskcwsz;
		}

		if (! droprootprivs())
			cleanstop(42);
	}

	return 1;
}

/*
** store the full command line; the command-line may contain:
**    - null-bytes as a separator between the arguments
**    - newlines (e.g. arguments for awk or sed)
**    - tabs (e.g. arguments for awk or sed)
** these special bytes will be converted to spaces
*/
static void
proccmd(struct tstat *curtask)
{
	FILE		*fp;
	register int 	i, nr;

	memset(curtask->gen.cmdline, 0, CMDLEN+1);

	if ( (fp = fopen("cmdline", "r")) != NULL)
	{
		register char *p = curtask->gen.cmdline;

		nr = fread(p, 1, CMDLEN, fp);
		fclose(fp);

		if (nr >= 0)	/* anything read ? */
		{
			for (i=0; i < nr-1; i++, p++)
			{
				switch (*p)
				{
				   case '\0':
				   case '\n':
				   case '\t':
					*p = ' ';
				}
			}
		}
	}
}

#endif
