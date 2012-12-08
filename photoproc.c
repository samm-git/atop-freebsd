/*
** ATOP - System & Process Monitor 
** 
** The program 'atop' offers the possibility to view the activity of
** the system on system-level as well as process-level.
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
** Solved segmentation fault by checking pval.
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
			"%*d  %lld %lld %lld %*d  %lld "	\
			"%lld %*d  %*d  %*d  %*d  %*d  " 	\
			"%*d  %*d  %*d  %lld %*d  %*d  "	\
			"%d   %d   %d "

/* ATOP-extension line of /proc/pid/stat */
#define ATOPSTAT	"%lld %llu %lld %llu %lld %llu %lld %llu "	\
			"%lld %llu %lld %llu %lld %lld"
#ifdef linux  /* using /proc/ to get all information */
static int	fillproc(struct pstat *);

int
photoproc(struct pstat *proclist, int maxproc)
{

	static int	firstcall = 1;

	register struct pstat	*curproc;

	FILE		*fp;
	DIR		*dirp;
	struct dirent	*entp;
	char		origdir[1024];
	int		nr, i, nthreads, pval=0;

	/*
	** one-time initialization stuff
	*/
	if (firstcall)
	{
		/*
		** check if this kernel is patched for additional
		** per-process counters
		*/
		if ( (fp = fopen("/proc/1/stat", "r")) )
		{
			char	line[4096];

			/*
			** when the patch is installed, the output
			** of /proc/pid/stat contains two lines
			*/
			(void) fgets(line, sizeof line, fp);

			if ( fgets(line, sizeof line, fp) != NULL)
				supportflags |= PATCHSTAT;

			fclose(fp);
		}

		/*
		** check if this kernel offers io-statistics per process
		*/
		if ( !(supportflags & PATCHSTAT) )
		{
			if ( (fp = fopen("/proc/1/io", "r")) )
			{
				supportflags |= IOSTAT;

				fclose(fp);
			}
		}

		firstcall = 0;
	}

	/*
	** read all subdirectory-names below the /proc directory
	*/
	getcwd(origdir, sizeof origdir);
	chdir("/proc");
	dirp = opendir(".");

	while ( (entp = readdir(dirp)) && pval < maxproc )
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
		** call fillproc to open the required files and gather
		** the process' info
		*/
		curproc	= proclist+pval;

		if ( (nthreads = fillproc(curproc)) == 0 )
		{
			chdir("..");
			continue;
		}

		pval++;

		/*
		** store the full command line; the command-line may contain:
		**    - null-bytes as a separator between the arguments
		**    - newlines (e.g. arguments for awk or sed)
		**    - tabs (e.g. arguments for awk or sed)
		** these special bytes will be converted to spaces
		*/
		memset(curproc->gen.cmdline, 0, CMDLEN+1);

		if ( (fp = fopen("cmdline", "r")) != NULL)
		{
			register char *p = curproc->gen.cmdline;

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

		chdir("..");
	}

	closedir(dirp);

	chdir(origdir);

	return pval;
}

static int
fillproc(struct pstat *curproc)
{
	static time_t	bootepoch;
	FILE		*fp;
	int		nr;
	char		line[4096], *cmdhead, *cmdtail;
	char		command[64], state;
	int		pid, ppid, prio, policy, rtprio, nice,
			ruid, euid, suid, fsuid, rgid, egid, sgid, fsgid,
			curcpu, nthreads, sleepavg;
	count_t		utime, stime, starttime;
	count_t		minflt, majflt, size, rss, nswap,
			startcode, endcode,
			dskrio=0, dskwio=0, dskrsz=0, dskwsz=0, dskcwsz=0,
			tcpsnd=0, tcprcv=0, tcpssz=0, tcprsz=0,
			udpsnd=0, udprcv=0, udpssz=0, udprsz=0,
			rawsnd=0, rawrcv=0;

	if (bootepoch == 0)
		bootepoch = getboot();

	/*
	** open file "stat" and obtain required info
	*/
	if ( (fp = fopen("stat", "r")) == NULL)
		return 0;

	if (fgets(line, sizeof line, fp) == NULL)
	{
		fclose(fp);
		return 0;
	}

	sscanf(line, "%d", &pid);		/* fetch pid */

	cmdhead = strchr (line, '(');		/* fetch commandname */
	cmdtail = strrchr(line, ')');
	if ( (nr = cmdtail-cmdhead-1) > sizeof command)
		nr = sizeof command;
	memcpy(command, cmdhead+1, nr);
	memset(&command[nr], 0, sizeof command - nr);

	rtprio = policy = 0;

	nr = sscanf(cmdtail+2, SCANSTAT,
		&state,    &ppid,      &minflt,    &majflt,
		&utime,    &stime,     &prio,      &nice,    &starttime,
		&size,     &rss,       &startcode, &endcode, &nswap,
		&curcpu,   &rtprio,    &policy);

	if ( fgets(line, sizeof line, fp) != NULL)
	{
		sscanf(line, ATOPSTAT,
			&dskrio, &dskrsz, &dskwio, &dskwsz,
			&tcpsnd, &tcpssz, &tcprcv, &tcprsz,
			&udpsnd, &udpssz, &udprcv, &udprsz,
			&rawsnd, &rawrcv);
	}

	fclose(fp);

	if (nr < 14)		/* parsing succeeded ? */
		return 0;

	/*
	** open file "status" and obtain required info
	*/
	if ( (fp = fopen("status", "r")) == NULL)
		return 0;

	nthreads = 1;		/* for compat with 2.4 */
	sleepavg = 0;		/* for compat with 2.4 */

	while (fgets(line, sizeof line, fp))
	{
		if (memcmp(line, "SleepAVG:", 9)==0)
		{
			sscanf(line, "SleepAVG: %d%%", &sleepavg);
			continue;
		}

		if (memcmp(line, "Uid:", 4)==0)
		{
			sscanf(line, "Uid: %d %d %d %d",
				&ruid, &euid, &suid, &fsuid);
			continue;
		}

		if (memcmp(line, "Gid:", 4)==0)
		{
			sscanf(line, "Gid: %d %d %d %d",
				&rgid, &egid, &sgid, &fsgid);
			continue;
		}

		if (memcmp(line, "Threads:", 8)==0)
		{
			sscanf(line, "Threads: %d", &nthreads);
			break;
		}
	}

	fclose(fp);

	/*
	** open file "io" (>= 2.6.20) and obtain required info
	*/
#define	IO_READ		"read_bytes:"
#define	IO_WRITE	"write_bytes:"
#define	IO_CWRITE	"cancelled_write_bytes:"

	if ((supportflags & IOSTAT) && (fp = fopen("io", "r")) )
	{
		while (fgets(line, sizeof line, fp))
		{
			if (memcmp(line, IO_READ, sizeof IO_READ -1) == 0)
			{
				sscanf(line, "%*s %llu", &dskrsz);
				dskrsz /= 512;		/* in sectors     */
				dskrio  = dskrsz;	/* enable sorting */
				continue;
			}

			if (memcmp(line, IO_WRITE, sizeof IO_WRITE -1) == 0)
			{
				sscanf(line, "%*s %llu", &dskwsz);
				dskwsz /= 512;		/* in sectors     */
				dskwio  = dskwsz;	/* enable sorting */
				continue;
			}

			if (memcmp(line, IO_CWRITE, sizeof IO_CWRITE -1) == 0)
			{
				sscanf(line, "%*s %llu", &dskcwsz);
				dskcwsz /= 512;		/* in sectors     */
				continue;
			}
		}

		fclose(fp);
	}

	/*
	** store required info in process-structure
	*/
	curproc->gen.pid      = pid;
	curproc->gen.ppid     = ppid;
	curproc->gen.ruid     = ruid;
	curproc->gen.euid     = euid;
	curproc->gen.suid     = suid;
	curproc->gen.fsuid    = fsuid;
	curproc->gen.rgid     = rgid;
	curproc->gen.egid     = egid;
	curproc->gen.sgid     = sgid;
	curproc->gen.fsgid    = fsgid;
	curproc->gen.nthr     = nthreads;
	curproc->gen.state    = state;

	strncpy(curproc->gen.name, command, PNAMLEN);
	curproc->gen.name[PNAMLEN] = 0;

	curproc->gen.excode   = 0;
	curproc->gen.btime    = starttime/hertz+bootepoch;
	curproc->cpu.utime    = utime;
	curproc->cpu.stime    = stime;
	curproc->cpu.nice     = nice;
	curproc->cpu.prio     = prio + 100; /* was subtracted by kernel */
	curproc->cpu.rtprio   = rtprio;
	curproc->cpu.policy   = policy;
	curproc->cpu.curcpu   = curcpu;
	curproc->cpu.sleepavg = sleepavg;

	curproc->mem.minflt   = minflt;
	curproc->mem.majflt   = majflt;
	curproc->mem.vmem     = size / 1024;
	curproc->mem.rmem     = rss  * (pagesize/1024);
	curproc->mem.vgrow    = 0;	/* calculated later */
	curproc->mem.rgrow    = 0;	/* calculated later */
	curproc->mem.shtext   = (endcode-startcode)/1024;

	curproc->dsk.rio      = dskrio;
	curproc->dsk.rsz      = dskrsz;
	curproc->dsk.wio      = dskwio;
	curproc->dsk.wsz      = dskwsz;
	curproc->dsk.cwsz     = dskcwsz;
	curproc->net.tcpsnd   = tcpsnd;
	curproc->net.tcpssz   = tcpssz;
	curproc->net.tcprcv   = tcprcv;
	curproc->net.tcprsz   = tcprsz;
	curproc->net.udpsnd   = udpsnd;
	curproc->net.udpssz   = udpssz;
	curproc->net.udprcv   = udprcv;
	curproc->net.udprsz   = udprsz;
	curproc->net.rawsnd   = rawsnd;
	curproc->net.rawrcv   = rawrcv;

	/*
	** check the state of every individual thread
	*/
	if (nthreads > 1)
	{
		DIR		*dirt;
		struct dirent	*tent;
		FILE		*tstat;
		char		tpath[128];

		/*
		** open underlying task directory
		*/
		if ( chdir("task") == 0 )
		{
			dirt = opendir(".");

			while ( (tent = readdir(dirt)) )
			{
				/*
				** check if valid thread directory underneath
				*/
				if (!isdigit(tent->d_name[0]))
					continue;

				/*
				** open stat-file of thread
				*/
				snprintf(tpath, sizeof tpath,
						"%s/stat", tent->d_name);

				if ( (tstat = fopen(tpath, "r")) == NULL)
					continue;

				/*
				** read (first) line from file
				*/
				if (fgets(line, sizeof line, tstat) == NULL)
				{
					fclose(tstat);	/* failed */
					continue;
				}

				/*
				** fetch required info from thread
				*/
				cmdtail = strrchr(line, ')');

				nr = sscanf(cmdtail+2, "%c", &state);

				fclose(tstat);

				switch (state)
				{
				   case 'R':
					curproc->gen.nthrrun++;
					break;
				   case 'S':
					curproc->gen.nthrslpi++;
					break;
				   case 'D':
					curproc->gen.nthrslpu++;
					break;
				}
			}

			closedir(dirt);

			chdir("..");
		}
	}
	else
	{
		switch (state)
		{
		   case 'R':
			curproc->gen.nthrrun  = 1;
			break;
		   case 'S':
			curproc->gen.nthrslpi = 1;
			break;
		   case 'D':
			curproc->gen.nthrslpu = 1;
			break;
		}
	}

	return nthreads;
	
}
#elif defined(FREEBSD)  /* we are using kvm to get all the information */
static int	fillproc(struct pstat *, struct kinfo_proc *pp);

int
photoproc(struct pstat *proclist, int maxproc)
{
	static int	firstcall = 1;

	register struct pstat	*curproc, *prev_curproc = NULL, *temp_proc = NULL;

	int		i, pval=0;

	/*
	** one-time initialization stuff
	*/
	if (firstcall)
	{
		supportflags |= IOSTAT; /* we have block count number per process in the kvm stat */
		firstcall = 0;
	}
	
	struct kinfo_proc *pbase;
	static char     string[CMDLEN];
	char          **argv;
	int nproc, prev_pid;
	pbase = kvm_getprocs(kd, KERN_PROC_ALL, 0, &nproc);
	prev_pid = 0;
	for (i = nproc; --i >= 0; ++pbase) {
	    if(pbase->ki_pid)  {
		if (filterkernel && ((pbase->ki_flag & P_SYSTEM ) || (pbase->ki_flag & P_KTHREAD)))
		    continue;
		
		curproc = proclist+pval ;
	
		if(prev_pid==pbase->ki_pid && prev_curproc)	/*
								** process thread. Use previous process to fill thread data 
								*/
		    temp_proc=prev_curproc;
		else 
		    temp_proc=curproc;
		/* count threads */
		switch (pbase->ki_stat) {
	    		case SRUN:
	    		    temp_proc->gen.nthrrun++;
		    	    break;
			case SSLEEP:
			case SIDL:
			case SSTOP:
			case SLOCK:
				temp_proc->gen.nthrslpi++;
				break;
			case SWAIT:
			temp_proc->gen.nthrslpu++;
				break;
			default: 
		    	temp_proc->gen.nthrrun++;
		    }
		    
		if (prev_pid==pbase->ki_pid)  /* thread detected, no need to add to the process table */
		    continue;
		fillproc(curproc, pbase);
		prev_pid=pbase->ki_pid;
		prev_curproc=curproc;
		string[0] = 0;
		argv = kvm_getargv(kd, pbase, sizeof(string));
		while (argv && *argv) {
		    if (string[0] != 0)
		    strcat(string, " ");
		    strcat(string, *argv);
		    argv++;
		}
		memset(curproc->gen.cmdline, 0, CMDLEN+1);
		strncpy(curproc->gen.cmdline, string, CMDLEN); 
		pval++;
		if(pval == maxproc)  /* do not write more procs then allocated memory */
		    break;
	    }
	}
	return pval;
}

static int
fillproc(struct pstat *curproc, struct kinfo_proc *pp)
{
	curproc->gen.pid      = pp->ki_pid;
	curproc->gen.ppid     = pp->ki_ppid;
	curproc->gen.ruid     = pp->ki_ruid;
	curproc->gen.euid     = pp->ki_uid;;
	curproc->gen.suid     = pp->ki_svuid;;
	curproc->gen.fsuid    = 0; /* we don`t have it on BSD? */
	curproc->gen.rgid     = pp->ki_rgid;
	curproc->gen.egid     = pp->ki_pgid;
	curproc->gen.sgid     = pp->ki_svgid;
	curproc->gen.fsgid    = 0; /* we don`t have it on BSD? */
	curproc->gen.jid      = pp->ki_jid;
	curproc->gen.nthr     = pp->ki_numthreads;
	/*
	 *   generate "STATE" field, emulating linux
	 *   - see http://linux.die.net/man/5/proc
	 */
	curproc->gen.state = ' ';
	switch (pp->ki_stat) {
	case SRUN:
		curproc->gen.state = 'R';
		break;
	case SLOCK: /* Blocked on a lock. */
		curproc->gen.state = 'L';
		break;
	case SSLEEP:
		curproc->gen.state = 'S';
		break;
	case SIDL: /* Process being created by fork. */ 
		curproc->gen.state = 'I';
		break;
	case SSTOP: /* Process debugging or suspension. */ 
		curproc->gen.state = 'T';
		break;
	case SZOMB:
		curproc->gen.state = 'Z';
		break;
	case SWAIT:
		curproc->gen.state = 'D';
		break;
	}
	if ((pp->ki_flag & P_SYSTEM ) || (pp->ki_flag & P_KTHREAD))
	    /* kernel process, show with {name} */
	    snprintf(curproc->gen.name,PNAMLEN-1, "{%s}", pp->ki_comm);
	else
	    strncpy(curproc->gen.name, pp->ki_comm, PNAMLEN-1);
	curproc->gen.name[PNAMLEN] = 0;

	curproc->gen.excode   = 0;
	curproc->gen.btime    = pp->ki_start.tv_sec;
	curproc->cpu.utime    = pp->ki_rusage.ru_utime.tv_sec * 1000 + pp->ki_rusage.ru_utime.tv_usec / 1000;
	curproc->cpu.stime    = pp->ki_rusage.ru_stime.tv_sec * 1000 + pp->ki_rusage.ru_stime.tv_usec / 1000;
	curproc->cpu.nice     = pp->ki_nice;
	curproc->cpu.prio     = pp->ki_pri.pri_level - PZERO; /* from freebsd top */
	/* 
	 * FIXME need to review http://www.unix.com/man-page/all/2/rtprio/ one more time 
	 Probably we need to change labels in FreeBSD atop as well to make it look more native
	*/
	switch (PRI_BASE(pp->ki_pri.pri_class)) {
	    case PRI_REALTIME:
	    curproc->cpu.rtprio = ((pp->ki_flag & P_KTHREAD) ? pp->ki_pri.pri_native :
		        pp->ki_pri.pri_user) - PRI_MIN_REALTIME;
	    break;
	    case PRI_IDLE:
	    curproc->cpu.rtprio = ((pp->ki_flag & P_KTHREAD) ? pp->ki_pri.pri_native :
		        pp->ki_pri.pri_user) - PRI_MIN_IDLE;
	    break;
	    default: 
		curproc->cpu.rtprio = 0;
	}
	curproc->cpu.policy   = pp->ki_pri.pri_class; // it is different value then in Linux
	curproc->cpu.curcpu   = (int)pp->ki_lastcpu;
	/* 
	* sleepavg value currently is not used by atop 
	* and not directly provided by FreeBSD kernel 
	*/ 
	curproc->cpu.sleepavg = 0; 

	curproc->mem.minflt   = pp->ki_rusage.ru_minflt;
	curproc->mem.majflt   = pp->ki_rusage.ru_majflt;
	curproc->mem.vmem     = pp->ki_size / 1024;
	curproc->mem.rmem     = pp->ki_rssize * (pagesize/1024);
	curproc->mem.vgrow    = 0;	/* calculated later */
	curproc->mem.rgrow    = 0;	/* calculated later */
	curproc->mem.shtext   = pp->ki_tsize * (pagesize/1024);

	curproc->dsk.rio      = pp->ki_rusage.ru_inblock; /* Provided data is in blocks, no idea if it is possible to convert it to bytes */
	curproc->dsk.rsz      = pp->ki_rusage.ru_inblock;
	curproc->dsk.wio      = pp->ki_rusage.ru_oublock;
	curproc->dsk.wsz      = pp->ki_rusage.ru_oublock;
	curproc->dsk.cwsz     = 0;
	curproc->net.tcpsnd   = 0; /* there is no per-process network information in the FreeBSD  */
	curproc->net.tcpssz   = 0;
	curproc->net.tcprcv   = 0;
	curproc->net.tcprsz   = 0;
	curproc->net.udpsnd   = 0;
	curproc->net.udpssz   = 0;
	curproc->net.udprcv   = 0;
	curproc->net.udprsz   = 0;
	curproc->net.rawsnd   = 0;
	curproc->net.rawrcv   = 0;

	return curproc->gen.nthr;
}
#endif /* FREEBSD */
/*
** count number of processes currently running
*/
unsigned int
countprocs(void)
{
#ifdef linux
	unsigned int	nr=0;
	DIR		*dirp;
	struct dirent	*entp;
	char		origdir[1024];

	getcwd(origdir, sizeof origdir);
	chdir("/proc");
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

	chdir(origdir);

	return nr;
#elif defined(FREEBSD)
	int nproc = 0, nproc_all = 0, i = 0;
	struct kinfo_proc *pbase;
	/* 
	** Result of the function is used to (re)allocte memory for the proc
	** structure. It is not  very accurate, because includes threads.
	*/
	pbase = kvm_getprocs(kd, KERN_PROC_ALL, 0, &nproc_all);
	for (i = nproc_all; --i >= 0; ++pbase) {
	    if(pbase->ki_pid)  {
		if (filterkernel && ((pbase->ki_flag & P_SYSTEM ) || (pbase->ki_flag & P_KTHREAD))) 
		    continue;
		nproc++;
	    }
	}

	return nproc;
#endif
}
