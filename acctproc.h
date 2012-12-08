/*
** ATOP - System & Process Monitor
**
** The program 'atop' offers the possibility to view the activity of
** the system on system-level as well as process-level.
**
** Include-file for process-accounting functions.
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
int 	acctswon(void);
void	acctswoff(void);
int 	acctprocnt(void);
int 	acctphotoproc(struct tstat *, int);
void 	acctrepos(unsigned int);

#ifdef linux
/*
** maximum number of records to be read from process accounting file
** for one sample, to avoid that atop explodes and introduces OOM killing ....
**
** the maximum is based on a limit of 50 MiB extra memory (approx. 70000 procs)
*/
#define MAXACCTPROCS	(50*1024*1024/sizeof(struct tstat))

/*
** preferred maximum size of process accounting file (200 MiB)
*/
#define ACCTMAXFILESZ	(200*1024*1024)

/*
** alternative layout of accounting record if kernel-patch
** has been installed
*/
#include <linux/types.h>
typedef __u16   comp_t;
typedef __u32   comp2_t;
#elif defined(FREEBSD)

#include <sys/types.h>
#include <sys/acct.h>

typedef uint16_t   comp_t;
typedef uint32_t   comp2_t;
#define __u16 uint16_t
#define __u8 uint8_t
#define __u32 uint32_t
#define __64 uint64_t
#endif

#define ACCT_COMM	16
struct acct_atop
{
	char		ac_flag;		/* Flags */
	char		ac_version;		/* Always set to ACCT_VERSION */
	__u32		ac_pid;			/* Process ID */
	__u32		ac_ppid;		/* Parent Process ID */
	__u16		ac_uid16;		/* LSB of Real User ID */
	__u16		ac_gid16;		/* LSB of Real Group ID */
	__u16		ac_tty;			/* Control Terminal */
	__u32		ac_btime;		/* Process Creation Time */
	comp_t		ac_utime;		/* User Time */
	comp_t		ac_stime;		/* System Time */
	comp_t		ac_etime;		/* Elapsed Time */
	comp_t		ac_mem;			/* Virtual  Memory */
	comp_t		ac_rss;			/* Resident Memory */
	comp_t		ac_io;			/* Chars Transferred */
	comp_t		ac_rw;			/* Blocks Read or Written */
	comp_t		ac_bread;		/* Blocks Read */
	comp_t		ac_bwrite;		/* Blocks Written */
	comp2_t		ac_dskrsz;		/* Cum. blocks read */
	comp2_t		ac_dskwsz;		/* Cum. blocks written */
	comp_t		ac_tcpsnd;		/* TCP send requests */
	comp_t		ac_tcprcv;		/* TCP recv requests */
	comp2_t		ac_tcpssz;		/* TCP cum. length   */
	comp2_t		ac_tcprsz;		/* TCP cum. length   */
	comp_t		ac_udpsnd;		/* UDP send requests */
	comp_t		ac_udprcv;		/* UDP recv requests */
	comp2_t		ac_udpssz;		/* UDP cum. length   */
	comp2_t		ac_udprsz;		/* UDP cum. length   */
	comp_t		ac_rawsnd;		/* RAW send requests */
	comp_t		ac_rawrcv;		/* RAW recv requests */
	comp_t		ac_minflt;		/* Minor Pagefaults */
	comp_t		ac_majflt;		/* Major Pagefaults */
	comp_t		ac_swaps;		/* Number of Swaps */
/* m68k had no padding here. */
#if !defined(CONFIG_M68K) || !defined(__KERNEL__)
	__u16		ac_ahz;			/* AHZ */
#endif
	__u32		ac_exitcode;		/* Exitcode */
	char		ac_comm[ACCT_COMM + 1];	/* Command Name */
	__u8		ac_etime_hi;		/* Elapsed Time MSB */
	__u16		ac_etime_lo;		/* Elapsed Time LSB */
	__u32		ac_uid;			/* Real User ID */
	__u32		ac_gid;			/* Real Group ID */
};

#ifdef linux
/*
** default layout of accounting record
** (copied from /usr/src/linux/include/linux/acct.h)
*/

struct acct
{
	char		ac_flag;		/* Flags */
	char		ac_version;		/* Always set to ACCT_VERSION */
	/* for binary compatibility back until 2.0 */
	__u16		ac_uid16;		/* LSB of Real User ID */
	__u16		ac_gid16;		/* LSB of Real Group ID */
	__u16		ac_tty;			/* Control Terminal */
	__u32		ac_btime;		/* Process Creation Time */
	comp_t		ac_utime;		/* User Time */
	comp_t		ac_stime;		/* System Time */
	comp_t		ac_etime;		/* Elapsed Time */
	comp_t		ac_mem;			/* Average Memory Usage */
	comp_t		ac_io;			/* Chars Transferred */
	comp_t		ac_rw;			/* Blocks Read or Written */
	comp_t		ac_minflt;		/* Minor Pagefaults */
	comp_t		ac_majflt;		/* Major Pagefaults */
	comp_t		ac_swaps;		/* Number of Swaps */
/* m68k had no padding here. */
#if !defined(CONFIG_M68K) || !defined(__KERNEL__)
	__u16		ac_ahz;			/* AHZ */
#endif
	__u32		ac_exitcode;		/* Exitcode */
	char		ac_comm[ACCT_COMM + 1];	/* Command Name */
	__u8		ac_etime_hi;		/* Elapsed Time MSB */
	__u16		ac_etime_lo;		/* Elapsed Time LSB */
	__u32		ac_uid;			/* Real User ID */
	__u32		ac_gid;			/* Real Group ID */
};
#elif defined(FREEBSD)
// copied from acct.h, probably better not to do this
struct acct {
	uint8_t   ac_zero;		/* zero identifies new version */
	uint8_t   ac_version;		/* record version number */
	uint16_t  ac_len;		/* record length */

	char	  ac_comm[AC_COMM_LEN];	/* command name */
	float	  ac_utime;		/* user time */
	float	  ac_stime;		/* system time */
	float	  ac_etime;		/* elapsed time */
	time_t	  ac_btime;		/* starting time */
	uid_t	  ac_uid;		/* user id */
	gid_t	  ac_gid;		/* group id */
	float	  ac_mem;		/* average memory usage */
	float	  ac_io;		/* count of IO blocks */
	__dev_t   ac_tty;		/* controlling tty */

	uint16_t  ac_len2;		/* record length */
	union {
		__dev_t	  ac_align;	/* force v1 compatible alignment */

#define	AFORK	0x01			/* forked but not exec'ed */
/* ASU is no longer supported */
#define	ASU	0x02			/* used super-user permissions */
#define	ACOMPAT	0x04			/* used compatibility mode */
#define	ACORE	0x08			/* dumped core */
#define	AXSIG	0x10			/* killed by a signal */
#define ANVER	0x20			/* new record version */

		uint8_t   ac_flag;	/* accounting flags */
	} ac_trailer;

#define ac_flagx ac_trailer.ac_flag
};


#endif
struct acct_v3
{
	char		ac_flag;		/* Flags */
	char		ac_version;		/* Always set to ACCT_VERSION */
	__u16		ac_tty;			/* Control Terminal */
	__u32		ac_exitcode;		/* Exitcode */
	__u32		ac_uid;			/* Real User ID */
	__u32		ac_gid;			/* Real Group ID */
	__u32		ac_pid;			/* Process ID */
	__u32		ac_ppid;		/* Parent Process ID */
	__u32		ac_btime;		/* Process Creation Time */
#ifdef __KERNEL__
	__u32		ac_etime;		/* Elapsed Time */
#else
	float		ac_etime;		/* Elapsed Time */
#endif
	comp_t		ac_utime;		/* User Time */
	comp_t		ac_stime;		/* System Time */
	comp_t		ac_mem;			/* Average Memory Usage */
	comp_t		ac_io;			/* Chars Transferred */
	comp_t		ac_rw;			/* Blocks Read or Written */
	comp_t		ac_minflt;		/* Minor Pagefaults */
	comp_t		ac_majflt;		/* Major Pagefaults */
	comp_t		ac_swaps;		/* Number of Swaps */
	char		ac_comm[ACCT_COMM];	/* Command Name */
};
