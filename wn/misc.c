/*
    Wn: A Server for the HTTP
    File: wn/misc.c
    Version 2.3.13
*/

/*
 * Misc functions for systems which don't have them.  Everything
 * is public domain.
 *
 * Exception:
 * strstr() is taken (in slightly modified form) from wu-ftpd, which
 * notes that it is:
 *
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */


#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include "wn.h"


/*
 *  Make string all lower case.
 */

char *
strlower( st)
char	*st;
{
	register char	*cp;

	cp = st;
	while ( *cp) {
		*cp =  (isupper(*cp) ? *cp - 'A' + 'a' : *cp );
		cp++;
	}
	return (st);
}

#if NEED_STRNCASECMP

/*
 *  Case insensitive comparison of first n chars of two strings
 */

int
strncasecmp( s1, s2, n)
char	*s1,
	*s2;
int	n;

{
	int	r;

	while ( *s1 && *s2 && ( n > 0)) {
		if ( (r = (tolower( *s1) - tolower( *s2))) != 0 )
			return r;
		s1++;
		s2++;
		n--;
	}
	return ( n == 0 ? 0 : *s1 - *s2);
}
#endif

#if NEED_STRCASECMP
/*
 *  Case insensitive comparison of two strings
 */
int
strcasecmp( s1, s2)
char	*s1,
	*s2;

{
	int	r;

	while ( *s1 && *s2 ) {
		if ( (r = (tolower( *s1) - tolower( *s2))) != 0 )
			return r;
		s1++;
		s2++;
	} 
	return ( *s1 - *s2);
}
#endif


#if  NEED_PUTENV
/*
 * Define putenv for machines the don't have it in the standard  
 * library.  This version is from comp.sys.next.programmer
 */
int 

putenv(s)
char *s;
{
	int nlen;
	char *cptr;
	char **nenv, **eptr;
	extern char **environ;

	/*  First see if there is an existing 'name=value' with the
	 *  same name as s.
	 */
	for (cptr = s; *cptr != '=' && *cptr != '\0'; cptr++)
		;
	if (*cptr == '=' && cptr > s) {
		nlen = cptr - s + 1;
		for (eptr = environ; *eptr != NULL; eptr++) {
			if (strncmp(*eptr, s, nlen) == 0) {
				*eptr = s;
				return 0;
			}
		}
	}
	
	/*  New name, so must change environ.
	 */
	for (eptr = environ; *eptr != NULL; eptr++)
		;
	nenv = (char **) malloc((eptr - environ + 2) * sizeof(char *));
	if (nenv == NULL)
		return -1;
	eptr = environ;
	environ = nenv;
	while ((*nenv = *eptr) != NULL)
		nenv++, eptr++;
	*nenv = s;
	nenv[1] = NULL;
	return 0;
}
#endif


#if NEED_STRFTIME
/*
 * strftime.c
 *
 * Public-domain relatively quick-and-dirty implemenation of
 * ANSI library routine for System V Unix systems.
 *
 * It's written in old-style C for maximal portability.
 * However, since I'm used to prototypes, I've included them too.
 *
 * If you want stuff in the System V ascftime routine, add the SYSV_EXT define.
 *
 * The code for %c, %x, and %X is my best guess as to what's "appropriate".
 * This version ignores LOCALE information.
 * It also doesn't worry about multi-byte characters.
 * So there.
 *
 * Arnold Robbins
 * January, February, 1991
 *
 * Fixes from ado@elsie.nci.nih.gov
 * February 1991
 */


#ifndef __STDC__
#define const	/**/
#endif

#ifndef __STDC__
/* extern void tzset(); */
extern char *strchr();
static int weeknumber();
#else
/* extern void tzset(void); */
extern char *strchr(const char *str, int ch);
static int weeknumber(const struct tm *timeptr, int firstweekday);
#endif

/* extern char *tzname[2]; */
/* extern int daylight; */

#define SYSV_EXT	1	/* stuff in System V ascftime routine */

/* strftime --- produce formatted time */

#ifndef __STDC__
size_t
strftime(s, maxsize, format, timeptr)
char *s;
size_t maxsize;
const char *format;
const struct tm *timeptr;
#else
size_t
strftime(char *s, size_t maxsize, const char *format, const struct tm *timeptr)
#endif
{
	char *endp = s + maxsize;
	char *start = s;
	char tbuf[SMALLLEN];
	int i;
	static short first = 1;

	/* various tables, useful in North America */
	static char *days_a[] = {
		"Sun", "Mon", "Tue", "Wed",
		"Thu", "Fri", "Sat",
	};
	static char *days_l[] = {
		"Sunday", "Monday", "Tuesday", "Wednesday",
		"Thursday", "Friday", "Saturday",
	};
	static char *months_a[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	};
	static char *months_l[] = {
		"January", "February", "March", "April",
		"May", "June", "July", "August", "September",
		"October", "November", "December",
	};
	static char *ampm[] = { "AM", "PM", };

	if (s == NULL || format == NULL || timeptr == NULL || maxsize == 0)
		return 0;

	if (strchr(format, '%') == NULL && strlen(format) + 1 >= maxsize)
		return 0;

	if (first) {
/*		tzset(); */
		first = 0;
	}

	for (; *format && s < endp - 1; format++) {
		tbuf[0] = '\0';
		if (*format != '%') {
			*s++ = *format;
			continue;
		}
		switch (*++format) {
		case '\0':
			*s++ = '%';
			goto out;

		case '%':
			*s++ = '%';
			continue;

		case 'a':	/* abbreviated weekday name */
			if (timeptr->tm_wday < 0 || timeptr->tm_wday > 6)
				mystrncpy(tbuf, "?", 2);
			else
				mystrncpy(tbuf, days_a[timeptr->tm_wday], SMALLLEN);
			break;

		case 'A':	/* full weekday name */
			if (timeptr->tm_wday < 0 || timeptr->tm_wday > 6)
				mystrncpy(tbuf, "?", 2);
			else
				mystrncpy(tbuf, days_l[timeptr->tm_wday], SMALLLEN);
			break;

		case 'h':	/* abbreviated month name */
		case 'b':	/* abbreviated month name */
			if (timeptr->tm_mon < 0 || timeptr->tm_mon > 11)
				mystrncpy(tbuf, "?", 2);
			else
				mystrncpy(tbuf, months_a[timeptr->tm_mon], SMALLLEN);
			break;

		case 'B':	/* full month name */
			if (timeptr->tm_mon < 0 || timeptr->tm_mon > 11)
				mystrncpy(tbuf, "?", 2);
			else
				mystrncpy(tbuf, months_l[timeptr->tm_mon], SMALLLEN);
			break;
		case 'c':	/* appropriate date and time representation */
			sprintf(tbuf, "%.3s %.3s %2d %02d:%02d:%02d %d",
				days_a[timeptr->tm_wday],
				months_a[timeptr->tm_mon],
				timeptr->tm_mday,
				timeptr->tm_hour,
				timeptr->tm_min,
				timeptr->tm_sec,
				timeptr->tm_year + 1900);
			break;

		case 'd':	/* day of the month, 01 - 31 */
			sprintf(tbuf, "%02d", timeptr->tm_mday);
			break;

		case 'H':	/* hour, 24-hour clock, 00 - 23 */
			sprintf(tbuf, "%02d", timeptr->tm_hour);
			break;

		case 'I':	/* hour, 12-hour clock, 01 - 12 */
			i = timeptr->tm_hour;
			if (i == 0)
				i = 12;
			else if (i > 12)
				i -= 12;
			sprintf(tbuf, "%02d", i);
			break;

		case 'j':	/* day of the year, 001 - 366 */
			sprintf(tbuf, "%03d", timeptr->tm_yday + 1);
			break;

		case 'm':	/* month, 01 - 12 */
			sprintf(tbuf, "%02d", timeptr->tm_mon + 1);
			break;

		case 'M':	/* minute, 00 - 59 */
			sprintf(tbuf, "%02d", timeptr->tm_min);
			break;

		case 'p':	/* am or pm based on 12-hour clock */
			if (timeptr->tm_hour < 12)
				mystrncpy(tbuf, ampm[0], 4);
			else
				mystrncpy(tbuf, ampm[1], 4);
			break;

		case 'S':	/* second, 00 - 61 */
			sprintf(tbuf, "%02d", timeptr->tm_sec);
			break;

		case 'U':	/* week of year, Sunday is first day of week */
			sprintf(tbuf, "%d", weeknumber(timeptr, 0));
			break;

		case 'w':	/* weekday, Sunday == 0, 0 - 6 */
			sprintf(tbuf, "%d", timeptr->tm_wday);
			break;

		case 'W':	/* week of year, Monday is first day of week */
			sprintf(tbuf, "%d", weeknumber(timeptr, 1));
			break;

		case 'x':	/* appropriate date representation */
			sprintf(tbuf, "%.3s %.3s %2d %d",
				days_a[timeptr->tm_wday],
				months_a[timeptr->tm_mon],
				timeptr->tm_mday,
				timeptr->tm_year + 1900);
			break;

		case 'X':	/* appropriate time representation */
			sprintf(tbuf, "%02d:%02d:%02d",
				timeptr->tm_hour,
				timeptr->tm_min,
				timeptr->tm_sec);
			break;

		case 'y':	/* year without a century, 00 - 99 */
			i = timeptr->tm_year % 100;
			sprintf(tbuf, "%d", i);
			break;

		case 'Y':	/* year with century */
			sprintf(tbuf, "%d", 1900 + timeptr->tm_year);
			break;

		case 'Z':	/* time zone name or abbrevation */
			break;


		default:
			tbuf[0] = '%';
			tbuf[1] = *format;
			tbuf[2] = '\0';
			break;
		}
		i = strlen(tbuf);
		if (i)
			if (s + i < endp - 1) {
				mystrncpy(s, tbuf, 3 );
				s += i;
			} else
				return 0;
	}
out:
	if (s < endp && *format == '\0') {
		*s = '\0';
		return (s - start);
	} else
		return 0;
}

/* weeknumber --- figure how many weeks into the year */

/* With thanks and tip of the hatlo to ado@elsie.nci.nih.gov */

#ifndef __STDC__
static int
weeknumber(timeptr, firstweekday)
const struct tm *timeptr;
int firstweekday;
#else
static int
weeknumber(const struct tm *timeptr, int firstweekday)
#endif
{
	if (firstweekday == 0)
		return (timeptr->tm_yday + 7 - timeptr->tm_wday) / 7;
	else
		return (timeptr->tm_yday + 7 -
			(timeptr->tm_wday ? (timeptr->tm_wday - 1) : 6)) / 7;
}
#endif

#ifdef hpux
/* This is from the HPUX porting tricks FAQ */

/*
 * flock (fd, operation)
 *
 * This routine performs some file locking like the BSD 'flock'
 * on the object described by the int file descriptor 'fd',
 * which must already be open.
 *
 * The operations that are available are:
 *
 * LOCK_SH  -  get a shared lock.
 * LOCK_EX  -  get an exclusive lock.
 * LOCK_NB  -  don't block (must be ORed with LOCK_SH or LOCK_EX).
 * LOCK_UN  -  release a lock.
 *
 * Return value: 0 if lock successful, -1 if failed.
 *
 * Note that whether the locks are enforced or advisory is
 * controlled by the presence or absence of the SETGID bit on
 * the executable.
 *
 * Note that there is no difference between shared and exclusive
 * locks, since the 'lockf' system call in SYSV doesn't make any
 * distinction.
 *
 * The file "<sys/file.h>" should be modified to contain the definitions
 * of the available operations, which must be added manually (see below
 * for the values).
 */

#include <unistd.h>
#include <sys/file.h>
#include <errno.h>

#ifndef LOCK_SH
#define LOCK_SH 1
#endif
#ifndef LOCK_EX
#define LOCK_EX 2
#endif
#ifndef LOCK_NB
#define LOCK_NB 4
#endif
#ifndef LOCK_UN
#define LOCK_UN 8
#endif

int
flock ( fd, operation)
int	fd,
	operation;
{
	int i;

	switch (operation) {

	/* LOCK_SH - get a shared lock */
	case LOCK_SH:
	/* LOCK_EX - get an exclusive lock */
	case LOCK_EX:
		i = lockf (fd, F_LOCK, 0);
		break;

	/* LOCK_SH|LOCK_NB - get a non-blocking shared lock */
	case LOCK_SH|LOCK_NB:
	/* LOCK_EX|LOCK_NB - get a non-blocking exclusive lock */
	case LOCK_EX|LOCK_NB:
		i = lockf (fd, F_TLOCK, 0);
		if (i == -1)
			if ((errno == EAGAIN) || (errno == EACCES))
				errno = EWOULDBLOCK;
		break;

	/* LOCK_UN - unlock */
	case LOCK_UN:
		i = lockf (fd, F_ULOCK, 0);
		break;

	/* Default - can't decipher operation */
	default:
		i = -1;
		errno = EINVAL;
		break;
	}

	return (i);
}
#endif

#if NEED_STRSTR

/*
 * Find the first occurrence of find in s.
 */
char *
strstr(s, find)
char	*s, *find;
{
	register char c,
	  sc;
	register size_t len;

	if ((c = *find++) != 0) {
		len = strlen(find);
		do {
			do {
				if ((sc = *s++) == 0)
					return (NULL);
			} while (sc != c);
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	return ((char *) s);
}
#endif

int
myisalnum( ch)
char ch;
{
	register unsigned char	c;

	c = (unsigned char) ch;
	return ( (( 47 < c) && ( c<58)) /* digit */
		|| ( ( 64<c) && ( c<91)) /* A-Z */
		|| ( ( 96<c) && ( c<123)) /* a-z */
		|| ( USE_LATIN1 && ( 191<c) && ( c<=255)) /* Latin1 */
		);
}

