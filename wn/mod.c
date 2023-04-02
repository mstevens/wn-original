/*
    Wn: A Server for the HTTP
    File: wn/mod.c
    Version 2.3.1
    
    Copyright (C) 1996-2000  <by John Franks>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 1, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/


#include <string.h>
#include <ctype.h>
#include "wn.h"

static int	mon2int(),
		getnum();


/*
 * date_cmp( ip, ext_date, ims)
 * Take ext_date  and compare it with the file's  last modified date
 * if ims == TRUE.  Otherwise compare with current date. Return TRUE if 
 * ext_date is earlier than  date (current or last modified) or if 
 * ext_date is not understood and return FALSE otherwise.  We understand
 * dates of the form
 * Sun, 06 Nov 1995 08:49:37 GMT   ; RFC 822, updated by RFC 1123, or
 * Sunday, 06-Nov-94 08:49:37 GMT  ; RFC 850, obsoleted by RFC 1036
 * but NOT Sun Nov  6 08:49:37 1994 ; ANSI C's asctime() format. The
 * ext_date may be contained in quotes.
 */

int
date_cmp( ip, ext_date, ims)
Request	*ip;
char	*ext_date;
int	ims;	/* TRUE for If-Modified-Since */
{
	register char	*cp,
			*cp2;

	char		buf[SMALLLEN];

	int		n1,
			len = 0;

	time_t		clock;

	struct	tm	remote_tm,
			*ltm_p;


	if ( ims && !ip->mod_time)
		return TRUE;

	mystrncpy( buf, ext_date, SMALLLEN);

	bzero( &remote_tm, sizeof( remote_tm));

	/* Remove surrounding quotes, if any */
	if ( (cp = strrchr( buf, '"')) != NULL) 
		*cp = '\0';

	if ( (cp = strchr( buf, '"')) == NULL) 
		cp = buf;
	else
		cp++;

	cp2 = cp;
	/* Skip past any day-of-week-comma */
	if ( (cp = strchr( cp2, ',')) == NULL) 
		cp = cp2;
	else
		cp++;

	len = 2;  /* assume format is Sun, 06 Nov 1994 08:49:37 GMT  */

	if ( ( cp2 = strchr( cp, '-')) != NULL ) {
		if ( strncmp( cp2, "-->", 3) != 0) {
			/* format is Sunday, 06-Nov-94 08:49:37 GMT */
			len = 0;
		}
		else {
			*cp2 = '\0';
		}
	}

	while ( isspace( *cp) )
		cp++;
	remote_tm.tm_mday = getnum( cp, 2);

	if ( (remote_tm.tm_mon = mon2int( cp + 3)) < 0 ) {
		/* Messed up date, do a GET */
		logerr( err_m[80], buf);
		return TRUE;
	}

	n1 = getnum( cp + 7, len + 2);
	if ( len == 0 )     /* n1 = two digit year */
		remote_tm.tm_year = ( n1 < 69 ? n1 + 100 : n1);
	else         /* n1 = four digit year */
		remote_tm.tm_year = ( n1 - 1900);

	remote_tm.tm_hour = getnum( cp + len + 10, 2);
	remote_tm.tm_min = getnum( cp + len + 13, 2);
	remote_tm.tm_sec = getnum( cp + len + 16, 2);

	if ( (remote_tm.tm_hour > 23 ) || (remote_tm.tm_min > 59) ||
				(remote_tm.tm_sec > 59) ) {
		/* Messed up date, do a GET */
		logerr( err_m[80], buf);
		return TRUE;
	}

	if ( ims)
		ltm_p = gmtime(&ip->mod_time);
	else {
		time( &clock);
		ltm_p = localtime(&clock);
	}

	if ( ltm_p->tm_year != remote_tm.tm_year)
		return ( ltm_p->tm_year > remote_tm.tm_year);

	if ( ltm_p->tm_mon != remote_tm.tm_mon)
		return ( ltm_p->tm_mon > remote_tm.tm_mon);

	if ( ltm_p->tm_mday != remote_tm.tm_mday)
		return ( ltm_p->tm_mday > remote_tm.tm_mday);

	if ( ltm_p->tm_hour != remote_tm.tm_hour)
		return ( ltm_p->tm_hour > remote_tm.tm_hour);

	if ( ltm_p->tm_min != remote_tm.tm_min)
		return ( ltm_p->tm_min > remote_tm.tm_min);

	return ( ltm_p->tm_sec > remote_tm.tm_sec);
}


static int
getnum( s, n)
char	*s;
int	n;
{
	int	val;

	val = 0;
	while ( *s && (n > 0) ) {
		val = 10*val + ( *s - '0');
		n--;
		s++;
	}
	return val;
}



static int
mon2int( month)
char	*month;
{
	switch (*month) {
	case 'A':
		return ( *++month == 'p' ? 3 : 7);
	case 'D':
		return (11);
	case 'F':
		return (1);
	case 'J':
		if ( *++month == 'a' )
			return (0);
		return ( *++month == 'n' ? 5 : 6);
	case 'M':
		return ( *(month+2) == 'r' ? 2 : 4);
	case 'N':
		return (10);
	case 'O':
		return (9);
	case 'S':
		return (8);
	default:
		return (-1);
	}
}

