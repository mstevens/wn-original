/*
    Wn: A Server for the HTTP
    File: wn/vhost.c
    Version 2.3.13
    
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

#include <errno.h>
#include <string.h>

#include "wn.h"

#if USE_VIRTUAL_HOSTS

/*
 * The MAXVHOSTS line below sets the maximum number of virtual hosts
 * which can be listed in a virtual host file.  You can increase it
 * if you wish.
 */

#define	MAXVHOSTS	(64)

#ifndef VIRTUAL_HOSTS_FILE
#include "vhost.h"
#else
static char	*mark_token();


char *vhostlist[MAXVHOSTS][7] = 
{
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

char	vhostfile[SMALLLEN] = VIRTUAL_HOSTS_FILE;

void
load_virtual()
{
	register char	*cp;
	char	buf[SMALLLEN];

	FILE	*vhostfp;
	int	i = 0;

	if ( (vhostfp = fopen( vhostfile, "r")) == (FILE *) NULL) {
		daemon_logerr( err_m[99], vhostfile, errno);
		return;
	}

	while ( fgets( buf, MIDLEN, vhostfp)) {
		int len;

		chop( buf);
		if ( !buf[0] || buf[0] == '#')
			continue;
		len = strlen( buf) + 2;
		if ( (vhostlist[i][0] = malloc( len)) == NULL) {
			daemon_logerr( err_m[64], " load_virtual",  errno);
			return;
		}
		
		cp = buf;
		while ( *cp && isspace( *cp))  /* skip leading spaces */
			cp++;

		mystrncpy( vhostlist[i][0], cp, len);
		cp = vhostlist[i][0];			/* hostname */

		if ( !*cp ) {
			daemon_logerr( err_m[101], buf, 0);
			break;
		}

		cp = mark_token( cp);

		if ( *cp )
			vhostlist[i][1] = cp;	/* IP address */
		else {
			daemon_logerr( err_m[101], buf, 0);
			break;
		}

		cp = mark_token( cp);

		if ( *cp )
			vhostlist[i][2] = cp;	/* Root directory */
		else {
			daemon_logerr( err_m[101], buf, 0);
			break;
		}

		cp = mark_token( cp);

		if ( *cp ) {
			vhostlist[i][3] = cp;	/* Nickname */
			if ( streq( cp, "NULL") || streq( cp, ""))
				vhostlist[i][3] = NULL;
		}
		else {
			vhostlist[i][3] = NULL;
		}

		cp = mark_token( cp);

		if ( *cp ) {
			vhostlist[i][4] = cp;		/* User ID */
			if ( streq( cp, "NULL") || streq( cp, ""))
				vhostlist[i][4] = NULL;
		}
		else {
			vhostlist[i][4] = NULL;
		}

		cp = mark_token( cp);

		if ( *cp ) {
			vhostlist[i][5] = cp;		/* Group ID */
			if ( streq( cp, "NULL") || streq( cp, ""))
				vhostlist[i][5] = NULL;
		}
		else {
			vhostlist[i][5] = NULL;
		}

		cp = mark_token( cp);

		if ( *cp ) {
			vhostlist[i][6] = cp;		/* vhost flags */
			if ( streq( cp, "NULL") || streq( cp, ""))
				vhostlist[i][6] = NULL;
		}
		else {
			vhostlist[i][6] = NULL;
		}


		while ( *cp && !isspace( *cp))
			cp++;
		if ( *cp )
			*cp = '\0';

		i++;
		if ( i >= MAXVHOSTS) {
			daemon_logerr( err_m[100], "",  0);
			return;
		}
	}
	vhostlist[i][0] = vhostlist[i][1] = vhostlist[i][2] 
			= vhostlist[i][3] = vhostlist[i][4] 
			= vhostlist[i][5] = vhostlist[i][6] = NULL;

	fclose( vhostfp);
}

static char *
mark_token( ptr)
char	*ptr;
{

	register char *cpl;

	cpl = ptr;

	while ( *cpl && !isspace( *cpl))
		cpl++;

	if ( *cpl )
		*cpl++ = '\0';

	while ( *cpl && isspace( *cpl))
		cpl++;

	return cpl;
}

#endif /* VIRTUAL_HOSTS_FILE */
#endif /* USE_VIRTUAL_HOSTS */

