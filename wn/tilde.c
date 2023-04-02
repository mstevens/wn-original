/*
    Wn: A Server for the HTTP
    File: wn/tilde.c
    Version 2.3.10

    Copyright (C) 1995-2000  <by John Franks>
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


#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include "wn.h"

extern struct passwd *getpwnam();


static char	tus[] = TILDE_USER_STRING;

static int	get_user_dir( );

/*
 * tilde( path) translates the URI /~user/foo to /foo
 * and changes the rootdir to /home/user/PUB_HTML where 
 * /home/user is either the home directory of user and 
 * PUB_HTML is #defined in config.h.
 */

void
tilde( ip, path)
Request	*ip;
char	*path;
{
	int		i,
			tslen;
	register char	*cp,
			*cp2;

	char		*name,
	 		tredirect[MIDLEN];

	tslen = sizeof( tus);
	tslen--;
	if ( strncmp( path, tus, tslen)) {
		*(ip->user_dir) = '\0';
		return;
	}

	if ( (ip->vhost_flag) & VHOST_NO_USERDIR) {
		*(ip->user_dir) = '\0';
		senderr( CLIENT_ERR, err_m[145], "");
		return;
	}

	cp2 = ip->user_dir;
	*cp2++ = tus[0];
	cp = path + 1;
	i = 1;
	while ( *cp && ( ( i < tslen) || (*cp != '/')) && (i < USERNAME_LEN-1)) {
		/* copy path+1 to ip->user_dir 
		   until a '/' after tus is reached */
		i++;
		*cp2++ = *cp++;
	}
	*cp2 = '\0';

	name = ip->user_dir + tslen;
 	if (get_user_dir( name, tredirect)) {
		/* redirection needed */
	 	char	*p;
 
		if ( ip->type == RTYPE_FINISHED)
			return; /* to parse_request() */

 		p = tredirect + strlen( tredirect);

		/* add path, removing excess '/' if necessary */
		if ((*cp == '/') && (*(p-1) == '/')) {
			*--p = '\0';
		}

 		mystrncat (tredirect, cp, MIDLEN);

 		sendredirect( ip, "301 Moved Permanently", tredirect);
		ip->type = RTYPE_FINISHED;
		return;
 	}
	else
		mystrncpy( path, cp, MIDLEN);

	return;
}

static int
get_user_dir( name, redirp)
char	*name,
	*redirp;
{
	int	found = FALSE;	/* user name found or not */
	int	redir = FALSE;	/* redirection indicated or not */

	if ( USE_TILDE_PWFILE) {
		struct passwd	*pws;
		char 	buf[SMALLLEN];
  
		if ( ((pws = getpwnam( name)) != NULL)
				&& ( pws->pw_uid >= LEAST_UID)) {

			Snprintf2( buf, SMALLLEN, "%.150s:%d", name, pws->pw_gid);
			this_rp->tilde_user_group = strdup( buf);

			mystrncpy( this_rp->rootdir, pws->pw_dir, SMALLLEN);
			mystrncat( this_rp->rootdir, PUB_HTML, SMALLLEN );
			found = TRUE;
		}
	}
	else if ( USE_TILDE_TABLE) {

		register char	*cp;
		FILE	*fp;
		char	linebuf[MIDLEN];

		if ( (fp = fopen( TILDE_TABLE, "r")) == (FILE *) NULL ) {
			senderr( SERV_ERR, err_m[69], TILDE_TABLE);
			return FALSE;  /* to tilde() */
		}

		while ( fgets( linebuf, MIDLEN, fp)) {
			if ( !chop( linebuf)) {
				senderr( SERV_ERR, err_m[71], linebuf);
				return FALSE;  /* to tilde() */
			}

			if ( *linebuf == '#')
				continue;

			if ( (cp = strchr(linebuf, ':')) == NULL) {
				logerr( err_m[72], linebuf);
				continue;
			}
			*cp++ = '\0';
			if ( streq( name, linebuf)) {
				if (*cp == ':') { /* second colon = redirect */
					redir = TRUE;
					cp++;
					mystrncpy( redirp, cp, MIDLEN);
				}
				else {
					mystrncpy( this_rp->rootdir, cp, SMALLLEN);
				}
				found = TRUE;
				break;
			}
		}
		fclose( fp);
	}
	if (!found) {
		senderr( CLIENT_ERR, err_m[67], "");
		return FALSE;  /* to tilde() */
	}
	return (redir);
}
