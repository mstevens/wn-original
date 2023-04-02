/*
    Wn: A Server for the HTTP
    File: wndex/serveall.c
    Version 2.0.7
    
    Copyright (C) 1996, 1997  <by John Franks>

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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include "wndex.h"

#ifndef NEED_DIR_H
#include <dirent.h>
#else
#include <sys/dir.h>
#endif

#define LIST_SIZE	(2048)

#define WNDEX_NO_STAT	(1)
#define WNDEX_DIR	(2)
#define WNDEX_FILE	(3)

static int	isafile(),
		slist_num;

static char	*listdp,
		*slist[LIST_SIZE],
		list_data[32*LIST_SIZE];

void
clear_slist( ) 
{
	slist_num = 0;
	listdp = list_data;
}

void
add_to_slist( name) 
char	*name;
{
	char	*cp;

	cp = listdp + strlen( name) + 1;

	if ( (slist_num >= LIST_SIZE)
			|| ( cp >= list_data + sizeof (list_data))) {
		fprintf( stderr, ERRMSG21);
		exit( 2);
	}

	strcpy( listdp, name);

	slist[ slist_num++] = listdp;

	listdp = cp;
}	

static int
match_slist( file) 
char	*file;
{
	int	i;

	for ( i = 0; i < slist_num; i++ ) {
		if ( streq( file, slist[i]))
			return TRUE;
	}
	return FALSE;
}


void
do_serveall( dirpath, cfp, hfp, ep)
char	*dirpath;
FILE	*cfp,
	*hfp;
Entry	*ep;
{

	DIR	*dirp;
#ifndef NEED_DIR_H
	struct dirent	*dp;
#else
	struct direct	*dp;
#endif

	if ( (dirp = opendir( dirpath)) == NULL) {
		fprintf( stderr, ERRMSG22, dirpath);
		exit( 2);
	}
	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
		if ( streq( dp->d_name, cachefname))
			continue;
		if ( streq( dp->d_name, INDEX_TMPFILE))
			continue;
		if ( streq( dp->d_name, cntlfname))
			continue;
		if ( streq( dp->d_name, ep->accessfile))
			continue;
		if ( *(dp->d_name) == '.')
			continue;
		if ( (dp->d_name)[strlen(dp->d_name) - 1] == '~')
			continue;
		if (match_slist( dp->d_name))
			continue;

		if ( isafile( dirpath, dp->d_name, TRUE) != WNDEX_FILE)
			continue;
		mystrncpy( ep->file, dp->d_name, SMALLLEN);
		addpair("file", dp->d_name, ep);
		writeitem( cfp, hfp, ep);
		
	}
	closedir (dirp);
}


void
mksubd_list( dirpath, ep)
char	*dirpath;
Entry	*ep;
{

	int	n;
	char	*subp;

	DIR	*dirp;
#ifndef NEED_DIR_H
	struct dirent	*dp;
#else
	struct direct	*dp;
#endif


	if ( (dirp = opendir( dirpath)) == NULL) {
		fprintf( stderr, ERRMSG28, dirpath);
		return;
	}
	subp = ep->subdirs;
	for (dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
		if ( isafile( dirpath, dp->d_name, TRUE) != WNDEX_DIR)
			continue;
		if ( *(dp->d_name) == '.')
			continue;
		if ( strchr(dp->d_name, '~') != NULL)
			continue;

		if ( which_subdirs == WNDEX_INDEX) {
			char	lbuf[MIDLEN];

			mystrncpy( lbuf, dirpath, MIDLEN - SMALLLEN);
			strcat( lbuf, "/");
			mystrncat( lbuf, dp->d_name, SMALLLEN);	
			if ( isafile( lbuf, CONTROLFILE_NAME, FALSE)
								!= WNDEX_FILE)
				continue;
		}

		n = strlen( dp->d_name);
		if ( subp + n >= ep->subdirs + sizeof (ep->subdirs)) {
			fprintf( stderr, ERRMSG29);
			exit( 2);
		}
		
		mystrncpy( subp, dp->d_name, SMALLLEN);
		subp += n;
		*subp++ = ',';
	}

	if ( subp > ep->subdirs)
		*--subp = '\0';

	closedir (dirp);
}


/*
 * isafile( dirpath, fname, verbose)
 * Stats the file dirpath/fname.  If it fails issue warning return 
 * WNDEX_NO_STAT.   If it is a directory return WNDEX_DIR, else return
 * WNDEX_FILE.
 */

static int
isafile( dirpath, fname, verbose)
char	*dirpath,
	*fname;
int	verbose;
{
	struct stat stat_buf;
	char	buf[MIDLEN];

	mystrncpy( buf, dirpath, MIDLEN);
	mystrncat( buf, "/", MIDLEN);
	mystrncat( buf, fname, MIDLEN );
	if ( stat( buf, &stat_buf) != 0 ) {
		if ( !quiet && verbose)
			fprintf( stderr, ERRMSG24, buf);

		return WNDEX_NO_STAT;
	}


	if ( S_ISDIR( stat_buf.st_mode)) {
		return WNDEX_DIR;
	}
	return WNDEX_FILE;
}

