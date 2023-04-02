/*
    Wn: A Server for the HTTP
    File: wndex/init.c
    Version 2.3.4
    
    Copyright (C) 1996-1999  <by John Franks>

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
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "wndex.h"
#include "version.h"

int	recurse = FALSE,
	strong_serveall = FALSE,
	which_subdirs = WNDEX_NONE,
	stdioflg = FALSE,
	verboseflg = FALSE,
	i_opt_used = FALSE,
	quiet	= FALSE;

char	cntlfname[MIDLEN],
	cntlf2name[MIDLEN],
	cachefname[MIDLEN];

	
extern char *optarg;
extern int optind;


void
init( argc, argv)
int	argc;
char	*argv[];
{
	int	c,
		dflg = FALSE,
		errflg = FALSE;
	char	*dir = NULL;

	umask( 033);
	mystrncpy( cntlfname, CONTROLFILE_NAME, MIDLEN);
	mystrncpy( cntlf2name, CONTROLFILE2_NAME, MIDLEN);
	mystrncpy( cachefname, CACHEFNAME, MIDLEN);

	while ((c = getopt(argc, argv, "aqrVvxc:d:i:s:")) != -1) {
		switch ((char) c) {
			case 'r':
				recurse = TRUE;
				break;
			case 'a':
				strong_serveall = TRUE;
				break;
			case 's':
				if ( streq( optarg, "all"))
					which_subdirs = WNDEX_ALL;
				else if ( streq( optarg, "index"))
					which_subdirs = WNDEX_INDEX;
				else 
					fprintf( stderr, ERRMSG30, c, optarg);
				break;
			case 'q':
				quiet = TRUE;
				break;
			case 'd':
				dflg = TRUE;
				dir = optarg;
				break;
			case 'i':
				mystrncpy( cntlfname, optarg, MIDLEN);
				i_opt_used = TRUE;
				cntlf2name[0] = '\0';
				break;
			case 'c':
				mystrncpy( cachefname, optarg, MIDLEN);
				break;
			case 'v':
				verboseflg = TRUE;
				break;
			case 'V':
				printf( "Wndex: version %s\n", VERSION);
				exit( 0);
			case 'x':
				stdioflg = TRUE;
				break;
			case '?':
				errflg = TRUE;
		}
	}

	if (errflg) {
		fprintf( stderr, "Usage:\n");
		fprintf( stderr,"%s [-a] [-i] [-r] [-s all|index] [-q] [-v]\n",
				argv[0]);
		fprintf( stderr, "[-d dir] [-i indexfile] [-c cachefile]\n");
		exit (2);
	}

	if ( recurse && strong_serveall && (which_subdirs == WNDEX_NONE))
		which_subdirs = WNDEX_ALL;

	loadmime();

	if ( dflg ) {
		fmt3( top.cntlfpath, MIDLEN, dir, "/", cntlfname);
		fmt3( top.cachefpath, MIDLEN, dir, "/", cachefname);
		if ( *cntlf2name)
			fmt3( top.cntlf2path, MIDLEN, dir, "/",
				cntlf2name);
		else
			top.cntlf2path[0] = '\0';
	} else {
		if ( *cntlfname == '/') 
			mystrncpy(top.cntlfpath, cntlfname, MIDLEN);
		else
			fmt2( top.cntlfpath, MIDLEN, "./", cntlfname);

		if ( *cntlf2name == '/') 
			mystrncpy(top.cntlf2path, cntlf2name, MIDLEN);
		else if ( *cntlf2name ) 
			fmt2( top.cntlf2path, MIDLEN, "./", cntlf2name);
		else
			top.cntlf2path[0] = '\0';

		if ( *cachefname == '/') 
			mystrncpy(top.cachefpath, cachefname, MIDLEN);
		else
			fmt2( top.cachefpath, MIDLEN, "./", cachefname);
	}

}

/* chop( line)  Cut out CRLF at end of line */

void
chop( line)
char *line;
{
	char	*p;

	if ( *line == '\0')
		return;
	if ( (p = strchr( line, '\n')) == (char *) NULL )
		return;
	if ( *--p != '\r')
		p++;
	*p = '\0';
}
