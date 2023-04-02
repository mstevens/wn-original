/*
    Wn: A Server for the HTTP
    File: wn/wn.c
    Version 2.3.0
    
    Copyright (C) 1995-1999  <by John Franks>

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
#include "wn.h"


/*
 * www_unescape( path, pluschar) undoes what www_escape does.  Also change
 * any +'s to pluschar.  If an encoded newline or return is encountered,
 * null it and log err.
 */

void
www_unescape( path, pluschar)
char	*path,
	pluschar;

{

	register char	*cp,
			*cp2;
	int	val;

	char	minbuf[3];

	cp = cp2 = path;
	while ( *cp ) {
		switch ( *cp) {
		case '%':
			cp++;
			minbuf[0] = *cp++;
			minbuf[1] = *cp++;
			minbuf[2] = '\0';
			sscanf( minbuf, "%x", &val);
			*cp2 = (char) val;
			break;
		case '+':
			*cp2 = pluschar;
			cp++;
			break;
		default:
			*cp2 = *cp++;
		}
		if ( (*cp2 == '\n') || (*cp2 == '\r') ) {
			/* Found \r \n */
			*cp2 = '\0';
			logerr( err_m[65], "");
			break;
		}
		cp2++;
	}
	*cp2 = '\0';
}
