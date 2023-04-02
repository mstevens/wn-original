/*
    WN: A Server for the HTTP
    File: wnputh/puth.h
    Version 2.3.9
    
    Copyright (C) 2000  <by John Franks>

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

#define PUT_FILE_PERMS	(0644)

#define MIDLEN		2048
#define SMALLLEN	256
#define TINYLEN		32

#ifndef TRUE
#define TRUE	(1)
#endif

#ifndef FALSE
#define FALSE	(0)
#endif

#define streq( a, b)	( strcmp( (a), (b)) == 0 )


/*
 * Authorization modules should exit with a status indicating that
 * access is granted, denied or an error occurred.  The #defines 
 * listed here specify the error status to use for granting, denying
 * or indicating certain errors.  Any exit status > 30 are available
 * for the programmers use and the decimal value of such a status
 * will be logged in the error log.
 */

#define P_ERRMSG1	"Can't get method"
#define P_ERRMSG2	"Can't get URI filename"
#define P_ERRMSG3	"Can't get temp filename"
#define P_ERRMSG4	"Can't create new file: "
#define P_ERRMSG5	"Can't unlink file: "
#define P_ERRMSG6	"Can't get new URI filename"
#define P_ERRMSG7	"Can't rename URI to: "
#define P_ERRMSG8	"Unsuuported method: "
#define P_ERRMSG9	"Move filename has no '/'"
#define P_ERRMSG10	"Can't chown tempfile: "
#define P_ERRMSG11	"Can't chmod file: "
#define P_ERRMSG12	"Unknown option to puth: "


#define P_ERRMSG16	"Timed Out"




