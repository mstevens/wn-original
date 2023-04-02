/*
    WN: A Server for the HTTP
    File: authwn/authwn.h
    Version 2.3.1
    
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


#ifndef WN_PAMAUTH
typedef struct {
	unsigned long int state[4];
	unsigned long int count[2];
	unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

void	MD5_Init( ),
	MD5_Update( ),
	MD5_Final( );
#endif

/*
 * Authorization modules should exit with a status indicating that
 * access is granted, denied or an error occurred.  The #defines 
 * listed here specify the error status to use for granting, denying
 * or indicating certain errors.  Any exit status > 30 are available
 * for the programmers use and the decimal value of such a status
 * will be logged in the error log.
 */

#define AUTH_GRANTED	(0)
#define AUTH_DENIED	(1)
#define AUTH_EXPIRED	(2)

#define AUTHERR_NUM3	(3)	/* Badly formed user info string */
#define AUTHERR_NUM4	(4)	/* Can't open passwd file */
#define AUTHERR_NUM5	(5)	/* Can't init dbm file */
#define AUTHERR_NUM6	(6)	/* Can't open group file */
#define AUTHERR_NUM7	(7)	/* No password file listed on command line */
#define AUTHERR_NUM8	(8)	/* DBM code for authorization not installed */
#define AUTHERR_NUM9	(9)	/* Unknown authorization type */
#define AUTHERR_NUM10	(10)	/* No AUTHORIZATION line */
/* AUTHERR_NUM11-14 are used in digest authentication */

#define AUTHERR_NUM16	(16)	/* Timed Out */
#define AUTHERR_NUM18	(18)	/* DBM data too large or missing*/
#define AUTHERR_NUM19	(19)	/* "wnauth: Can't open %s\n" */
/* AUTHERR_NUM20-21 are used in PAM authentication */


char *authlog_m[] = {

	/* 0 */ "Granted %s",
	/* 1 */ "Denied %s",
	/* 2 */ "Expired",
	/* 3 */	"Badly formed user info string: %s",
	/* 4 */	"Can't open passwd file: %s",
	/* 5 */	"Can't init dbm file: %s",
	/* 6 */	"Can't open group file: %s",
	/* 7 */	"No password file listed on command line",
	/* 8 */	"DBM code for authorization not installed",
	/* 9 */	"Unknown authorization type: %s",
	/* 10 */ "No AUTHORIZATION line",
	/* 11 */ "",
	/* 12 */ "",
	/* 13 */ "",
	/* 14 */ "",
	/* 15 */ "data to be digested too long",
	/* 16 */ "Timed Out",
	/* 17 */ "No realm available",
	/* 18 */ "DBM data too large or missing",
	/* 19 */ "wnauth: Can't open %s\n" 
	/* 20 */ "wnauth: Unknown option: %c" 
};

