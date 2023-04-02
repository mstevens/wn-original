/*
    Wn: A Server for the HTTP
    File: wn/image.c
    Version 2.4.0
    
    Copyright (C) 1995-2001  <by John Franks>

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
#include "image.h"

#define HIT_IT	(111)	/* anything bigger than 2 works fine here */

extern long	atol();

static long	xclick,
		yclick;

static void	setpoint();

static int	setpoint_firsttime,
		dorect(),
		dopoly(),
		docircle(),
		segment();


static char	*getcoords();



void
image( )
{
	register char	*cp,
			*cp2;

	FILE	*fp;
	char	*url,
		*coords,
		*method,
		linebuf[MIDLEN],
		default_url[MIDLEN];

	int	res,
		coords_ok;

	default_url[0] = '\0';
	res = coords_ok = FALSE;
	setpoint_firsttime = TRUE;

	check_perm( this_rp, this_rp->filepath);

	if ( (cp = getcoords( &xclick, &yclick, this_rp->query)) != NULL )
		coords_ok = TRUE;

	if ( this_rp->status & WN_ABORTED)
		return;

	if ( (fp = fopen( this_rp->filepath, "r")) == (FILE *) NULL ) {
		logerr( err_m[1], this_rp->filepath);
		wn_abort( );
		return;
	}

	while ( fgets( linebuf, MIDLEN, fp)) {
		chop( linebuf);
		cp = linebuf;
		while ( isspace( *cp))
			cp++;

		method = cp2 = cp;
		while ( *cp2 && !isspace( *cp2))
			cp2++;

		if ( *cp2)
			*cp2++ = '\0';

		while ( *cp2 && isspace( *cp2))
			cp2++;
		
		url = cp2;

		while ( *cp2 && !isspace( *cp2))
			cp2++;

		if ( *cp2)
			*cp2++ = '\0';

		while ( *cp2 && isspace( *cp2))
			cp2++;
		coords = cp2;

		if ( !coords_ok) {
			if ( tolower(*method) == 'n') {
				mystrncpy( default_url, url, MIDLEN);
				break;
			}
			continue;
		}
		else {		/* coords_ok = TRUE */

			switch ( tolower(*method)) {
			case 'c':
				if ( (res = docircle( url, coords)) )
					break;
				continue;
			case 'd':
				mystrncpy( default_url, url, MIDLEN);
				continue;
			case 'p':
				if ( strncasecmp( method, "point", 5) == 0 ) {
					setpoint( url, coords, default_url);
					if ( this_rp->status & WN_ABORTED)
						return;
					continue;
				}
				else
					if ( (res = dopoly( url, coords)) )
						break;
						/* Polygon */
				continue;
			case 'r':
				if ( (res = dorect( url, coords)) )
					break;
				continue;
			default:
				continue;

			}
			break;	/* break out of while */
		}
		
	}

	if ( this_rp->status & WN_ABORTED)
		return;

	if ( *default_url && !res )
		dolocation( default_url, this_rp, 302);
	else if ( !res) {
		if ( !coords_ok)
			senderr( SERV_ERR, IMAGE_ERR1, this_rp->query);
		else
			senderr( SERV_ERR,IMAGE_ERR2, "");
		wn_abort( );
		return;
	}
	/* return to process_url */
}

/*
 * getcoords( x, y, text) Take text of the form "n1,n2" and place the
 * value of n1 in *x, the value of n2 in *y.  Do some error checking.
 * It returns a pointer to the char after n2 or NULL if nothing found.
 */

static char *
getcoords( x, y, text)
long	*x,
	*y;
char	*text;
{
	register char	*cp,
			*xptr,
			*yptr;

	char	buf[ MIDLEN];

	mystrncpy( buf, text, MIDLEN);
	cp = buf;

	while ( *cp && isspace( *cp))
		cp++;

	if ( !*cp )
		return NULL;

	xptr = cp;

	while ( *cp && !isspace( *cp))
		cp++;
	*cp = '\0';

	text += (cp - buf);
	yptr = xptr;
	while ( *yptr && (*yptr != ','))
		yptr++;

	if (*yptr != ',') {
		senderr( CLIENT_ERR, IMAGE_ERR1, text);
		wn_abort( );
		return NULL;
	}
	*yptr++ = '\0';

	if ( (!isdigit( *xptr)) || (!isdigit( *yptr))) {
		senderr( CLIENT_ERR, IMAGE_ERR1, text);
		wn_abort( );
		return NULL;
	}

	*x = atol( xptr);
	*y = atol( yptr);

	return text;

}

/*
 * If coords in region call dolocation for URL and return TRUE.  Otherwise
 * return FALSE.
 */

static int
dorect( url, coords)
char	*url,
	*coords;
{
	long	x1,	/* (x1,y1) = upper left */
		y1,
		x2,	/* (x2,y2) = lower right */
		y2;

	register char	*cp;

	if ( ((cp = getcoords( &x1, &y1, coords)) == NULL) ||
				(getcoords( &x2, &y2, cp) == NULL) ) {
		senderr( SERV_ERR, IMAGE_ERR1, coords);
		wn_abort( );
		return FALSE;
	}

	if ( (x1 <= xclick) && (x2 >= xclick) &&
				(y1 <= yclick) && (y2 >= yclick) ) {
		dolocation( url, this_rp, 302);
		return TRUE;
	}
	return FALSE;
}

/*
 * If coords in region call dolocation for URL and return TRUE.  Otherwise
 * return FALSE.
 */

static int
docircle( url, coords)
char	*url,
	*coords;
{
	unsigned long	radius,
			dist;

	long	x1,	/* (x1,y1) = center */
		y1,
		x2,	/* (x2,y2) = point on circle */
		y2;

	char	*cp;

	if ( ((cp = getcoords( &x1, &y1, coords)) == NULL) ||
				(getcoords( &x2, &y2, cp) == NULL) ) {
		senderr( SERV_ERR, IMAGE_ERR1, coords);
		wn_abort( );
		return FALSE;
	}

	radius = (unsigned long)((x1 - x2)*(x1 - x2) + (y1 - y2)*(y1 - y2));
	dist = (unsigned long) ((x1 - xclick) * (x1 - xclick) + 
			(y1 - yclick) * (y1 - yclick));

	if ( dist <= radius) {
		dolocation( url, this_rp, 302);
		return TRUE;
	}
	return FALSE;
}


static void
setpoint( url, coords, d_url)
char	*url,
	*coords,
	*d_url;
{
	static unsigned long	min_dist;
	unsigned long		dist;


	long	x1,
		y1;
	char	*cp;

	cp = coords;
	while ( (cp = getcoords( &x1, &y1, cp)) != NULL) {
		dist = (unsigned long) ((x1 - xclick) * (x1 - xclick)
			+ (y1 - yclick) * (y1 - yclick));

		if ( setpoint_firsttime || (dist < min_dist)) {
			min_dist = dist;
			mystrncpy( d_url, url, MIDLEN);
			setpoint_firsttime = FALSE;
		}
	}
}

/*
 * If coords in region call dolocation for URL and return TRUE.  Otherwise
 * return FALSE.
 */

static int
dopoly( url, coords)
char	*url,
	*coords;
{
	long	firstx,
		firsty,
		x,
		y;

	int	cross,
		crossnum;
	char	*cp;

/*
 * We calculate crossnum, which is twice the crossing number of a
 * ray from (xclick,yclick) parallel to the positive X axis.
 * A coordinate change is made to move (xclick, yclick) to the origin.
 * Then the function segment() is called to calculate the crossnum of
 * one segment of the translated polygon with the ray which is the
 * positive X-axis.
 */

	crossnum = 0; 
	cp = coords;
	if ( (cp = getcoords( &x, &y, cp)) == NULL) {
		senderr( SERV_ERR, IMAGE_ERR1, coords);
		wn_abort( );
		return FALSE;
	}
	firstx = x;
	firsty = y;
/*
 * Don't count cross the first time segment is called.  It just 
 * initializes the previous point in segment().
 */
	if ( segment( x - xclick, y - yclick) == HIT_IT) {
		dolocation( url, this_rp, 302);  /* clicked on a vertex */
		return TRUE;
	}

	while ( (cp = getcoords( &x, &y, cp)) != NULL) {
		if ( (cross = segment( x - xclick, y - yclick)) == HIT_IT ) {
			dolocation( url, this_rp, 302); /* clicked on vertex */
			return TRUE;
		}
		crossnum += cross;
	}

	if ( this_rp->status & WN_ABORTED)
		return FALSE;

	if ( (cross = segment( firstx - xclick, firsty - yclick)) == HIT_IT ) {
		dolocation( url, this_rp, 302); /* clicked on a vertex */
		return TRUE;
	}
	crossnum += cross;
	if ( crossnum != 0 ) {
		dolocation( url, this_rp, 302);
		return TRUE;
	}
	return FALSE;
}


/*
 * The function segment() returns +2, or -2 if the segment from (x,y)
 * to previous (x,y) crosses the positive X-axis positively or negatively.
 * It returns +1 or -1 if one endpoint is on this ray, or 0 if both are.
 * It returns 0 if the ray and the segment don't intersect.
 * It returns HIT_IT if the segment contains (0,0)
 */

static int
segment( x, y)
long	x,
	y;
{
	static long	px = 0,
			py = 0;	/* previous x and y, initial value arbitrary */

	long		z,
			x2,
			y2;

	int		sgn;

	x2 = px;
	y2 = py;
	px = x;
	py = y;

	/* If (x2,y2) = (0,0) and not first call we have already sent HIT_IT */

	if ( y == 0 ) {
		if ( x == 0 )
			return HIT_IT;
		if ( x > 0 ) {
			if ( y2 == 0 )
				return ( x2 > 0 ? 0 : HIT_IT);
			return ( y2 < 0 ? 1 : -1);
		}
		else {	/* x < 0 */
			if ( y2 == 0 )
				return ( x2 < 0 ? 0 : HIT_IT);
			return ( 0);
		}
	}

	/* Now we know y != 0;  set sgn to sign of y */
	sgn = ( y > 0 ? 1 : -1 );
	if ( y2 == 0 )
		return ( x2 < 0 ? 0 : sgn );
	if ( sgn * y2 > 0 )	/* y and y2 have same sign */
		return (0);
	else {			/* y and y2 have opposite signs */
		if ( (x >= 0) && (x2 > 0) )
			return (2 * sgn);
		if ( (x < 0) && (x2 <= 0) )
			return (0);

		z = (x-x2) * y - (y-y2) * x;
		if ( z == 0 )
			return HIT_IT;
		return ( sgn*z > 0 ? 0 : 2 * sgn);
	}
}

