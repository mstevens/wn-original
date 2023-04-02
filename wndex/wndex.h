/*
    Wn: A Server for the HTTP
    File: wndex/wndex.h
    Version 2.4.3
    
    Copyright (C) 1995-2002  <by John Franks>

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

#include "../config.h"
#include "../wn/common.h"
#include "err.h"

#define INDEX_TMPFILE		"indxcach.tmp"
#define MAPFILE_EXT		"map"
#define NUM_TITLE_LINES		(30)

#define streq( a, b)	( strcmp( (a), (b)) == 0 )

#define	SMALLBUF	(256)

#ifndef TRUE
#define TRUE	(1)
#endif

#ifndef FALSE
#define FALSE	(0)
#endif

#define WNDEX_NONE	(0)
#define WNDEX_ALL	(1)
#define WNDEX_INDEX	(2)

/* bits of flag */
#define WN_NOINDEX	(1)
#define WN_HASCONTENT	(2)
#define WN_HASENCODING	(4)
#define WN_ISLINK	(8)
#define WN_ISURL	(16)

/* bits of md5_attrib */
#define WN_DO_MD5	(1)	/* Calculate base64 of MD5 digest */
#define WN_DEF_DO_MD5	(2)	/* Calculate MD5 by default */
#define WN_UNDO_MD5	(4)	/* Choose not to do MD5 */
#define WN_NO_MD5		(8)	/* Can't do MD5 */

#define	hasencoding(x)	(x->flag & WN_HASENCODING)
#define hascontent(x)	(x->flag & WN_HASCONTENT)


extern void	init(),
		loadmime(),
		chop(),
		mksubd_list(),
		getcontent(),
		getkeytitle(),
		getmd5(),
		writeitem(),
		clear_slist(),
		add_to_slist(),
		add_charset(),
		do_serveall(),
		addpair();

extern int	recurse,
		errno,
		i_opt_used,
		stdioflg,
		strong_serveall,
		which_subdirs,
		verboseflg,
		fmt3(),
		quiet;


extern char	*get_next_line(),
		*strlower(),
		*md5digest(),
		cntlfname[],
		cntlf2name[],
		cachefname[];


typedef struct Entry {
	char	file[SMALLLEN],
		url[MIDLEN],
		title[MIDLEN],
		content[SMALLLEN],	/* content-type */
		charset[SMALLLEN], 
		md5[SMALLLEN/2],	/* base64 of MD5 hash */
		default_content[SMALLLEN],
		default_charset[SMALLLEN],
		owner[MIDLEN],
		cacheline[CACHELINE_LEN],
		subdirs[CACHELINE_LEN],
		accessfile[SMALLLEN],
		cntlfpath[MIDLEN],	/* path to index file */
		cntlf2path[MIDLEN],	/* path to index file */
		cachefpath[MIDLEN];	/* path to index.cache file */

	int	foundtitle,
		foundexp,
		foundkey,
		inlist,
		firsttime,
		isindexfile,
		serveall,
		doindex;


	unsigned	flag,
			md5_attrib,
			attributes,
			defattributes;

} Entry;

extern Entry	top;

#define fmt2( b, n, s1, s2)  fmt3( b, n, s1, s2, NULL)
#define mystrncat( b, s, n)	fmt3( b, n, b, s, NULL)
#define mystrncpy( b, s, n)	fmt3( b, n, s, NULL, NULL)
