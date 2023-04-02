/*
    Wn: A Server for the HTTP
    File: wn/wn.h
    Version 2.4.5
    
    Copyright (C) 1996-2003  <by John Franks>

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

#ifndef	TRUE
#define TRUE	(1)
#define FALSE	(0)
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>


#ifndef MAKE_WNSSL
#define  MAKE_WNSSL	(FALSE)
#else
#undef MAKE_WNSSL
#define  MAKE_WNSSL	(TRUE)
#endif


#ifndef STANDALONE
#define STANDALONE	(FALSE)
#endif

#if MAKE_WNSSL
#include "../config_ssl.h"

extern int	WN_write(),
		WN_read();
#else
#include "../config.h"
#define WN_write( a, b, c)		write( a, b, c)
#define WN_read( a, b, c)		read( a, b, c)
#endif

#if (!WN_SU_EXEC)
#define WN_popen			popen
#endif

#include "common.h"


#define WN_HTML_MARK	"WN_mark"
#define	ACCEPTLEN (2048)
#define MAXDIRLEN (256)
#define NUMFIELDS (20)

#define FREE	(0)
#define ROOTCHK	(1)
#define DIRCHK	(2)

#define FRP_FILE	(0)
#define FRP_PIPE	(1)

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	(256)
#endif

#define CLIENT_ERR		"400"
#define DENYSTATUS		"404"
#define PRECON_FAILED_STATUS	"412"
#define REQ_TOO_LONG_STATUS	"413"
#define URI_TOO_LONG_STATUS	"414"
#define SERV_ERR		"500"


#if WN_SU_EXEC
extern FILE	*WN_popen();
#endif

extern FILE	*safer_popen();

extern WN_CONST
char * WN_CONST	err_m[];
extern WN_CONST
char * WN_CONST	log_m[];
extern WN_CONST
char * WN_CONST	search_m[];
extern WN_CONST
char * WN_CONST	out_m[];


extern char	rootdir[],
		wn_empty[],
		wn_tmpdir[],
		wnlogfile[],
		errlogfile[],
		pid_file[],
		vhostfile[],
		cfname[],
		afname[],
		hostname[],
		listen_ip[],
		**mtypelist,
		**suflist,
		*mymemcpy(),
		*get_parse_line(),
		*strlower();

extern unsigned	alarm(),
		cache_id,
		acache_id,
		default_logtype,
		interface_num;


extern int	errno,
		port,
		admin_mode,
		nofork,
		debug_log,
		chop(),
		fmt3(),
		mystrncpy(),
		mystrncat2(),
		needsuffix(),
		modified(),
		date_cmp(),
		getfpath(),
		getfpath2(),
		chkaccess(),
		amperline(),
		http_prolog(),
		set_show(),
		get_parse_token(),
		myisalnum(),
		do_ifexpr(),
		read_cache_file();

extern void	wn_init(),
		init_mime(),
		wn_abort(),
		wn_exit(),
		flush_outbuf(),
		send_out_mem(),
		send_out_fd(),
		load_virtual(),
		get_mtype(),
		set_etag(),
		rfc931(),
		get_stat(),
		chk_cntrl(),
		check_perm(),
		exec_ok(),
		clear_req(),
		do_standalone(),
		do_connection(),
		dolocation(),
		file_open(),
		process_url(),
		sanitize(),
		writelog(),
		read_cache_dirinfo(),
		list_search(),
		cache_search(),
		send_nomatch(),
		send_isearch(),
		sendtext(),
		sendbin(),
		image(),
		do_wrap(),
		do_nomatchsub(),
		sendgrep(),
		sendinfo(),
		sendcgi(),
		do_put(),
		send_markline_doc(),
		send_text_line(),
		search_prolog(),
		search_epilog(),
		get_remote_ip(),
		get_remote_info(),
		get_local_info(),
		startlog(),
		wn_cleanup(),
		www_unescape(),
		sendredirect(),
		send204(),
		cgi_env(),
		check_query(),
		do_swrap(),
		update_mod_time(),
		open_wnlog(),
		www_err(),
		set_interface_root(),
		reset_parse_err(),
		parse_html_err(),
		daemon_logerr(),
		logerr(),
		senderr();

extern uid_t	user_id;
extern gid_t	group_id;


typedef enum { 
	RTYPE_DENIED,
	RTYPE_UNCHECKED,
	RTYPE_FILE,
	RTYPE_CGI,
	RTYPE_NPH_CGI,
	RTYPE_CGI_HANDLER,
	RTYPE_PUT_HANDLER,
	RTYPE_GSEARCH,
	RTYPE_CONTEXTSEARCH,
	RTYPE_LINESSEARCH,
	RTYPE_ISEARCH,
	RTYPE_MARKLINE,
	RTYPE_TSEARCH,
	RTYPE_KSEARCH,
	RTYPE_TKSEARCH,
	RTYPE_FIELDSEARCH,
	RTYPE_LISTSEARCH,
	RTYPE_INFO,
	RTYPE_HEAD,
	RTYPE_OPTIONS,
	RTYPE_REDIRECT,
	RTYPE_NOT_MODIFIED,
	RTYPE_NO_AUTH,
	RTYPE_FINISHED,
	RTYPE_IMAGEMAP,
	RTYPE_NOACCESS,
	RTYPE_PRECON_FAILED
} Reqtype;

typedef struct Request {
	char	request[BIGLEN],	/* The original request */
		cacheline[CACHELINE_LEN],	/* filled in by chkcache */
			/* These are pointers into cacheline */
		*title,			/* Item title */
		*content_type,		/* MIME content type */
		*encoding,		/* MIME content-transfer-encoding */
		*keywords,		/* string of keywords */
		*field[NUMFIELDS],	/* user defined fields */
		*includes,		/* comma separated insert files */
		*wrappers,		/* comma separated wrapper files */
		*list_incl,		/* comma separated include list */
		*swrapper,		/* search wrapper files */
		*nomatchsub,		/* Substitute for empty search result*/
		*filter,		/* Path to filter  */
		*cookie,		/* Cookie value or script name */
		*handler,		/* Path to handler  */
		*phandler,		/* Path to PUT handler  */
		*maxage,                /* Maxage in ascii seconds */
		*expires,		/* Expiration date */
			/* These two are pointers into filepath */
		*relpath,		/* Path rel to rootdir */
		*basename,		/* Base name of file  */

		*inclptr,		/* Ptr to current wrap or include */
		*inclistp,		/* Ptr to current include list item */
		*tilde_user_group,     	/* tilde user "name gid" */
		*vhost_user,		/* UID of the current vhost */
		*vhost_group,		/* GID of the current vhost */


		contype[SMALLLEN],	/* Use content_type, not this */
		rootdir[SMALLLEN],	/* Complete pathname of root dir  */
		filepath[MIDLEN],	/* Complete pathname of file  */
 		cachepath[MIDLEN],	/* Complete pathname of cache file */
		query[MIDLEN],		/* Stuff after '?' in URL */
		param_field[SMALLLEN],	/* Stuff after ';' before '=' in URL */
		*param_value,		/* Stuff after '=' before '?' in URL */
		pathinfo[MIDLEN],	/* PATH_INFO for CGI */
		authuser[USERNAME_LEN], /* username with Basic auth */
		user_dir[USERNAME_LEN], /* /~username */
		range[RANGELEN],	/* range from range header */
		etag[2*TINYLEN],		/* ETag in ASCII calculated locally */
		length[TINYLEN];	/* File length in ASCII */
		
	FILE	*fp;
	int	fptype;			/* FP_PIPE or FP_FILE */


	time_t	mod_time;		/* File modification time */

	Reqtype	type;			/* RTYPE_FILE, RTYPE_CGI, etc. */

	unsigned long	attributes,
			datalen,		/* Length of file as a long */
			logcount,		/* Bytes sent (for log) */
			attrib2,
			vhost_flag,
			allowed,
			status,
			filetype;

	int		do_wrap_1st_time;

} Request;

extern Request		*this_rp;


/* Bits in the Request attributes  and attrib2 are in common.h */

/* Bits in request allowed */
#define	WN_M_GET		(1<<0)
#define	WN_M_HEAD		(1<<1)
#define	WN_M_TRACE		(1<<2)
#define	WN_M_OPTIONS		(1<<3)
#define	WN_M_POST		(1<<4)
#define	WN_M_PUT		(1<<5)
#define	WN_M_DELETE		(1<<6)
#define	WN_M_MOVE		(1<<7)

/* Bits in the request status */
#define	WN_CANT_STAT		(1<<0)
#define	WN_HAS_BODY		(1<<1)
#define WN_PROLOGSENT		(1<<2)
#define WN_SMALL_CGI_SET	(1<<3)
#define WN_FULL_CGI_SET		(1<<4)
#define WN_ABORTED		(1<<5)
#define WN_MATCH_SENT		(1<<6)
#define WN_ERROR		(1<<7)

/* Bits in the Request vhost_flag */
#define VHOST_NO_USERDIR	(1<<0)

/* Bits in the Request filetype */
#define	WN_TEXT			(1<<0)
#define	WN_DIR			(1<<1)
#define	WN_NOT_WORLD_READ	(1<<2)
#define	WN_NOT_REG_FILE		(1<<3)
#define WN_ISHTML		(1<<4)
#define	WN_DEFAULT_DOC		(1<<5)
#define	WN_IMAGEMAP		(1<<6)
#define	WN_BYTERANGE		(1<<7)
#define	WN_LINERANGE		(1<<8)
#define	WN_RFC_BYTERANGE	(1<<9)
#define	WN_WORLD_WRITABLE	(1<<10)

typedef struct Dir_info {
	char	dirline[BIGLEN],
		*accessfile,
		*swrapper,
		*defincludes,
		*defwrapper,
		*deflist,
		*nomatchsub,
		*subdirs,
		*dir_owner,
		*cachemod,		/* Cache data base module */
		*filemod,		/* File data base  module */
		*indexmod,		/* Index search module  module */
		*authtype,		/* Type of authorization */
		*authrealm,		/* Realm for authorization */
		*authmod,		/* module to do authorization */
		*pauthtype,		/* Type of PUT authorization */
		*pauthrealm,		/* Realm for PUT authorization */
		*pauthmod,		/* module to do PUT authorization */
		*defdoc,		/* default document for this dir */
		*default_content,	/* default content type */
		*default_charset,	/* default character set */
		*default_maxage,	/* default value of maxage  */
		*def_cookie,		/* default cookie  */
		*def_handler,		/* default CGI handler  */
		*def_phandler,		/* default PUT handler  */
		*def_filter,		/* default filter  */
		authmodule[MIDLEN],
		filemodule[MIDLEN],
		cachemodule[MIDLEN],
		indexmodule[MIDLEN],
		cantstat_url[MIDLEN/2],
		authdenied_file[MIDLEN/2],
		noaccess_url[MIDLEN/2];

	unsigned long	attributes,
			defattributes;

	unsigned	logtype,
			cache_uid,
			cache_gid;

	time_t		cmod_time;	/* Cache file modification time */
} Dir_info;

extern Dir_info	*dir_p;

/* Bits in the Dir attributes */
#define	WN_DIRNOSEARCH	(1<<0)
#define WN_DIRWRAPPED	(1<<1)
#define WN_SERVEALL	(1<<2)


typedef struct Cache_entry {
	char	*line,
		headerlines[BIGLEN],
		*basename,
		*title,
		*keywords,
		*field[NUMFIELDS],	/* user defined fields */
		*content,
		*encoding,	/* MIME content-transfer-encoding */
		*status,
		*cookie,
		*md5,
		*includes,	/* comma separated include files */
		*wrappers,	/* comma separated wrapper files */
		*list_incl,	/* comma separated include list */
		*swrapper,	/* comma separated search wrapper files */
		*nomatchsub,
		*filter,
		*handler,	/* CGI handler */
		*phandler,	/* PUT handler */
		*maxage,                /* Maxage in ascii seconds */
		*expires,
		*url,		/* URL link to remote object */
		*redirect,	/* URL link to redirected object */
		*end;

	unsigned	attributes,
			filetype;
} Cache_entry;


typedef enum { 
	GET,
	CONDITIONAL_GET,
	POST,
	HEAD,
	TRACE,
	OPTIONS,
	PUT,
	MOVE,
	DELETE,
	UNKNOWN
} Methodtype;

typedef enum { 
	HTTP0_9,
	HTTP1_0,
	HTTP1_1
} Prottype;

typedef struct Inheader {
	char	htext[HEADERTEXTLEN],
		*current_htext,
		accept[ACCEPTLEN],
		cookie[ACCEPTLEN],
		charset[ACCEPTLEN/4],
		lang[ACCEPTLEN/4],
		a_encoding[ACCEPTLEN/4],  /* Accept-Encoding header */
		te[ACCEPTLEN/4],  	/* TE header */
		url_path[BIGLEN],
		auth_url_path[MIDLEN],
		content[SMALLLEN],
		encoding[SMALLLEN],	/* MIME content-encoding */
		length[TINYLEN],
		referrer[MIDLEN],
		*ua,
		from[SMALLLEN],
		host_head[SMALLLEN],
		*new_uri,
		new_uri_env[MIDLEN/2],
		authorization[MIDLEN],
		inmod_date[SMALLLEN],
		etag[SMALLLEN],
		*range,
		*xforwardedfor,	/* X-Forwarded-For */
		*via,
		*tmpfile_name,
		tmpfile_env[SMALLLEN];

	Methodtype	method;
	Prottype	protocol;

	unsigned	attrib,
			conget;

} Inheader;

extern Inheader	*inheadp;


/* Bits in inheadp->attrib */
#define	INPUT_CHUNKED	(1<<0)

/* Bits in inheadp->conget */

#define	IFNMATCH	(1<<0)
#define	IFMATCH		(1<<1)
#define	IFMODSINCE	(1<<2)
#define	IFUNMODSINCE	(1<<3)
#define	IFRANGE		(1<<4)



typedef struct Outheader {
	char	
		list[BIGLEN],
		location[MIDLEN],
		expires[SMALLLEN],
		md5[2*TINYLEN],
		range[SMALLLEN],
		allow[SMALLLEN],
		status[SMALLLEN];

	unsigned ohstat;
} Outheader;

extern Outheader	*outheadp;

/* Bits in outheadp->ohstat */

#define	OHSTAT_ISREDIR	(1)



typedef struct Inbuffer {
	char	buffer[INBUFFSIZE],
		*bcp;
	int	cur_sz;
} Inbuffer;


#define LOGBUFLEN	(BIGLEN + MIDLEN)
			/* must be bigger than BIGLEN+SMALLLEN */


typedef struct Connection {
	int		pid,
			keepalive,	/* boolean */
			more_in_buf,	/* boolean */
			trans_cnt;

	char		logbuf[LOGBUFLEN],
			outbuf[OUT_BUFFSIZE + TINYLEN],
			remotehost[MAXHOSTNAMELEN],
			remaddr[20],
			remport[16],
			rfc931name[SMALLLEN],
			*out_ptr,
			*chunksize_ptr, /* pointer into outbuf to place */
                                        /* where chunksize must be inserted */
			*scheme;	/* "http" or something else */

	long		chunksize,
			bytecount;

	unsigned	con_status,
			chunk_status;

	Inbuffer	*bufp;
} Connection;

extern Connection	*this_conp;


/* Bits in the Connection con_status */
#define WN_CON_CGI_SET		(1<<0)
#define WN_CON_TIMEDOUT		(1<<1)

/* Bits in the Connection chunk_status */
#define WN_USE_CHUNK		(1<<0)
#define WN_START_CHUNK		(1<<1)
#define WN_IN_CHUNK		(1<<2)


extern unsigned	serv_perm;

/* Bits in serv_perm */
#define	WN_TRUSTED_UID		(1<<0)
#define	WN_TRUSTED_GID		(1<<1)
#define	WN_FORBID_EXEC		(1<<2)
#define	WN_RESTRICT_EXEC	(1<<3)
#define	WN_COMP_UID		(1<<4)
#define	WN_COMP_GID		(1<<5)
#define	WN_ATRUSTED_UID		(1<<6)
#define	WN_ATRUSTED_GID		(1<<7)
#define	WN_PERMIT_PUT		(1<<8)






#define streq( a, b)	( strcmp( (a), (b)) == 0 )
#define iswndir( x)	( x->filetype & WN_DIR  )
#define isdirwrapped( x)	( x->attributes & WN_DIRWRAPPED  )
#define mystrncat( b, s, n)	fmt3( b, n, b, s, NULL)
#define fmt2( b, n, s1, s2)  fmt3( b, n, s1, s2, NULL)

