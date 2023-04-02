/*
    Wn: A Server for the HTTP
    File: wn/send.c
    Version 2.4.4
    
    Copyright (C) 1996-2001  <by John Franks>

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
#include <memory.h>
#include <errno.h>

#ifndef NO_UNISTD_H
#include <unistd.h>
#endif

#include "wn.h"
#include "version.h"
#include "parse.h"
#include "reg.h"


#define BYTECHUNK	(256*1024)
#define MAX_REDIRECT	(10)


static void	filter_open(),
		send_byterange(),
		sendsubrange();

static char	*enter_range(),
		*count_range();

extern long	atol();


void
senderr( status, msg, file)
char	*status,
	*msg,
	*file;
{
	char	buf[MIDLEN];
	int	prolog_sent;

	get_remote_info( );

	fmt3( outheadp->status, SMALLLEN, status, " ", msg);
	fmt3( outheadp->list, SMALLLEN, "Content-type: ",
			BUILTIN_CONTENT_TYPE, "\r\n");

	if ( *status == '4') {
		/* it's a 4xx error; a client error */
		if ( streq( status, "416") ) {
			Snprintf1( outheadp->range, SMALLLEN, 
					"*/%lu", this_rp->datalen);
		}
		else {
			this_conp->keepalive = FALSE;
		}
	}

	if ( streq( status, SERV_ERR)) {
		this_conp->keepalive = FALSE;
		logerr( msg, file);
	}
	else
		writelog( this_rp, msg, file);

	prolog_sent = this_rp->status & WN_PROLOGSENT;
	clear_req( );

	this_rp->status |= prolog_sent;

	if ( !prolog_sent) {
		set_interface_root( );

		fmt3( buf, sizeof( buf), "<html>\n<head>\n<title>", status, " ");
		fmt3( buf, sizeof( buf), buf, msg,
			"</title>\n</head>\n<body>\n<h2>Error code ");
		fmt3( buf, sizeof( buf), buf, status, "</h2>\n");
		fmt3( buf, sizeof( buf), buf, msg, "\n\n<hr>\n<address>");
		fmt3( buf, sizeof( buf), buf, VERSION,
			"</address>\n\n</body>\n</html>\n");

		Snprintf1( this_rp->length, TINYLEN, "%d", strlen(buf));

		if (inheadp->method != HEAD)
			this_rp->status |= WN_HAS_BODY;
		http_prolog( );
		if (inheadp->method != HEAD)
			send_text_line( buf);
	}

	this_rp->status |= WN_ERROR;
	this_rp->type = RTYPE_FINISHED;

}


void
sendinfo( ip)
Request	*ip;

{
	char	*cp,
		*maintainer,
		owner[MIDLEN],
		len[TINYLEN],
		con[SMALLLEN],
		enc[SMALLLEN],
		buf[2*BIGLEN];

	int	i;

	struct tm *gmt;
	
	if ( *ip->length) {
		mystrncpy( len, ip->length, TINYLEN);
		*ip->length = '\0';
	}
	mystrncpy( enc, ip->encoding, SMALLLEN);
	*ip->encoding = '\0';

	mystrncpy( con, ip->content_type, SMALLLEN);
	ip->content_type = BUILTIN_CONTENT_TYPE;
	this_rp->status |= WN_HAS_BODY;
	http_prolog( );

	mystrncpy(buf, "<html>\n<head>\n<title>URL information </title>\n", 
			SMALLLEN );
	send_text_line( buf);
	maintainer = ( *dir_p->dir_owner ? dir_p->dir_owner : MAINTAINER);
	fmt3( owner, MIDLEN,"<link rev=\"made\" href=\"", maintainer, "\">\n");
	fmt2(buf, MIDLEN, owner, 
	     "</head>\n<body>\n<h2>URL information</h2>\n");
	send_text_line( buf);

	fmt3( buf, MIDLEN, "<dl>\n<dt><b>Title:</b>\n<dd>", ip->title, "\n");
	send_text_line( buf);

	fmt3(buf, MIDLEN, "<dt><b> Filename:</b>\n<dd>", ip->basename, "\n");
	send_text_line( buf);

	if ( *ip->keywords) {
		fmt3( buf, MIDLEN, "<dt><b>Keywords:</b>\n<dd>",
					ip->keywords, "\n");
		send_text_line( buf);
	}
	for ( i = 0; i < NUMFIELDS; i++) {
		if ( *(ip->field[i])) {
			Snprintf2(buf, MIDLEN, 
				"<dt><b>User field %d:</b>\n<dd>%.1024s\n",
							i, ip->field[i]);
			send_text_line( buf);
		}
	}

	if ( *ip->etag) {
		fmt3( buf, MIDLEN, "<dt><b>ETag:</b>\n<dd>", ip->etag, "\n");
		send_text_line( buf);
	}

	if ( ip->expires && *ip->expires) {
		fmt3( buf, MIDLEN, 
			"<dt><b>Expires:</b>\n<dd>", ip->expires, "\n");
		send_text_line( buf);
	}

	if ( *len ) {
		fmt3( buf, SMALLLEN, "<dt><b>Size:</b>\n<dd>", len, "\n");
		send_text_line( buf);
	}
	fmt3( buf, SMALLLEN, "<dt><b>Content-type:</b>\n<dd>", con, "\n");
	send_text_line( buf);

	if ( *enc) {
		fmt3(buf, SMALLLEN, 
				"<dt><b>Content-encoding:</b>\n<dd>", 
		     			enc, "\n");
		send_text_line( buf);
	}

	if ( outheadp->md5 &&  (cp = strchr( outheadp->md5, ':')) != NULL ) {
		fmt3( buf, SMALLLEN, 
			"<dt><b>Content-MD5:</b>\n<dd>", ++cp, "\n");
		send_text_line( buf);
	}

	if ( ip->mod_time) {
		gmt = gmtime(&ip->mod_time);
		strftime( buf, SMALLLEN,
		"<dt><b>Last-Modified:</b>\n<dd> %a, %d %h %Y %T GMT\n", gmt);
		send_text_line( buf);
	}

	fmt3( buf, MIDLEN, "<dt><b>Maintainer:</b>\n<dd>",
	      maintainer, "\n");
	send_text_line( buf);

	fmt3( buf, SMALLLEN, "</dl>\n<hr>\n<address>",
	      VERSION, "</address>\n");
	send_text_line( buf);

	send_text_line( "\n</body>\n</html>\n");

	writelog( ip, log_m[14], ip->relpath);
}

/*
 * void file_open( ip)
 * Call check_perm() to check permissions then open a file to be served, 
 * store the FILE pointer in ip->fp.  If the string dir_p->filemod is
 * non-empty then use it as a data base module to to produce the data.
 * The data base module gets its key (which is ip->basename) from the
 * environment variable WN_KEY.
 *
 */

void
file_open( ip)
Request *ip;
{
	char	*cp,
		envkey[2*SMALLLEN];

	if ( !*dir_p->filemod) {
		check_perm( ip, ip->filepath);
		if ( (ip->fp = fopen( ip->filepath, "r")) == (FILE *) NULL ) {
			senderr( DENYSTATUS, err_m[1], ip->filepath);
			wn_exit( 2); /* senderr: DENYSTATUS */
		}
		ip->fptype = FRP_FILE;
		return;
	}	
	else {
		fmt3( envkey, 2*SMALLLEN, "WN_KEY=", ip->basename, NULL);
		if ( (cp = strdup( envkey)) == NULL)
			logerr( err_m[64], "file_open");
		else
			putenv( cp);

		if ((ip->fp = WN_popen( dir_p->filemod, "r")) == (FILE *) NULL ) {
			senderr( SERV_ERR, err_m[39], dir_p->filemod);
			wn_exit( 2); /* senderr: SERV_ERR */
		}
		ip->fptype = FRP_PIPE;
	}
}

/*
 * void filter_open( ip)
 * Like file_open above, but additionally pipes the output of the 
 * file or data base module to the filter in ip->filter.  The FILE
 * pointer for the output from the filter is put in ip->fp.
 *
 */

static void
filter_open( ip)
Request *ip;
{
	char		*cp,
			cmdbuf[2*MIDLEN],
			buf[MIDLEN];

	exec_ok( ip);
	check_perm( ip, ip->filter);

	fmt3( buf, MIDLEN, "WN_FILEPATH_INFO=", ip->filepath, NULL);
	if ( (cp = strdup( buf)) == NULL)
			logerr( err_m[64], "filter_open");
	else
		putenv( cp);

	getfpath( buf, ip->filter, ip);
	if ( !*dir_p->filemod) {
		check_perm( ip, ip->filepath);

		if ( WN_SU_EXEC) {
			mystrncpy( cmdbuf, buf, 2*MIDLEN);
		}
		else {
			fmt3( cmdbuf, 2*MIDLEN, buf, " < ", ip->filepath);
		}
	}
	else {
		senderr( SERV_ERR, err_m[52], cmdbuf);
		wn_exit( 2); /* senderr: SERV_ERR */
	}


	if ( (ip->fp = WN_popen( cmdbuf, "r")) == (FILE *) NULL ) {
		senderr( SERV_ERR, err_m[18], cmdbuf);
		wn_exit( 2); /* senderr: SERV_ERR */
	}
	ip->fptype = FRP_PIPE;
}


/*
 * sendbin( ip)  Send a binary file.
 */

				
void
sendbin(  ip)
Request	*ip;

{
	if ( ip->filetype & WN_LINERANGE) {
		senderr( DENYSTATUS, err_m[54], ip->filepath);
		wn_abort( );
		return;
	}
	if ( ip->attributes & WN_FILTERED )
		filter_open( ip);
	else
		file_open( ip);

	if ( ip->filetype & (WN_BYTERANGE + WN_RFC_BYTERANGE)) {
		if ( !(ip->filetype & WN_RFC_BYTERANGE))
			ip->content_type = "application/octet-stream";
		send_byterange();
	}
	else {
		http_prolog( );
		send_out_fd( fileno( ip->fp));
	}

	writelog( ip, log_m[13], ip->relpath);

	if ( ip->fptype == FRP_PIPE)
		pclose( ip->fp);
	else
		fclose( ip->fp);
}

/*
 * sendtext( ip)  Send a text file.
 */

void
sendtext(  ip)
Request	*ip;
{

	int	dontlog = FALSE;

	char	buf[OUT_BUFFSIZE];

	int	n,
		invalid;


	if ( ip->attributes & WN_FILTERED )
		filter_open( ip);
	else
		file_open( ip);

	if ( ip->filetype & (WN_BYTERANGE + WN_RFC_BYTERANGE + WN_LINERANGE)) {
		if ( ip->attributes & (WN_PARSE + WN_DYNAMIC + WN_FILTERED) ) {
			senderr( DENYSTATUS, err_m[94], ip->filepath);
			wn_abort( );
			return;
		}
		else if ( !(ip->filetype & WN_RFC_BYTERANGE)) {
			char sbuf[SMALLLEN];

			fmt2( sbuf, SMALLLEN, "text/plain; charset=",
					DEFAULT_CHARSET);
			ip->content_type = (( ip->filetype & WN_TEXT )
				? sbuf : "application/octet-stream");
		}
	}


	if ( (ip->attributes & WN_PARSE) && (ip->filetype & WN_ISHTML) ){ 
		if ( ip->do_wrap_1st_time)
			dontlog = FALSE;
		else
			dontlog = TRUE;
		/* Don't do http_prolog() until later */

		do_wrap( ip, SHOW_IT);
		writelog( ip, log_m[13], ip->relpath);
/*		if ( !dontlog) {
			writelog( ip, log_m[13], ip->relpath);
		}
*/
		return;
	}
	else {
		if ( ip->filetype & (WN_BYTERANGE + WN_RFC_BYTERANGE)) {
			send_byterange();
		}
		else if ( ip->filetype & WN_LINERANGE) {
			long	startline,
				endline;
			char	*cp;

			cp = ip->range;
			enter_range( cp, &startline, &endline, &invalid);
			*ip->length ='\0';
			http_prolog( );
			if ( startline == -1 )
				logerr( err_m[93], "");
			for ( n = 1; n <= endline; n++) {
				if ( fgets( buf, OUT_BUFFSIZE, ip->fp) == NULL)
					break;
			/*
			   Note if a line is longer than OUT_BUFFSIZE so the
			   only a partial line is read, then the line count 
                           here will be wrong.  This is a bug.
			 */
				if ( n >= startline)
					send_text_line( buf);
			}
		}
		else if ( ip->type == RTYPE_MARKLINE ) {
			http_prolog( );
			send_markline_doc( ip, SHOW_IT);
		}
		else {
			http_prolog( );
			send_out_fd( fileno( ip->fp));
		}
	}

	writelog( ip, log_m[13], ip->relpath);
/*	if ( !dontlog)
		writelog( ip, log_m[13], ip->relpath); */

	if ( ip->fptype == FRP_PIPE)
		pclose( ip->fp);
	else
		fclose( ip->fp);

}

void
send_text_line( line)
char	*line;
{
	send_out_mem( line, strlen(line));
}


void
sendredirect( ip, status, location)
Request	*ip;
char	*status,
	*location;
{
	static int	num = 0;
	char	buf[MIDLEN];

	num++;
	if ( num > MAX_REDIRECT) {
		senderr( SERV_ERR, err_m[55], err_m[64]);
		wn_exit( 2); /* senderr: SERV_ERR */
	}

	if ( strncasecmp( location, "<null>", 6) == 0) {
		send204( ip);
		return;
	}

	outheadp->ohstat |= OHSTAT_ISREDIR;
	if ( location != outheadp->location)
		mystrncpy( outheadp->location, location, MIDLEN);
	mystrncpy( outheadp->status, status, SMALLLEN);
	ip->content_type = ip->encoding = NULL;
	ip->attributes = ip->attrib2 = 0;


	fmt3( buf, sizeof( buf), "<html>\n<head>\n<title>", status, 
			"</title>\n</head>\n<body>\n");
	fmt3( buf, sizeof( buf), buf, "<h2>Redirection: ", status);
	fmt3( buf, sizeof( buf), buf, 
			"</h2>\n<p> This resource is located at\n<a href=\"",
			location);
	fmt3( buf, sizeof( buf), buf, "\">\n", location);
	fmt3( buf, sizeof( buf), buf, ".</a></p>\n\n<hr>\n<address>", VERSION);
	mystrncat( buf, "</address>\n\n</body>\n</html>\n", sizeof( buf) );


	fmt3( buf, sizeof( buf), "<html>\n<head>\n<title>", status, 
			"</title>\n</head>\n<body>\n");
	fmt3( buf, sizeof( buf), buf, "<h2>Redirection: ", status);


	fmt3( buf,  sizeof(buf), buf,
	   "</h2>\n<p> This resource is located at <a href=\"", location);

	fmt3( buf,  sizeof(buf), buf, "\">", location);
	fmt3( buf,  sizeof(buf), buf, "</a></p>\n<hr>\n<address>", VERSION);
	fmt3( buf,  sizeof(buf), buf, "</address>\n</body>\n</html>\n", NULL);

	Snprintf1( this_rp->length, TINYLEN, "%d", strlen(buf));

	if (inheadp->method != HEAD)
			this_rp->status |= WN_HAS_BODY;

	http_prolog( );

	if (inheadp->method != HEAD)
		send_text_line( buf);

	writelog( ip, log_m[9], location);


	if ( (ip->attributes & (WN_PARSE + WN_DYNAMIC +WN_FILTERED))
				&& ( inheadp->protocol == HTTP1_0) ) {
		this_conp->keepalive = FALSE;
	}
	ip->type = RTYPE_FINISHED;
	return;
}

void
send204( ip)
Request	*ip;
{
	mystrncpy( outheadp->status, "204 No Response", SMALLLEN);

	ip->status &= ~(WN_HAS_BODY);
	http_prolog();

	writelog( ip, log_m[16], "");
	if ( (ip->attributes & (WN_PARSE + WN_DYNAMIC +WN_FILTERED))
				&& ( inheadp->protocol == HTTP1_0) ) {
		this_conp->keepalive = FALSE;
	}
	ip->type = RTYPE_FINISHED;
	return;
}


static void
send_byterange( )
{

	char	*nextrange,
		*save_content,
		sep[SMALLLEN],
		buf[SMALLLEN];

	long	startbyte,
		endbyte,
		tot_len,
		temp_len,
		file_len,
		len_sent;

	int	invalid,
		multi = FALSE,
		first_one = TRUE;

	len_sent = 0;
	tot_len = 0;
	file_len = this_rp->datalen;
	nextrange = this_rp->range;

	if ( strchr( nextrange, ',') != NULL) {
		long	seplen,
			range_size;

		char	*cntrp,
			cntrange[RANGELEN];

		multi = TRUE;
		mystrncpy( cntrange, nextrange, RANGELEN);
		cntrp = cntrange;

		srand( this_conp->pid);
		Snprintf2( sep, (SMALLLEN - 64), "WN%xX%xWN", rand(),  rand());
		seplen = strlen( sep);

		while ( cntrp ) {
			cntrp = count_range( cntrp, &range_size, 
					     seplen, file_len);
			tot_len += range_size;
		}
		tot_len += seplen + 8; 	/*  "\r\n--" + sep + "--\r\n" */

	}
	while ( nextrange ) {
		nextrange = enter_range( nextrange, &startbyte, &endbyte, &invalid);
		if ( invalid) {
			if ( invalid == 416 )
				senderr( "416", err_m[113], "");
			if ( invalid == 400 )
				senderr( CLIENT_ERR, err_m[121], "");
			wn_exit( 2); /* senderr: CLIEN_ERR or 113 */
		}

		if ( startbyte == -1 ) {
			temp_len = endbyte;
			endbyte = file_len - 1;
			startbyte = file_len - temp_len;
		}
		else {
			if ( (endbyte == -1 ) || (endbyte >= this_rp->datalen))
				endbyte = this_rp->datalen - 1;
		}

		mystrncpy( outheadp->status,
					"206 Partial Content", SMALLLEN);

	if ( multi && (this_rp->filetype & WN_RFC_BYTERANGE) ) {
			if ( first_one) {
				first_one = FALSE;
				Snprintf1( this_rp->length, TINYLEN, "%ld",
					   tot_len);
				fmt2( buf, SMALLLEN,
				      "multipart/x-byteranges; boundary=",
				      		sep);
				save_content = this_rp->content_type;
				this_rp->content_type = buf;
				http_prolog( );
				if ( this_conp->chunk_status
				     & (WN_START_CHUNK + WN_IN_CHUNK)) {
					senderr( SERV_ERR, err_m[120], "");
					wn_exit( 2); /* senderr: SERV_ERR */
				}
				this_rp->content_type = save_content;
			}
			fmt3( buf, SMALLLEN, "\r\n--", sep, "\r\n");

			send_text_line( buf);
			len_sent += strlen( buf);

			fmt3( buf, SMALLLEN, "Content-type: ",
					this_rp->content_type, "\r\n");
			send_text_line( buf);
			len_sent += strlen( buf);

			Snprintf3( buf, SMALLLEN,
				"Content-Range: bytes %ld-%ld/%ld\r\n\r\n",
					startbyte, endbyte, file_len);
			send_text_line( buf);
			len_sent += strlen( buf);

			sendsubrange( startbyte, endbyte);
			len_sent += (endbyte - startbyte + 1);

			if ( nextrange == (char *)NULL) {
				fmt3( buf, SMALLLEN,
					 "\r\n--", sep, "--\r\n");
				send_text_line( buf);
				len_sent += strlen( buf);
				Snprintf1(this_rp->length, TINYLEN, "%ld", len_sent);
				return;
			}
			else
				continue;
		}
		else {
			Snprintf1( this_rp->length, TINYLEN, "%ld",
						endbyte - startbyte + 1);
			if ( this_rp->filetype & WN_RFC_BYTERANGE ) {
				Snprintf3( outheadp->range, SMALLLEN, "%ld-%ld/%ld",
						startbyte, endbyte, file_len);
			}
			http_prolog( );
			flush_outbuf( );
			sendsubrange( startbyte, endbyte);
			return;
		}
	}
}

static void
sendsubrange( start, end)
long	start,
	end;
{
	int	remlen,
		fdfp,
		len = 0;

	long	remaining;

	remaining = end - start + 1;
	fdfp = fileno( this_rp->fp);
	if ( lseek( fdfp, (off_t) start, 0 /* SEEK_SET */) < 0) {
		senderr( SERV_ERR, err_m[133], "");
		wn_exit( 2); /* senderr: SERV_ERR */
	}

	remlen = this_conp->outbuf + OUT_BUFFSIZE - this_conp->out_ptr;
	remlen = ( remlen > remaining ? (int) remaining : remlen);

	while ( TRUE) {
		len = read( fdfp, this_conp->out_ptr, remlen);
		if ( (len == -1) && (errno == EINTR))
			continue;
		if ( len <= 0 ) {
			flush_outbuf();
			break;
		}
		this_rp->logcount += (long) len;

		if ( this_conp->outbuf + OUT_BUFFSIZE <= 
					this_conp->out_ptr + len ) {  
			/* buffer is full */
			this_conp->out_ptr += len;
			flush_outbuf();
			remaining -= len;
			remlen = ( OUT_BUFFSIZE > remaining ?
					(int) remaining : OUT_BUFFSIZE);
			continue;
		}
		else {  /* buffer not full yet */
			remlen -= len;
			this_conp->out_ptr += len;
			remaining -= len;
		}
	}
	if ( (remaining > 0) || (len < 0) )
		logerr( err_m[76], "sendsubrange");


}


static char 
*enter_range(  value, startp, endp, errp )
char	*value;
long	*startp,
	*endp;
int	*errp;
{
	register char	*cp,
			*cp2;

	char		*next;

	/* if ip->param_value is "123-234" it is a file range from
	 * byte  123 to 234.  Put 123 in *startp and 234
	 * in *endp. For 123- use -1 for endp range
	 */

	cp = value;

	if ( (cp2 = strchr( cp, ',')) != NULL) {
		*cp2++ = '\0';
		next = cp2;
	}
	else
		next = (char *)NULL;

	if ( (cp2 = strchr( cp, '-')) == NULL) {
		logerr( err_m[93], cp);
		*errp = 400;
		return (next);
	}


	*cp2++ = '\0';

	if ( strchr( cp, '-')  || strchr( cp2, '-') ) {
		logerr( err_m[93], cp);
		*errp = 400;
		return (next);
	}

	*startp = ( *cp ? atol( cp ) : (-1));
	*endp = ( *cp2 ? atol( cp2 ) : this_rp->datalen);
	if ( *endp > this_rp->datalen)
		*endp = this_rp->datalen;

	if ( *startp > this_rp->datalen)
		*errp = 416;
	else if ( *startp > *endp)
		*errp = 400;
	else
		*errp = 0;
	return (next);
}

static char 
*count_range(  rng, len_p, seplen, filelen)
char	*rng;
long	*len_p,
	seplen,
	filelen;
{
	register char	*cp,
			*cp2;

	long		len_sent,
			start,
			end;

	char		*next,
			buf[SMALLLEN];

	/* if ip->param_value is "123-234" it is a file range from
	 * byte  123 to 234.  Put 123 in *startp and 234
	 * in *endp. For 123- use -1 for endp range
	 */

	cp = rng;

	if ( (cp2 = strchr( cp, ',')) != NULL) {
		*cp2++ = '\0';
		next = cp2;
	}
	else
		next = (char *)NULL;

	if ( (cp2 = strchr( cp, '-')) == NULL) {
		*len_p = 0;
		return (next);
	}

	*cp2++ = '\0';

	if ( strchr( cp, '-')  || strchr( cp2, '-') ) {
		*len_p = 0;
		return (next);
	}

	start = ( *cp ? atol( cp ) : (-1));
	end = ( *cp2 ? atol( cp2 ) : this_rp->datalen);
	if ( end > this_rp->datalen)
		end = this_rp->datalen;

	len_sent = end - start + 1;

	/*  "\r\n--" + sep + "\r\n" */
	len_sent += seplen + 6;

	/*  "Content-type: " + 	this_rp->content_type + "\r\n" */
	len_sent += strlen( this_rp->content_type) + 16;

	Snprintf3( buf, SMALLLEN,
		"Content-Range: bytes %ld-%ld/%ld\r\n\r\n",
			start, end, filelen);
	len_sent += strlen( buf);

	*len_p = len_sent;
	return (next);
}




#define CHUNKPAD	(6)	/* number of bytes for chunk size */
				/* CHUNKPAD = 4 for digits + 2 for CRLF */
void
send_out_fd( fd )
int	fd;
{

	int		remlen,
			len;

	remlen = this_conp->outbuf + OUT_BUFFSIZE - this_conp->out_ptr;

	while ( TRUE) {
		if ( this_conp->chunk_status & WN_START_CHUNK) {
			/* set up chunking */
			this_conp->chunksize = 0;
			if ( remlen < OUT_BUFFSIZE/4 ) {
				flush_outbuf();
				remlen = OUT_BUFFSIZE;
			}

			this_conp->chunksize_ptr = this_conp->out_ptr;
			this_conp->out_ptr += CHUNKPAD;
			len = read( fd, this_conp->out_ptr, remlen);

			if ( len > 0 ) {
				this_conp->chunk_status &= ~(WN_START_CHUNK);
				this_conp->chunk_status |= WN_IN_CHUNK;
				this_rp->logcount += CHUNKPAD;
			}
			else {  /* len <= 0 */
				this_conp->out_ptr -= CHUNKPAD;
				/* undo this */
				if ( (len == -1) && (errno == EINTR))
					continue;
				else
					break;
			}
		}
		else {
			len = read( fd, this_conp->out_ptr, remlen);
			if ( (len == -1) && (errno == EINTR))
				continue;
			if ( len <= 0 )
				break;
		}

		this_rp->logcount += (long) len;
		this_conp->out_ptr += len;
		if ( this_conp->chunk_status & WN_IN_CHUNK) {
			this_conp->chunksize += (long)len;
		}
		if ( len == remlen ) {  /* buffer is full */
			flush_outbuf();
			remlen = OUT_BUFFSIZE;
			continue;
		}
		else {  /* buffer not full yet */
			remlen -= len;
			if ( this_rp->attributes & WN_UNBUFFERED)
				flush_outbuf();
		}
	}
	if ( len < 0 )
		logerr( err_m[76], "send_out_fd");
}

void
send_out_mem( buf, len)
char	*buf;
int	len;
{
	register char	*cp,
			*cp2,
			*end;

	int		remlen;
	end = this_conp->outbuf + OUT_BUFFSIZE;
	cp = buf;

	this_rp->logcount += (long) len;
	while ( len > 0 ){
		if ( this_conp->chunk_status & WN_START_CHUNK) {
			/* set up chunking */
			if ( (end - this_conp->out_ptr) < OUT_BUFFSIZE/4 ) {
				flush_outbuf();
			}
			this_conp->chunksize = 0;
			this_conp->chunk_status &= ~(WN_START_CHUNK);
			this_conp->chunk_status |= WN_IN_CHUNK;
			this_conp->chunksize_ptr = this_conp->out_ptr;
			this_conp->out_ptr += CHUNKPAD;
			this_rp->logcount += CHUNKPAD;
		}
		cp2 = this_conp->out_ptr;
		if ( end > cp2 + len ) {
			/* it all fits in buffer */
			memcpy( cp2, cp, len);
			this_conp->out_ptr += len;
			if ( this_conp->chunk_status & WN_IN_CHUNK)
				this_conp->chunksize += (long)len;
			if ( this_rp->attributes & WN_UNBUFFERED)
				flush_outbuf();
			return;
		}
		else {
			remlen = this_conp->outbuf
					+ OUT_BUFFSIZE - cp2;
			len -= remlen;
			memcpy( cp2, cp, remlen);

			if ( this_conp->chunk_status & WN_IN_CHUNK)
				this_conp->chunksize += (long)remlen;

			cp += remlen;
			this_conp->out_ptr = end;
			flush_outbuf();
		}
	}
}


void
flush_outbuf( )
{

	int		fdstdout,
			len,
			n;

	register char	*cp;
	static long bytechunk = BYTECHUNK;

	if ( this_conp->out_ptr == this_conp->outbuf)
		return;
	if ( this_conp->chunk_status & WN_IN_CHUNK) {
		cp = this_conp->chunksize_ptr;

		Snprintf1( cp, CHUNKPAD, "%.4lX\r", this_conp->chunksize);
		/* 4 in %.4lX is CHUNKPAD - 2 */

		cp += strlen(cp);
		*cp = '\n';
		this_conp->chunksize = 0;
		*this_conp->out_ptr++ = '\r';
		*this_conp->out_ptr++ = '\n';
		*this_conp->out_ptr = '\0';
		this_conp->chunk_status &= ~(WN_IN_CHUNK);
		this_conp->chunk_status |= WN_START_CHUNK;
	}


	cp = this_conp->outbuf;
	len = this_conp->out_ptr - cp;

	fdstdout = fileno( stdout);

	while ( (n = WN_write( fdstdout, cp, len)) < len) {

		if ( n == -1 && errno == EINTR ) 
			continue;
		if ( n == -1 && errno == EAGAIN ) {
			sleep( 1);
			continue;
		}
		if ( n <= 0) {
			if ( n == -1 && errno != EPIPE  && errno != ECONNRESET) {
				char   buf[SMALLLEN];
				Snprintf1( buf, SMALLLEN, 
					   "flush, errno = %d: %s",
					   errno, strerror(errno));
				logerr( err_m[75], buf);
			}
			break;
		}
		len -= n;
		cp += n;
		this_conp->bytecount += n;
	}
	if ( n >= 0 ) {
		this_conp->bytecount += n;
	}

	if ( this_conp->bytecount >= bytechunk) {
		if ( bytechunk < 4*BYTECHUNK )
			bytechunk += BYTECHUNK;
		alarm( TRANSACTION_TIMEOUT);
		this_conp->bytecount = 0L;
	}
	this_conp->out_ptr = this_conp->outbuf;
}

/* Chunking is automatically done by buffer routines (flush_outbuf,
 * send_out_fd() and send_out_mem() ) whenever chunk_status & WN_USE_CHUNK
 * is true.  There are two disjoint states for chunking WN_START_CHUNK and
 * WN_IN_CHUNK.  With the first we are ready to start a new chunk (any
 * previous one has been completed.  In this state when one of the send_out_*
 * functions is called space is reserved in the buffer to place the
 * chunk length,  WN_IN_CHUNK is set, an a chunksize count is started.
 * When in the state WN_IN_CHUNK, any calls to send_out_* put bytes
 * in the buffer and update the chunksize.  When the buffer is full
 * flush_outbuf() is called.  It completes a chunk by filling in the
 * the chunk size (at chunksize_ptr), terminating the chunk with
 * CRLF, and setting the state to WN_START_CHUNK, before the buffer is
 * flushed.  Finally when the document being sent is complete, a
 * call to end_chunking() completes the current chunk if necessary,
 * i.e. if WN_IN_CHUNK, appends the zero size chunk indicating the
 * end of chunking and reinitializes chunk_status, turning off all
 * bits.
 * Currently chunk size is formatted as %.4lX, e.g. 02FF.  The maximum
 * chunk size is OUT_BUFFSIZE which must be less than FFFF hex.
 */

void
end_chunking()
{
	register char	*cp,
			*cp2;

	if ( !this_conp->chunk_status & WN_USE_CHUNK) {
		logerr( err_m[116], "");
		return;
	}
	cp = this_conp->out_ptr;
	if ( this_conp->chunk_status & WN_IN_CHUNK) {
		/* finish the chunk we're doing */
		cp2 = this_conp->chunksize_ptr;

		Snprintf1( cp2, CHUNKPAD, "%.4lX\r", this_conp->chunksize);
		/* 4 in %.4lX is CHUNKPAD - 2 */

		cp2 += strlen(cp2);
		*cp2 = '\n';

		*cp++ = '\r';
		*cp++ = '\n';
	}
	this_conp->chunksize = 0;
	this_conp->chunk_status = 0;
	/* add last (zero size) chunk */
	*cp++ = '0';
	*cp++ = '\r';
	*cp++ = '\n';
	/* "trailer" (if any) should go here */
	*cp++ = '\r';
	*cp++ = '\n';
	*cp = '\0';
	this_conp->out_ptr = cp;
}
