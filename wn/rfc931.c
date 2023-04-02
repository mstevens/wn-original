
/************************************************************************
* Copyright 1995 by Wietse Venema.  All rights reserved.  Some individual
* files may be covered by other copyrights.
*
* This material was originally written and compiled by Wietse Venema at
* Eindhoven University of Technology, The Netherlands, in 1990, 1991,
* 1992, 1993, 1994 and 1995.
*
* Redistribution and use in source and binary forms are permitted
* provided that this entire copyright notice is duplicated in all such
* copies.  No charge, other than an "at-cost" distribution fee, may be
* charged for copies, derivations, or distributions of this material
* without the express written consent of the copyright holder.
*
* This software is provided "as is" and without any expressed or implied
* warranties, including, without limitation, the implied warranties of
* merchantibility and fitness for any particular purpose.
************************************************************************/

 /*
  * rfc931() speaks a common subset of the RFC 931, AUTH, TAP, IDENT and RFC
  * 1413 protocols. It queries an RFC 931 etc. compatible daemon on a remote
  * host to look up the owner of a connection. The information should not be
  * used for authentication purposes. This routine intercepts alarm signals.
  * 
  * Diagnostics are reported through syslog(3).
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

 /*
  * Originally from tcp_wrappers 7.2 package; modifications for WN/1.01
  * support by Christopher Davis <ckd@kei.com>
  *
  * Modifications include:
  *   - use of wn.h rather than tcpd.h for config information
  *   - use of logerr instead of tcpd_warn
  *   - use of mystrncpy instead of STRN_CPY
  *   - buffer sizes chosen from wn's common.h
  */

 /*
  * Modified by Kenji Rikitake <kenji.rikitake@acm.org>
  * to support T/TCP protocol for WN-2.0.0pre
  * 17-JUN-1998
  *
  * Modifications include:
  *   - use of raw socket I/O than stdio
  *   - use of T/TCP-compliant style of programming
  *   - use of goto statements to avoid
  *     unnecessary conditions in the if statements
  */

/* System libraries. */



/* header files added for T/TCP */

#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

/* Local stuff. */

#include "wn.h"

#ifdef RFC931_TIMEOUT   /* Only do RFC931 if this is defined */

#define	BUFFSIZE	(8192)
#define	RFC931_PORT	113		/* Semi-well-known port */
#define	ANY_PORT	0		/* Any old port will do */

int     rfc931_timeout = RFC931_TIMEOUT;/* Global so it can be changed */

static jmp_buf timebuf;
static char  *rfc931_result = "";


/* fsocket() no longer needed here */

/* timeout - handle timeouts */

static void timeout(sig)
int     sig;
{
    longjmp(timebuf, sig);
}

/* rfc931 - return remote user name, given socket structures */

void    
rfc931(rmt_sin, our_sin, dest)
struct sockaddr_in *rmt_sin;
struct sockaddr_in *our_sin;
char   *dest;
{
    unsigned rmt_port;
    unsigned our_port;
    struct sockaddr_in rmt_query_sin;
    struct sockaddr_in our_query_sin;
    char    user[SMALLLEN];
    char    buffer[BUFFSIZE];
    char   *cp;
    int     buflen;
    int	    nleft;
    int	    nread;
    int     sockfd;
#ifdef MSG_EOF
    int    ttcp;
#endif /* MSG_EOF */

    /* open the socket */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	logerr( err_m[77], "");
	return;
    }

    /*
     * Set up a timer so we won't get stuck while waiting for the server.
     */
    if (setjmp(timebuf) == 0) {
	signal(SIGALRM, timeout);
	alarm(rfc931_timeout);

	/*
	 * Bind the local and remote ends of the query socket to the same
	 * IP addresses as the connection under investigation. We go
	 * through all this trouble because the local or remote system
	 * might have more than one network address. The RFC931 etc.
	 * client sends only port numbers; the server takes the IP
	 * addresses from the query socket.
	 */
	 
	our_query_sin = *our_sin;
	our_query_sin.sin_port = htons(ANY_PORT);
	rmt_query_sin = *rmt_sin;
	rmt_query_sin.sin_port = htons(RFC931_PORT);

	/* bind socket first */
	if (bind(sockfd, (struct sockaddr *) & our_query_sin,
		     sizeof(our_query_sin)) < 0) {
	    logerr( "RFC931 lookup bind error", "");
	    goto timer_exit;
	}

	/* create the query message to the server */
	sprintf(buffer, "%u,%u\r\n",
		ntohs(rmt_sin->sin_port),
		ntohs(our_sin->sin_port));
	buflen = strlen(buffer);

#ifdef MSG_EOF
	ttcp = 1;

	/* set TCP_NOPUSH option */
	if (setsockopt(sockfd, IPPROTO_TCP, TCP_NOPUSH,
			(char *)&ttcp, sizeof(ttcp)) < 0) {
	    daemon_logerr( "RFC931 T/TCP unsupported: setsockopt error", 
				"", errno);
	    if (errno == ENOPROTOOPT) {
	        logerr( "RFC931 setsockopt error recovered by connect()", "");
	    	goto do_connect;
	    }
	    goto timer_exit;
	}

	/* send the query and close by using sendto() */
	if (sendto(sockfd, buffer, buflen, MSG_EOF,
		(struct sockaddr *) & rmt_query_sin, 
		sizeof(rmt_query_sin)) != buflen) {
	    daemon_logerr( "RFC931 T/TCP unsupported: sendto error",
				"", errno);
	    if (errno == ENOTCONN) {
	        logerr( "RFC931 sendto error recovered by connect()", "");
	    	goto do_connect;
	    }
	    goto timer_exit;
	}
	goto sendto_ok;

    do_connect:
#endif /*MSG_EOF */

	/* do conventional connect() */
	if (connect(sockfd, (struct sockaddr *) & rmt_query_sin,
			sizeof(rmt_query_sin)) < 0) {
	    /* 
	     * do not log the error
	     * if connection is refused or reset 
	     */
		if ( (errno != ECONNREFUSED) && (errno != EHOSTUNREACH)
					&& (errno != ECONNRESET)) {
		daemon_logerr( "RFC931 connect error", "", errno);
		}
	    goto timer_exit;
	}
	/* send the query to the server */
	if (write(sockfd, buffer, buflen) != buflen) {
	    daemon_logerr( "RFC931 write error", "", errno);
	    goto timer_exit;
	}
	/* nothing more to send, so shutdown the write socket */
	if (shutdown(sockfd, 1) < 0) {
	    daemon_logerr( "RFC931 shutdown error", "", errno);
	    goto timer_exit;
	}

#ifdef MSG_EOF
    sendto_ok:
#endif /* MSG_EOF */
	   
	/* read response from the server */
	cp = buffer;
	nleft = sizeof(buffer);
	while (nleft > 0) {
	    if ((nread = read(sockfd, cp, nleft)) < 0) {
	    	/* 
		 * RFC931 read error, 
		 * but you don't need this logged, do you? 
		 */
		goto timer_exit;
		}
	    else if (nread == 0)
		break;
	    nleft -= nread;
	    cp += nread;
	}
	nread = sizeof(buffer) - nleft;
	/* 
	 * parse the received message
	 * parse error ignored
	 */
	if ( (nread > 0)
	    && (sscanf(buffer, "%u , %u : USERID :%*[^:]:%255s",
				&rmt_port, &our_port, user) == 3)
	    && (ntohs(rmt_sin->sin_port) == rmt_port)
	    && (ntohs(our_sin->sin_port) == our_port) ) {
	    /*
	     * Strip trailing carriage return. It is part of the
	     * protocol, not part of the data.
	     */
	    if ( (cp = strchr( user, '\r')) != NULL)
		*cp = 0;
	    rfc931_result = user;
	}

    timer_exit:
	alarm(0);
	close(sockfd);
    }
    mystrncpy(dest, rfc931_result, SMALLLEN);
}
#endif /* RFC931_TIMEOUT */

