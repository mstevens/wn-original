/*
    WNDigest
    File digestauth/wndigest.h
    Version 1.2
    
    Copyright (C) 1995, 1996  <by John Franks>

    This program is free software; you can redistribute it and/or modify
    it in any way you choose.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#define BIGLEN		(4096)
#define MIDLEN		(2048)
#define SMALLLEN	(256)
#define TINYLEN		(32)

#ifndef TRUE
#define TRUE	(1)
#endif

#ifndef FALSE
#define FALSE	(0)
#endif

#define WN_REALM_NAME	"wndigest_realm"
#define streq( a, b)	( strcmp( (a), (b)) == 0 )


#define AUTH_GRANTED	(0)
#define AUTH_DENIED	(1)
#define AUTH_EXPIRED	(2)

#define AUTHERR_NUM3	(3)	/* Badly formed user info string */
#define AUTHERR_NUM4	(4)	/* Can't open passwd file */
#define AUTHERR_NUM5	(5)	/* Can't init dbm file */
#define AUTHERR_NUM6	(6)	/* DBM fetch failed */
#define AUTHERR_NUM7	(7)	/* No password file listed on command line */
#define AUTHERR_NUM8	(8)	/* DBM code for authorization not installed */
#define AUTHERR_NUM9	(9)	/* Unknown authorization type */
#define AUTHERR_NUM10	(10)	/* No AUTHORIZATION line */
#define AUTHERR_NUM11	(11)	/* Authorization module failed */
#define AUTHERR_NUM12	(12)	/* Improper usage: bad options */
#define AUTHERR_NUM13	(13)	/* No REQUEST_METHOD environmental variable */
#define AUTHERR_NUM14	(14)	/* No REMOTE_ADDR environmental variable */
#define AUTHERR_NUM15	(15)	/* Unsupported hash algorithm */

#define AUTHERR_NUM16	(16)	/* Timed Out */
#define AUTHERR_NUM17	(17)	/* No realm available */

typedef struct AuthData {
	char	username[SMALLLEN],
		realm[SMALLLEN],
		nonce[SMALLLEN],
		cnonce[SMALLLEN],
		qop[SMALLLEN],
		algorithm[SMALLLEN],
		nonce_count[TINYLEN],
		message[SMALLLEN],
		uri[MIDLEN],
		response[SMALLLEN],
		opaque[SMALLLEN];

} AuthData;
