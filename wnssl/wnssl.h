/*
    WN/WNSSL
    File: wn/wnssl.h
    Version 2.4.5
    
    Copyright (C) 1996-2003  <by Elias Doumas>

    Modified for WN 2.0 and SSL 0.8 by Matthias Cramer <cramer@freestone.net>
    Modified for WN 2.3* and openssl by John Franks 

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
#define NOPROTO
#define OPENSSL_NO_KRB5
#define WNSSL_ENVIRON 	(TRUE)
#define WNSSL_DEBUG 	(FALSE)

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>

#if  (OPENSSL_VERSION_NUMBER >=  (0x00904000L))
#define wnPEM_read_RSAPrivateKey(f,k,x) PEM_read_RSAPrivateKey(f,k,x,NULL)
#define wnPEM_read_X509(f,c,x)    PEM_read_X509(f,c,x,NULL)
#else
#define wnPEM_read_RSAPrivateKey(f,k,x) PEM_read_RSAPrivateKey(f,k,x)
#define wnPEM_read_X509(f,c,x)    PEM_read_X509(f,c,x)
#endif

#define DEFAULT_CERT_FILENAME	"wnssl.pem"

extern char   *ERR_error_string(),
              ssl_file_path[],
              ssl_buf[],
              env_cipher[],
              env_subject[],
              env_issuer[],
              env_serial[];

extern int    ERR_get_error();


#define is_ssl_fd(X,Y)    ( (SSL_get_fd((X))==0) || \
                            (SSL_get_fd((X))==1) || \
                            (SSL_get_fd((X))==(Y)) \
                          )

extern SSL *ssl_con;
extern SSL_CTX *ssl_ctx;
extern int ssl_debug_flag;
extern int ssl_verify_flag;
extern int standalone_debug;
extern X509 *ssl_public_cert;
extern RSA *ssl_private_key;
