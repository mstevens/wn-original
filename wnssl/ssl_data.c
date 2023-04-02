/*
    WN/SSL
    File: ssl_data.c
    Version 2.3.8

    Copyright (C) 2000  <by John Franks>
    Based on the work by Tim Hudson and Elias Doumas, and Matthias Cramer

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

#include "wn.h"
#include "wnssl.h"

SSL *ssl_con;
SSL_CTX *ssl_ctx;
int ssl_debug_flag = FALSE;
int ssl_verify_flag = SSL_VERIFY_NONE;
int standalone_debug = FALSE;
X509 *ssl_public_cert;
RSA *ssl_private_key;

 
char ssl_file_path[MIDLEN],
	ssl_buf[2*SMALLLEN],
	env_cipher[2*SMALLLEN],
	env_subject[2*SMALLLEN],
	env_issuer[2*SMALLLEN];

