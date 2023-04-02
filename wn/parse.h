/*
    Wn: A Server for the HTTP
    File: wn/parse.h
    Version 2.3.0
    
    Copyright (C) 1995-9  <by John Franks>

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


#define TEXT_TOKEN		(0)
#define END			(1)
#define ELSE			(2)
#define ENDIF			(3)
#define FIELD			(4)
#define IF_TRUE			(5)
#define IF_FALSE		(6)
#define IF_ERR			(7)
#define INCLUDE			(8)
#define QUERY			(9)
#define REDIRECT		(10)
#define START			(11)
#define SECTION			(12)
#define SEARCH_ON		(13)
#define SEARCH_OFF		(14)
#define TITLE			(15)
#define MATCH_ACCEPT		(16)
#define MATCH_UA		(17)
#define MATCH_REFERRER		(18)
#define MATCH_IP		(19)
#define MATCH_HOST		(20)
#define MATCH_COOKIE		(21)
#define MATCH_QUERY		(22)
#define MATCH_PARAM_FIELD	(23)
#define MATCH_PARAM_VALUE	(24)
#define MATCH_REQUEST		(25)
#define MATCH_HOST_HEAD		(26)
#define MATCH_FIELD		(27)
#define ENVIRON			(28)
#define COMMENT			(29)
#define ELIF_TRUE		(30)
#define ELIF_FALSE		(31)
#define PARSE_TOO_DEEP		(32)
#define LIST_INCLUDE		(33)
#define LIST_SECTION		(34)
#define EMPTY_TOKEN		(35)
#define MATCH_LANGUAGE		(36)
#define MATCH_BASIC_USER	(37)
#define KEYWORDS		(38)
#define LAST_MOD_DATE		(40)
#define MATCH_CHARSET		(41)
#define MATCH_A_ENCODING	(42)
#define MATCH_TE		(43)
#define MATCH_ENVIRON		(44)
#define MATCH_REM_USER		(45)


typedef struct Parsedata {
	unsigned	show;  /* see comment below */
	char		*currfile;
	int		currline;
} Parsedata;

/* 
 * The Parsedata field show has four significant bits.  The first SHOW_MSK
 * when set indicates, in parsed if clauses, to serve the
 * current text.  The third, SECT_MSK, when set indicates that the 
 * file is being served by virtue of a <!-- section ... directive.
 * The second, IN_SECT_MSK, indicates that the current line is inside
 * the start/end pair for the section and hence viewable.  In general
 * when show == SHOWIT the current line should be displayed.  The
 * fourth bit of show is ERR_MSK.  It is set if an error occurs, e.g.
 * inability to open an accessfile.
 */

#define SHOW_MSK	(1)
#define IN_SECT_MSK	(2)
#define SECT_MSK	(4)
#define SHOW_IT		(SHOW_MSK + IN_SECT_MSK)
#define ERR_MSK		(8)

/* tokens for pstack and sstack */

#define PS_NULL		(0)
#define PS_IF		(1)
#define PS_ELSE		(2)
#define PS_ELIF		(3)
#define SS_SHOW		(1 * 16)
#define SS_NOSHOW	(2 * 16)
#define SS_HIDDEN	(3 * 16)
#define SS_SEEN		(4 * 16)
#define PARSE_MASK	(15)		/* = 0f */
#define STATE_MASK	(15 * 16)	/* = 0f0 */
#define STACKSIZE	(64)		/* size of parse stack */

/* status for do_swrap */

#define SWSTAT_NO_INCL	(0)
#define SWSTAT_INCL	(1)
#define SWSTAT_ERROR	(2)

/* return values for gettoken */

#define IFCLAUSE_TERM	(1)
#define IFCLAUSE_END	(2)
#define IFCLAUSE_AND	(3)
#define IFCLAUSE_OR	(4)
#define IFCLAUSE_ERR	(5)



extern
WN_CONST 
char * WN_CONST parserr_m[];




