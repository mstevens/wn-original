/*
    Wn: A Server for the HTTP
    File: wn/search.h
    Version 2.2.5
    
    Copyright (C) 1996-2000  <by John Franks>

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

WN_CONST
char * WN_CONST out_m[] = {
	/* 0 */ "Access denied, or file does not exist",
	/* 1 */ "Directory Text Search",
	/* 2 */ "Unsuccessful search",
	/* 3 */ "File Regular Expression Search",
	/* 4 */ "Document Title/Keyword Search",
	/* 5 */ "Precondition Failed",
	/* 6 */ "File Index Search"
};


WN_CONST
char * WN_CONST search_m[] = {
	/* 0 */ "<li> <b>Maximum</b> number of matches per file exceeded.\n",
	/* 1 */ "Please Enter a Search Term",
	/* 2 */ "<hr>\nThese are the matches for the regular expression <b>`",
	/* 3 */ "Sorry, there appear to be no items containing a match for the regular expression <b>`",
	/* 4 */ "You may repeat your search with a new regular expression.\nSearches are not case sensitive.\n",
	/* 5 */ "<form action=\"search=",
	/* 6 */ "\">\nSearch term:\n<input name=\"query\">\n",
	/* 7 */ "<input type=\"submit\" value=\"Execute Search\">\n</form>\n",
	/* 8 */	"<form>\nSearch term:\n<input name=\"query\">\n"
};

