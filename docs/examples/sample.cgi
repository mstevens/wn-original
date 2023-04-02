#!/usr/bin/perl

# Simple example of CGI script.

$PPID = getppid();

print "Content-type: text/html; charset=iso-8859-1\r\n"; 
# The first line must specify content type

print "\r\n";                        # A blank line ends the headers

# From now on everything goes to the client

print "<!doctype html public \"-//W3C//DTD HTML 3.2 Final//EN\">\n";
print "<html>\n";
print "  <head>\n";
print "    <title>WN Executable Program Example -- Results</title>\n";
print "  </head>\n";
print "\n";
print "  <body>\n";
print "    <h2>Here are sanitized values of some standard CGI environment variables:</h2>\n";
print "\n";
print "    <p>\n";
print "      Parent Pid = $PPID<br>\n";

$var = $ENV{PATH_INFO};
$var = &Sanitize( $var);
print "      PATH_INFO = $var<br>\n";

print "      SERVER_SOFTWARE = $ENV{SERVER_SOFTWARE}<br>\n";
print "      SERVER_NAME = $ENV{SERVER_NAME}<br>\n";
print "      SERVER_PROTOCOL = $ENV{SERVER_PROTOCOL}<br>\n";
print "      SERVER_PORT = $ENV{SERVER_PORT}<br>\n";
print "      AUTH_TYPE = $ENV{AUTH_TYPE}<br>\n";
print "      REMOTE_USER = $ENV{REMOTE_USER}<br>\n";

$var = $ENV{HTTP_ACCEPT};
$var = &Sanitize( $var);
print "      HTTP_ACCEPT = $var <br>\n";

$var = $ENV{HTTP_ACCEPT_CHARSET};
$var = &Sanitize( $var);
print "      HTTP_ACCEPT_CHARSET = $var<br>\n";

$var = $ENV{HTTP_ACCEPT_LANGUAGE};
$var = &Sanitize( $var);
print "      HTTP_ACCEPT_LANGUAGE = $var<br>\n";

$var = $ENV{HTTP_RANGE};
$var = &Sanitize( $var);
print "      HTTP_RANGE = $var<br>\n";

$var = $ENV{HTTP_REFERER};
$var = &Sanitize( $var);
print "      HTTP_REFERER = $var<br>\n";

$var = $ENV{HTTP_USER_AGENT};
$var = &Sanitize( $var);
print "      HTTP_USER_AGENT = $var<br>\n";

$var = $ENV{HTTP_FROM};
$var = &Sanitize( $var);
print "      HTTP_FROM = $var<br>\n";

$var = $ENV{HTTP_HOST};
$var = &Sanitize( $var);
print "      HTTP_HOST = $var<br>\n";

$var = $ENV{HTTP_COOKIE};
$var = &Sanitize( $var);
print "      HTTP_COOKIE = $var<br>\n";

$var = $ENV{PATH_TRANSLATED};
$var = &Sanitize( $var);
print "      PATH_TRANSLATED = $var<br>\n";

print "      SCRIPT_NAME = $ENV{SCRIPT_NAME}<br>\n";
print "      SCRIPT_FILENAME = $ENV{SCRIPT_FILENAME}<br>\n";

$var = $ENV{QUERY_STRING};
$var = &Sanitize( $var);
print "      QUERY_STRING = $var<br>\n";

$var = $ENV{HTTP_X_FORWARDED_FOR};
$var = &Sanitize( $var);
print "      HTTP_X_FORWARDED_FOR = $var<br>\n";

$var = $ENV{HTTP_VIA};
$var = &Sanitize( $var);
print "      HTTP_VIA = $var<br>\n";


print "      REMOTE_HOST = $ENV{REMOTE_HOST}<br>\n";
print "      REMOTE_ADDR = $ENV{REMOTE_ADDR}<br>\n";
print "      REQUEST_METHOD = $ENV{REQUEST_METHOD}<br>\n";
print "    </p>\n";
print "\n";
print "    <h2>Non-CGI variables provided by the WN server:</h2>\n";
print "\n";
print "    <p>\n";
print "      URL_SCHEME = $ENV{URL_SCHEME}<br>\n";
print "      DOCUMENT_ROOT = $ENV{DOCUMENT_ROOT}<br>\n";
print "      WN_DIR_PATH = $ENV{WN_DIR_PATH}<br>\n";
print "      WN_KEY = $ENV{WN_KEY}<br>\n";
print "      REMOTE_PORT = $ENV{REMOTE_PORT}<br>\n";
print "      HTTP_POST_FILE = $ENV{HTTP_POST_FILE}<br>\n";
print "      HTTP_PUT_FILE = $ENV{HTTP_POST_FILE}<br>\n";
print "    </p>\n";
print "  </body>\n";
print "</html>\n";
exit(0);

sub Sanitize {
	local( $fd ) = @_;
        $fd =~ s/[\<\>\"\'\%\;\)\(\&\+]//g;
	return( $fd ) ;
}
