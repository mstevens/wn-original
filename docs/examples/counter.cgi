#!/usr/bin/perl

require "stat.pl";
require "ctime.pl";

# This perl program counts accesses to a file foo.html and prints
# the last modified date for that file.  Set the variable $file
# to the complete path of the file whose accesses you want to count.
# $countfile is a file which will contain the current count.  The complete 
# filename must be given for it too.  A careful version of this program
# would do file locking since multiple processes might be trying to
# update $countfile simultaneously.  Note that the WN user id (usually
# "nobody") must have write permission for this file.

$countfile = "/tmp/wncount";
$file = "$ENV{WN_DIR_PATH}/index.html";

&Stat( $file);

if (! -e $countfile)
{
  open(COUNT, ">$countfile") || die "Cannot open file: $! for writing";
  print COUNT "0";
  close(COUNT);
}

open( COUNT, "<$countfile" ) || die "Can't open file: $! for reading";
$count = <COUNT>;
close( COUNT);
$count++;

print "<p>\n";
print "  You are viewer <strong>", $count, "</strong> to see this page.\n";
print "</p>\n";
print "<p>\n";
print "  It was last modified <strong>", &ctime($st_mtime), "</strong>\n";
print "</p>\n";

open( COUNT, ">$countfile" ) || die "Can't open file: $! for writing";
print COUNT $count, "\n";
close (COUNT);
