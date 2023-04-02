#!/usr/bin/perl
# This is a sample of the Netscape "server push" feature.  This CGI script
# will only work properly when viewed with a Netscape 1.1 or later browser.

require "ctime.pl";

# This makes i/o non-buffered.  It must be non-buffered for server push
$| = 1;

print "Content-type: multipart/x-mixed-replace; boundary=ThisRandomString\n";

print "\n--ThisRandomString\n";
for (1..4) {
    print "Content-type: text/html\n\n";
    print "<h2>Current time on the server updated every 5 seconds</h2>\n";
    print "<b>Time: ", &ctime( time), "</b>\n";

    close (PS);
    print "\n--ThisRandomString\n";
    sleep (5);
}
    print "Content-type: text/html\n\n";
    print "All done\n";
    print "\n--ThisRandomString--\n";

