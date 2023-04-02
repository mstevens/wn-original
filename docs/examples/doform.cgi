#!/usr/bin/perl

# This perl script does two fairly different things.  If is invoked
# with the environmental variable PATH_INFO set to "ismap" then it
# prints out the X and Y coordinates which it obtains from the
# environment variable QUERY_STRING.  Otherwise it assumes it has been
# invoked to handle an HTML form (via the GET or POST method) and
# processes and prints out the values and variables set in that form.

print "Content-type: text/html\n\n";


$WN_ARG = $ENV{PATH_INFO};  # Get the argument from the URL
$WN_QUERY = $ENV{QUERY_STRING};
$WN_QUERY =~ s/\+/ /g;		# Change +'s to spaces

if ( $WN_ARG =~ /ismap/) {          # Print the X,Y coords from QUERY_STRING
	($x, $y) = split( /,/, $WN_QUERY);
	print( "Here are the X and Y coordinates of the point\n");
	print( "on which you clicked: ");
	print( "X = ", $x, ", Y = ", $y, "\n");
	exit( 0);
}

if ( $ENV{REQUEST_METHOD} eq "GET") {

# It's the GET method, so assume it is a form with QUERY_STRING a string
# of the form"param1=value1&param2=value2&param3=value3..." and create an
# associative array with keys the params.


	@QUERY_LIST = split( /&/, $WN_QUERY);

	foreach $item (@QUERY_LIST) {
        	($param, $value) = split( /=/, $item);
		 $QUERY_ARRAY{$param} .= $value;
		 $QUERY_ARRAY{$param} .= " ";
	}

	# Now print it all out.

print <<EOF;
<html>
<head>
<title>Response from a Form</title>
</head>

<body bgcolor = "FFFFFF">
<h2>Response from a Form</h2>


        Here are the (sanitized) parameters which were
        sent by your form and their values:

<ul>

EOF

	foreach $param ( sort( keys(%QUERY_ARRAY))) {
		print( "<li> ", $param, " = ", &Sanitize($QUERY_ARRAY{$param}), "\n");
	}

print "</ul>\n</body>\n</html>\n";
}


if ( $ENV{REQUEST_METHOD} eq "POST") {
	
# It's the POST method, so print content length and coded input from
# STDIN.  Then decode it and print again.

print <<EOF
<html>
<head>
<title>Response from a Posted Form</title>
</head>

<body bgcolor = "FFFFFF">
<h2>Response from a Posted Form</h2>


        <b>Here is the data sent by your form using the POST method:</b><br>
EOF
;
	$len = $ENV{CONTENT_LENGTH};
	print "Posted input content-length = $len<br>\n";
	$postinput = <STDIN>;
	print "<p><b>Undecoded (sanitized) posted input:</b><br>\n";
	$spostinput = &Sanitize( $postinput);
	print "$spostinput<br>\n\n";
	$postinput =~ s/&/\n/g;
	$postinput =~ s/\+/ /g;
	$postinput =~ s/%([\da-f]{1,2})/pack(C,hex($1))/eig;
	$postinput = &Sanitize( $postinput);
	print "<p><b>Decoded (sanitized) posted input:</b><br>\n";
	print "<pre>$postinput\n\n</pre>";
	print "<p>Posted data is in file:  $ENV{HTTP_POST_FILE}\n";
	print "</body>\n</html>\n";	
}


sub Sanitize {  # Allow % in this one
	local( $fd ) = @_;
        $fd =~ s/[\<\>\"\'\;\)\(\+]//g;
        $fd =~ s/\&/&amp;/g;
	return( $fd ) ;
}
