use 5.006;
use strict;
use warnings;


# Replace STDIN and STDOUT with PerlIO::via(Perlite::IO)
# Note the filenames are dummy values and are not actually used
open(my $in, '<:via(Perlite::IO)', 'mod_perlite_stdin' );
open(my $out, '>:via(Perlite::IO)', 'mod_perlite_stdout' );
*STDIN = $in;
*STDOUT = $out;

# Catch and pretty-print errors
$SIG{__DIE__} = sub {
    my $err = $_[0] || $@ || $!;
    if ($Perlite::IO::body) {
        print "\n\n<br><b>Dying</b>: <pre>\n$err\n</pre>\n" if $err;
        #my $i = 0;
        #while (my @c = caller($i++)) {
        #    print "<pre>";
        #    print $c[3] ;
        #    print "</pre>";
        #}
    } else {
        Perlite::IO::_header("Content-Type", "text/html");
    }
    *CORE::GLOBAL::exit = sub { };
};

$SIG{__WARN__} = sub {
    if ($Perlite::IO::body) {
        print "<br><b>Warning</b>: <pre>\n$_[0]\n</pre>\n" 
    }
};

# Replace the actual %ENV with a CGI-compatible %ENV
%ENV = %{ Perlite::_env () };

# Put us into the local directory of the script
($ENV{PWD}) = ($ENV{SCRIPT_FILENAME} =~ m#(.*/)[^/]*#);
chdir($ENV{PWD});


package Perlite::IO;

# XS: _write, _header

sub BINMODE { 0 }

sub PUSHED { bless \*PUSHED, $_[0] }

sub OPEN { 1 }

sub FILL { return _read () }

our $body = 0;
my $unput = "";

sub WRITE {
    my ($class, $buffer, $handle) = @_;

#    Perlite::_log(1, "Buffer is [$buffer] and body is [$body]");

    return _write($buffer) if $body; # print to body

    # TODO: Handle situation of:
    #       Header: Value\n
    #       \n Body...
    # Note how the necessary \n\n is spread across two writes.

#    $unput = substr $buffer, -2 if substr $buffer, -2 eq "\r\n";
#    $unput = substr $buffer, -1 if substr $buffer, -1 eq "\n";
#    $body = 1 if $unput eq "\n" and substr $buffer, 0, 1 eq "\n";
#    $body = 1 if $unput eq "\r\n" and substr $buffer, 0, 2 eq "\r\n";

    # If there was a long block of headers and body, this finds the body part
    $body = $buffer =~ m/\r\n\r\n|\n\n/ ? 1 : 0;

#    Perlite::_log(1, "Buffer is [$buffer] and body is [$body]");

    my ($header, $bodytext);
       ($header, $bodytext) = split /\r\n\r\n|\n\n/, $buffer, 2 if $body;

#    Perlite::_log(1, "Header is [$header]");
    # This is probably the usual case: someone prints a single header lines
    $header = $buffer unless $header;
#    Perlite::_log(1, "Header is [$header]");

    # Handles the case of printing many header lines
    my @headerlines = split /\r\n|\n/, $header;

    # Split each line into key and value pairs, then set the header
    foreach (@headerlines) {
        my ($header, $value) = split /: /, $_, 2;
#        Perlite::_log(1, "Looking at $_");
#        Perlite::_log(1, "Missing header") unless $header;
#        Perlite::_log(1, "Missing value for header $header") unless $value;
#        Perlite::_log(1, "Setting header [$header]: [$value]");
        last unless $header and $value;
        _header($header, $value);
    }

    # If there was a long block of headers and body, this prints the body part
    _write($bodytext) if ($bodytext);

    return length $buffer; # lie and say we printed everything
}

1;


package Perlite;

# XS: _log, _env

sub run_file {
    # Someone can still call CORE::exit if they really want to.
    *CORE::GLOBAL::exit = sub { goto Perlite__EXIT };

    my $file = shift;
    die "Couldn't find file: $file" unless $file;
    do $file;

    return 1;

  Perlite__EXIT:
    return _exit ();
}

1;

