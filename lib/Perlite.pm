use strict;
use warnings;


# Replace STDIN and STDOUT with PerlIO::via -- Perlite::IO
# the filenames are dummy values and are not actually used
open(my $in, '<:via(Perlite::IO)', 'mod_perlite_stdin' );
open(my $out, '>:via(Perlite::IO)', 'mod_perlite_stdout' );
*STDIN = $in;
*STDOUT = $out;

# Catch and pretty-print errors
$SIG{__DIE__} = sub { print "<br><b>Dying</b>: <pre>\n$@\n</pre>\n" if $@ };
$SIG{__WARN__} = sub { print "<br><b>Warning</b>: <pre>\n$@\n</pre>\n" if $@ };

# Replace the actual %ENV with a CGI-compatible %ENV
%ENV = %{ Perlite::_env () };


package Perlite::IO;

# XS: _write, _header

sub PUSHED { bless \*PUSHED, $_[0] }

sub OPEN { 1 }

sub FILL { undef }

my $body = 0;

sub WRITE {
    my ($class, $buffer, $handle) = @_;

    return _write($buffer) if $body; # print to body

    # If there was a long block of headers and body, this finds the body part
    my $cr = $buffer =~ tr/\r\n\r\n//;
    my $cn = $buffer =~ tr/\n\n//;

    # The next time someone prints something, it's in body space
    $body = 1 if $cr or $cn;

    my ($header, $bodytext) = split /\r\n\r\n/, $buffer, 2 if $cr;
       ($header, $bodytext) = split /\n\n/, $buffer, 2 if $cn;

    # This is probably the usual case: someone prints a single header lines
    $header = $buffer unless $header;

    # Handles the case of printing many header lines
    my @headerlines = split /\n/, $header;

    # Split each line into key and value pairs, then set the header
    foreach (@headerlines) {
        my ($header, $value) = split /: /, $_, 2;
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
    my $file = shift;
    return unless $file;
    require $file;
}

1;
