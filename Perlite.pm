use strict;
use warnings;


# Replace STDIN and STDOUT with PerlIO::via -- Perlite::IO
# the filenames are dummy values and are not actually used
open(my $in, '<:via(Perlite::IO)', 'mod_perlite_stdin' );
open(my $out, '>:via(Perlite::IO)', 'mod_perlite_stdout' );
*STDIN = $in;
*STDOUT = $out;

# Hopefully these will help to catch and pretty-print errors
$SIG{__DIE__} = sub { print "<br><b>Died: <pre>$!</pre>" };
$SIG{__WARN__} = sub { print "<br><b>Warned</b>: <pre>$!</pre>" };

# Replace the actual %ENV with a CGI-compatible Apache %ENV
my $_ENV = Perlite::perlite_get_env;
%ENV = %$_ENV;


package Perlite::IO;

sub PUSHED { bless \*PUSHED, $_[0] }

sub OPEN { 1 }

sub FILL { undef }

# Return the number of bytes written
sub WRITE {
    my ($class, $buffer, $handle) = @_;

    perlite_io_write($buffer);

    return 6;
}

1;


package Perlite;

sub run_file {
    my $file = shift;
    return unless $file;
    require $file;
}

1;
