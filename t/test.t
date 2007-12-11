
use Test::More tests => 5;

sub Perlite::IO::_header {
    my ($header, $value) = @_;
    system "echo", $header."_: _".$value;
}

sub Perlite::IO::_write {
    my ($value) = @_;
    system "echo", $value;
}

sub Perlite::_env {
    return { foo => "bar" }
}


use lib '../lib';
use_ok( 'Perlite' ); 

ok print "Hello: this is a header\n";

ok print "\nThis is a body\n";
ok print "\nThis is a body\n";
ok print "\n\nNO REALLY A BODY\n";

#ok warn "Warning\n";

#ok die "Dying\n";

ok exit;

