use strict;
use warnings;

use Apache::TestMB qw();

my $class = Apache::TestMB->subclass(
    class => "Module::Build::Custom",
    code => <<'SUBCLASS' );

sub ACTION_code {
    my $self = shift;
    my $apxs = $self->args('apxs');
    unless ($apxs) {
        use File::Which qw(which);
        my @apxs = which 'apxs';
        unless (@apxs) {
            die <<'NOAPXS';
The apxs binary needed for extending the Apache webserver could not be found in
your PATH. In case you do have apxs, specify it explicitely:
    perl Build.PL --apxs=/path/to/apxs

NOAPXS
        } elsif (1 < scalar @apxs) {
            die <<"MANYAPXS";
Found several apxs binaries.
    @apxs

Specify which Apache installation to extend:
    perl Build.PL --apxs=/path/to/apxs

MANYAPXS
        } else {
            ($apxs) = @apxs;
            print "Using apxs binary: $apxs\n";
        }
    }
    $self->config_data(apxs => $apxs);

    use ExtUtils::Embed qw/ ccopts ldopts /;

    my $CC = `$apxs -q CC`;
    my $INC = '-I' . `$apxs -q INCLUDEDIR`;
    my $LDFLAGS = ldopts;
    my $CCFLAGS = '-fPIC -g -ggdb -DMP_SYS_DL_DLOPEN=1 ' . `pkg-config --cflags apr-1` . ccopts;
    my $VERSION = '-DVERSION=\"' . $self->dist_version . '\"';

    my $build = "$CC -c mod_perlite.c $CCFLAGS $INC $VERSION";
    $build =~ s/\n//g;

    my $link = "$CC -shared mod_perlite.o -o mod_perlite.so $CCFLAGS $LDFLAGS";
    $link =~ s/\n//g;

    print $build, "\n";
    `$build`;

    print $link, "\n";
    `$link`;

    $self->SUPER::ACTION_code;
}

sub ACTION_install {
    my $self = shift;
    my $apxs = $self->config_data('apxs');
    `$apxs -n mod_perlite -i mod_perlite.so`;
    $self->SUPER::ACTION_install;
}
SUBCLASS

$class->new(
    module_name     => 'Perlite',
    license         => 'perl',
    dist_author     => 'Aaron Stone <aaron@serendipity.cx>',
    dist_abstract   => 'lightweight Perl module for Apache 2.x',
    dist_version    => '0.10',
    configure_requires => {
        # need to be available for Build.PL to run
        'Apache::Test'  => '1.30',
        'File::Which'   => 0,
        'Module::Build' => '0.26', # for config_data
    },
    build_requires  => {
        # Those below are actually test_requires, but only Module::Install makes
        # that distinction; Module::Build and META.yml don't (yet).
        'CGI'           => 0,
        'Data::Dumper'  => 0,
    },
    requires => {
        'perl'          => '5.6.0',
    },
    add_to_cleanup  => [
        'mod_perlite.o',
        'mod_perlite.so',
        't/conf/apache_test_config.pm',
        't/conf/extra.conf',
        't/conf/httpd.conf',
        't/htdocs/index.html',
        't/logs',
    ],
)->create_build_script;
