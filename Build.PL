#!/usr/bin/perl

use strict;
use warnings;

use Module::Build;

my $class = Module::Build->subclass(
    class => "Module::Build::Custom",
    code => <<'SUBCLASS' );

sub ACTION_code {
    my $self = shift;

    use ExtUtils::Embed qw/ ccopts ldopts /;

    my $CC = `apxs -q CC`;
    my $INC = '-I' . `/usr/sbin/apxs -q INCLUDEDIR`;
    my $LDFLAGS = ldopts;
    my $CCFLAGS = '-fPIC -g -ggdb -DMP_SYS_DL_DLOPEN=1 ' . `pkg-config --cflags apr-1` . ccopts;
    my $VERSION = '-DVERSION=\"' . $self->dist_version . '\"';
    
    my $build = "$CC $CCFLAGS $INC $VERSION -shared -c mod_perlite.c";
    $build =~ s/\n//g;

    my $link = "$CC $LDFLAGS -shared mod_perlite.o -o mod_perlite.so";
    $link =~ s/\n//g;

    print $build, "\n";
    `$build`;

    print $link, "\n";
    `$link`;

    $self->SUPER::ACTION_code;
}

sub ACTION_install {
    my $self = shift;
    `/usr/sbin/apxs -n mod_perlite -i mod_perlite.so`;
    $self->SUPER::ACTION_install;
}
SUBCLASS

$class->new(
    module_name     => 'Perlite',
    license         => 'perl',
    dist_author     => 'Aaron Stone <aaron@serendipity.cx>',
    dist_version    => '0.06',
)->create_build_script;
