use 5.008008;
use ExtUtils::MakeMaker;
use ExtUtils::Embed qw/ ccopts ldopts /;

WriteMakefile(
    NAME            => 'mod_perlite',
    VERSION         => '0.5',
    ABSTRACT        => 'Simple Perl handler for Apache',
    AUTHOR          => 'Aaron Stone  <astone@serendipity.cx>',
    C               => [ qw/ mod_perlite.c/ ],
    OBJECT          => q/$(O_FILES)/,

    INC             => "-I`/usr/sbin/apxs -q INCLUDEDIR`",
    CCFLAGS         => "-g -ggdb -DMP_SYS_DL_DLOPEN=1 `pkg-config --cflags apr-1` " . ccopts,
    LDFLAGS         => ldopts,
    dynamic_lib     => { OTHERLDFLAGS => ldopts },

    # This horrible hack creates a custom 'make install' action
    # Note that the \t characters are part of Makefile syntax!
    SKIP            => [ 'install' ],
    depend          => { install => "
	# An awful hack
	/usr/sbin/apxs -n mod_perlite -i blib/arch/auto/mod_perlite/mod_perlite.so " },
);
