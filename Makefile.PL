use 5.008008;
use ExtUtils::MakeMaker;
use ExtUtils::Embed qw/ ccopts ldopts /;

WriteMakefile(
    NAME            => 'mod_perlite',
    VERSION         => '0.1',
    ABSTRACT        => 'Simple Perl handler for Apache',
    AUTHOR          => 'Aaron Stone  <astone@serendipity.cx>',
    C               => [ qw/ mod_perlite.c
                         modperl_io.c modperl_io_apache.c modperl_util.c modperl_filter.c modperl_handler.c
                         modperl_error.c modperl_sys.c modperl_debug.c modperl_cgi.c modperl_global.c
                         / ],
    OBJECT          => q/$(O_FILES)/,

    INC             => "-I`/usr/sbin/apxs -q INCLUDEDIR`",
    CCFLAGS         => " -DMP_SYS_DL_DLOPEN=1 `pkg-config --cflags apr-1` " . ccopts,
    LDFLAGS         => ldopts,
    dynamic_lib     => { OTHERLDFLAGS => ldopts },

    # This horrible hack creates a custom 'make install' action
    # Note that the \t characters are part of Makefile syntax!
    SKIP            => [ 'install' ],
    depend          => { install => "
	# An awful hack
	/usr/sbin/apxs -n mod_perlite -i blib/arch/auto/mod_perlite/mod_perlite.so " },
);
