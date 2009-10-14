use strict;
use warnings FATAL => 'all';
use Apache::Test;
use Apache::TestUtil;
use Apache::TestRequest 'GET_BODY';

plan tests => 2;
ok t_cmp(
    GET_BODY('/hello.perlite'),
    'Hello world from mod_perlite!',
    'print to STDOUT'
);
ok t_cmp(
    GET_BODY('/env.perlite'),
    qr|'REQUEST_URI' => '/env.perlite',|,
    'CGI dumped environment'
);
