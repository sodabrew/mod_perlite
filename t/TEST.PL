use strict;
use warnings FATAL => 'all';
use Apache::TestRun qw();
Apache::TestRun->new->run(@ARGV);
