# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(filesize-err) begin
filesize-err: exit(-1)
EOF
pass;