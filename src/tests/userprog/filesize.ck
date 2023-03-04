use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF', <<'EOF']);
(filesize) begin
(filesize) Success
filesize: exit(0)
EOF
(filesize) begin
filesize: exit(-1)
EOF
pass;