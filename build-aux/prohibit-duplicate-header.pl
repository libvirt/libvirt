#!/usr/bin/env perl

use strict;

my $file = " ";
my $ret = 0;
my %includes = ( );
my $lineno = 0;

while (<>) {
    if (not $file eq $ARGV) {
        %includes = ( );
        $file = $ARGV;
        $lineno = 0;
    }
    $lineno++;
    if (/^# *include *[<"]([^>"]*\.h)[">]/) {
        $includes{$1}++;
        if ($includes{$1} == 2) {
            $ret = 1;
            print STDERR "$ARGV:$lineno: $_";
            print STDERR "Do not include a header more than once per file\n";
        }
    }
}
exit $ret;
