#!/usr/bin/perl

use strict;

my $file = " ";
my $ret = 0;
my %includes = ( );

while (<>) {
    if (not $file eq $ARGV) {
        %includes = ( );
        $file = $ARGV;
    }
    if (/^# *include *[<"]([^>"]*\.h)[">]/) {
        $includes{$1}++;
        if ($includes{$1} == 2) {
            $ret = 1;
            print STDERR "$1 included multiple times in $ARGV\n";
        }
    }
}
exit $ret;
