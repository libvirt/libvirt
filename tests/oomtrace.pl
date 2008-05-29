#!/usr/bin/perl

use strict;
use warnings;

(my $ME = $0) =~ s|.*/||;
# use File::Coda; # http://meyering.net/code/Coda/
END {
  defined fileno STDOUT or return;
  close STDOUT and return;
  warn "$ME: failed to close standard output: $!\n";
  $? ||= 1;
}


my @data = <>;


my %trace;
my %lines;

foreach (@data) {
    if (/^\s*TRACE:\s+(\S+?)(?:\(.*\))?\s+\[0x(.*)\]\s*$/ ) {
	$trace{$2} = $1;
    }
}

foreach my $key (keys %trace) {
    my $val = $trace{$key};
    my $info = $val =~ /\?\?/ ? $val : `addr2line -e $val $key`;
    $lines{$key} = $info;
}


foreach (@data) {
    if (/^\s*TRACE:\s+(\S+?)(?:\(.*\))?\s+\[0x(.*)\]\s*$/ ) {
	print $lines{$2};
    } else {
	print;
    }
}
