#!/usr/bin/perl
#
# Copyright (C) 2006-2007 Daniel P. Berrange
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
#
# Author: Daniel P. Berrange <berrange@redhat.com>
#
# coverage-report.pl: generate XML coverage summary report
#
# This script takes a listof gcov .cov files as args, and generates
# an XML document summarizing the coverage per function and per
# source file.

use warnings;
use strict;

my %coverage = ( function => {}, file => {} );

my @functionBlackList = (
			 "__memcpy",
			 "__memmove",
			 "__memset",
			 "__strcat",
			 "__strcpy",
			 "__strncpy",
			 "__strsep",
			 "__strtok"
		      );

my %filemap;

my $type;
my $name;

my @functions;

while (<>) {
    if (/^Function '(.*)'\s*$/) {
	$type = "function";
	$name = $1;
	$coverage{$type}->{$name} = {};
	push @functions, $name;
    } elsif (/^File '(.*?)'\s*$/) {
	$type = "file";
	$name = $1;
	$coverage{$type}->{$name} = {};

	foreach my $func (@functions) {
	    $coverage{"function"}->{$func}->{file} = $name;
	}
	@functions = ();
    } elsif (/^Lines executed:(.*)%\s*of\s*(\d+)\s*$/) {
	$coverage{$type}->{$name}->{lines} = $2;
	$coverage{$type}->{$name}->{linesCoverage} = $1;
    } elsif (/^Branches executed:(.*)%\s*of\s*(\d+)\s*$/) {
	$coverage{$type}->{$name}->{branches} = $2;
	$coverage{$type}->{$name}->{branchesCoverage} = $1;
    } elsif (/^Taken at least once:(.*)%\s*of\s*(\d+)\s*$/) {
	$coverage{$type}->{$name}->{conds} = $2;
	$coverage{$type}->{$name}->{condsCoverage} = $1;
    } elsif (/^Calls executed:(.*)%\s*of\s*(\d+)\s*$/) {
	$coverage{$type}->{$name}->{calls} = $2;
	$coverage{$type}->{$name}->{callsCoverage} = $1;
    } elsif (/^No branches$/) {
	$coverage{$type}->{$name}->{branches} = 0;
	$coverage{$type}->{$name}->{branchesCoverage} = "100.00";
	$coverage{$type}->{$name}->{conds} = 0;
	$coverage{$type}->{$name}->{condsCoverage} = "100.00";
    } elsif (/^No calls$/) {
	$coverage{$type}->{$name}->{calls} = 0;
	$coverage{$type}->{$name}->{callsCoverage} = "100.00";
    } elsif (/^\s*(.*):creating '(.*)'\s*$/) {
	$filemap{$1} = $2;
    } elsif (/^\s*$/) {
	# nada
    } else {
	warn "unexpected input [$_]\n";
    }
}

my %summary;
foreach my $type ("function", "file") {
    $summary{$type} = {};
    foreach my $m ("lines", "branches", "conds", "calls") {
	my $totalGot = 0;
	my $totalMiss = 0;
	my $count = 0;
	foreach my $func (keys %{$coverage{function}}) {
	    my $blacklisted = 0;
	    foreach my $blackName (@functionBlackList) {
		$blacklisted = 1 if $func =~ /^$blackName/;
	    }
	    next if $blacklisted;

	    $count++;
	    my $got = $coverage{function}->{$func}->{$m};
	    $totalGot += $got;
	    my $miss = $got * $coverage{function}->{$func}->{$m ."Coverage"} / 100;
	    $totalMiss += $miss;
	}
	$summary{$type}->{$m} = sprintf("%d", $totalGot);
	if ($totalGot == 0) {
	    $summary{$type}->{$m . "Coverage"} = "100.00";
	} else {
	    $summary{$type}->{$m . "Coverage"} = sprintf("%.2f", $totalMiss / $totalGot * 100);
	}
    }
}



print "<coverage>\n";

foreach my $type ("function", "file") {
    printf "<%ss>\n", $type;
    foreach my $name (sort { $a cmp $b } keys %{$coverage{$type}}) {
	if ($type eq "file") {
	    next if $name =~ m,^/usr,;
	} else {
	    my $blacklisted = 0;
	    foreach my $blackName (@functionBlackList) {
		$blacklisted = 1 if $name =~ /^$blackName/;
	    }
	    next if $blacklisted;
	}

	my $rec = $coverage{$type}->{$name};
	printf "  <entry name=\"%s\" details=\"%s\">\n", $name, ($type eq "file" ? $filemap{$name} : $filemap{$rec->{file}});
	printf "    <lines count=\"%s\" coverage=\"%s\"/>\n", $rec->{lines}, $rec->{linesCoverage};
	if (exists $rec->{branches}) {
	    printf "    <branches count=\"%s\" coverage=\"%s\"/>\n", $rec->{branches}, $rec->{branchesCoverage};
	}
	if (exists $rec->{conds}) {
	    printf "    <conditions count=\"%s\" coverage=\"%s\"/>\n", $rec->{conds}, $rec->{condsCoverage};
	}
	if (exists $rec->{calls}) {
	    printf "    <calls count=\"%s\" coverage=\"%s\"/>\n", $rec->{calls}, $rec->{callsCoverage};
	}
	print  "  </entry>\n";
    }

    printf "  <summary>\n";
    printf "    <lines count=\"%s\" coverage=\"%s\"/>\n", $summary{$type}->{lines}, $summary{$type}->{linesCoverage};
    printf "    <branches count=\"%s\" coverage=\"%s\"/>\n", $summary{$type}->{branches}, $summary{$type}->{branchesCoverage};
    printf "    <conditions count=\"%s\" coverage=\"%s\"/>\n", $summary{$type}->{conds}, $summary{$type}->{condsCoverage};
    printf "    <calls count=\"%s\" coverage=\"%s\"/>\n", $summary{$type}->{calls}, $summary{$type}->{callsCoverage};
    printf  "  </summary>\n";
    printf "</%ss>\n", $type;
}

print "</coverage>\n";
