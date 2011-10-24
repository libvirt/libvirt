#!/usr/bin/perl
#
# Copyright (C) 2011 Red Hat, Inc.
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
# Generate a set of systemtap probe definitions corresponding to
# DTrace probe markers in libvirt.so
#
#  perl dtrace2systemtap.pl probes.d > libvirt_probes.stp
#

use strict;
use warnings;

my $file;
my @files;
my %files;

my $bindir = shift @ARGV;
my $sbindir = shift @ARGV;
my $libdir = shift @ARGV;

my $probe;
my $args;

# Read the DTraceprobes definition
while (<>) {
    next if m,^\s*$,;

    next if /^\s*provider\s+\w+\s*{\s*$/;
    next if /^\s*};\s*$/;

    if (m,^\s*\#,) {
	if (m,^\s*\#\s*file:\s*(\S+)\s*$,) {
	    $file = $1;
	    push @files, $file;
	    $files{$file} = { prefix => undef, probes => [] };
	} elsif (m,^\s*\#\s*prefix:\s*(\S+)\s*$,) {
	    $files{$file}->{prefix} = $1;
	} elsif (m,^\s*\#\s*binary:\s*(\S+)\s*$,) {
	    $files{$file}->{binary} = $1;
	} else {
	    # ignore unknown comments
	}
    } else {
	if (m,\s*probe\s+([a-zA-Z0-9_]+)\((.*?)(\);)?$,) {
	    $probe = $1;
	    $args = $2;
	    if ($3) {
		push @{$files{$file}->{probes}}, [$probe, $args];
		$probe = $args = undef;
	    }
	} elsif ($probe) {
	    if (m,^(.*?)(\);)?$,) {
		$args .= $1;
		if ($2) {
		    push @{$files{$file}->{probes}}, [$probe, $args];
		    $probe = $args = undef;
		}
	    } else {
		die "unexpected data $_ on line $.";
	    }
	} else {
	    die "unexpected data $_ on line $.";
	}
    }
}

# Write out the SystemTap probes
foreach my $file (@files) {
    my $prefix = $files{$file}->{prefix};
    my @probes = @{$files{$file}->{probes}};

    print "# $file\n\n";
    foreach my $probe (@probes) {
	my $name = $probe->[0];
	my $args = $probe->[1];

	my $pname = $name;
	$pname =~ s/${prefix}_/libvirt.$prefix./;

	my $binary = "$libdir/libvirt.so";
	if (exists $files{$file}->{binary}) {
	    $binary = $sbindir . "/" . $files{$file}->{binary};
	}

	print "probe $pname = process(\"$binary\").mark(\"$name\") {\n";

	my @args = split /,/, $args;
	for (my $i = 0 ; $i <= $#args ; $i++) {
	    my $arg = $args[$i];
	    my $isstr = $arg =~ /char\s+\*/;
	    $arg =~ s/^.*\s\*?(\S+)$/$1/;

	    if ($isstr) {
		print "  $arg = user_string(\$arg", $i + 1, ");\n";
	    } else {
		print "  $arg = \$arg", $i + 1, ";\n";
	    }
	}
	print "}\n\n";
    }
    print "\n";
}
