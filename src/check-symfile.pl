#!/usr/bin/perl

# Copyright (C) 2012-2013 Red Hat, Inc.
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
# License along with this library.  If not, see
# <http://www.gnu.org/licenses/>.

die "syntax: $0 SYMFILE ELFLIB(S)" unless int(@ARGV) >= 2;

my $symfile = shift @ARGV;
my @elflibs = @ARGV;

my %wantsyms;
my %gotsyms;

my $ret = 0;

open SYMFILE, $symfile or die "cannot read $symfile: $!";

while (<SYMFILE>) {
    next if /{/;
    next if /}/;
    next if /global:/;
    next if /local:/;
    next if /^\s*$/;
    next if /^\s*#/;
    next if /\*/;

    die "malformed line $_" unless /^\s*(\S+);$/;

    if (exists $wantsyms{$1}) {
        print STDERR "Symbol $1 is listed twice\n";
        $ret = 1;
    } else {
        $wantsyms{$1} = 1;
    }
}
close SYMFILE;

foreach my $elflib (@elflibs) {
    open NM, "-|", "nm", $elflib or die "cannot run 'nm $elflib': $!";

    while (<NM>) {
        next unless /^\S+\s(?:[TBD])\s(\S+)\s*$/;

        $gotsyms{$1} = 1;
    }

    close NM;
}

foreach my $sym (keys(%wantsyms)) {
    next if exists $gotsyms{$sym};

    print STDERR "Expected symbol $sym is not in ELF library\n";
    $ret = 1;
}

exit($ret);
