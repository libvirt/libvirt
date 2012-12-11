#!/usr/bin/perl

use strict;
use warnings;

die "syntax: $0 SYMFILE..." unless int(@ARGV) >= 1;

my $ret = 0;
foreach my $symfile (@ARGV) {
    open SYMFILE, $symfile or die "cannot read $symfile: $!";

    my $line;
    my @group;

    while (<SYMFILE>) {
        chomp;
        next if /^#/;

        if (/^\s*$/) {
            if (@group) {
                &check_sorting(\@group, $symfile, $line);
            }
            @group = ();
            $line = $.;
        } else {
            $_ =~ s/;//;
            push @group, $_;
        }
    }

    close SYMFILE;
    if (@group) {
        &check_sorting(\@group, $symfile, $line);
    }
}

sub check_sorting {
    my $group = shift;
    my $symfile = shift;
    my $line = shift;

    my @group = @{$group};
    my @sorted = sort { lc $a cmp lc $b } @group;
    my $sorted = 1;
    my $first;
    my $last;
    for (my $i = 0 ; $i <= $#sorted ; $i++) {
        if ($sorted[$i] ne $group[$i]) {
            $first = $i unless defined $first;
            $last = $i;
            $sorted = 0;
        }
    }
    if (!$sorted) {
        @group = splice @group, $first, ($last-$first+1);
        @sorted = splice @sorted, $first, ($last-$first+1);
        print "Symbol block at $symfile:$line symbols not sorted\n";
        print map { "  " . $_ . "\n" } @group;
        print "Correct ordering\n";
        print map { "  " . $_ . "\n" } @sorted;
        print "\n";
        $ret = 1;
    }
}

exit $ret;
