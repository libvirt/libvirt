#!/usr/bin/env perl
#
# Copyright (C) 2015 Red Hat, Inc.
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
#
# This script is intended to be passed a list of .args files, used
# to store command line ARGV for the test suites. It will reformat
# them such that there is at most one '-param value' on each line
# of the file. Parameter values that are longer than 80 chars will
# also be split.
#
# If --in-place is supplied as the first parameter of this script,
# the files will be changed in place.
# If --check is the first parameter, the script will return
# a non-zero value if a file is not wrapped correctly.
# Otherwise the rewrapped files are printed to the standard output.

$in_place = 0;
$check = 0;

if (@ARGV[0] eq "--in-place" or @ARGV[0] eq "-i") {
    $in_place = 1;
    shift @ARGV;
} elsif (@ARGV[0] eq "--check") {
    $check = 1;
    shift @ARGV;
}

$ret = 0;
foreach my $file (@ARGV) {
    if (&rewrap($file) < 0) {
        $ret = 1;
    }
}

exit $ret;

sub rewrap {
    my $file = shift;

    # Read the original file
    open FILE, "<", $file or die "cannot read $file: $!";
    my @orig_lines = <FILE>;
    close FILE;
    my @lines = @orig_lines;
    foreach (@lines) {
        # If there is a trailing '\' then kill the new line
        if (/\\$/) {
            chomp;
            $_ =~ s/\\$//;
        }
    }

    # Skip empty files
    return unless @lines;

    # Kill the last new line in the file
    chomp @lines[$#lines];

    # Reconstruct the master data by joining all lines
    # and then split again based on the real desired
    # newlines
    @lines = split /\n/, join('', @lines);

    # Now each @lines represents a single command, we
    # can process them
    @lines = map { &rewrap_line($_) } @lines;

    if ($in_place) {
        open FILE, ">", $file or die "cannot write $file: $!";
        foreach my $line (@lines) {
            print FILE $line;
        }
        close FILE;
    } elsif ($check) {
        my $nl = join('', @lines);
        my $ol = join('', @orig_lines);
        unless ($nl eq $ol) {
            open DIFF, "| diff -u $file -" or die "cannot run diff: $!";
            print DIFF $nl;
            close DIFF;

            print STDERR "Incorrect line wrapping in $file\n";
            print STDERR "Use test-wrap-argv.pl to wrap test data files\n";
            return -1;
        }
    } else {
        foreach my $line (@lines) {
            print $line;
        }
    }
    return 0;
}

sub rewrap_line {
    my $line = shift;
    my @bits = split / /, join('', $line);

    # @bits contains env vars, then the command line
    # and then the arguments
    my @env;
    my $cmd;
    my @args;

    if ($bits[0] !~ /=/) {
        $cmd = shift @bits;
    }

    foreach my $bit (@bits) {
        # If no command is defined yet, we must still
        # have env vars
        if (!defined $cmd) {
            # Look for leading / to indicate command name
            if ($bit =~ m,^/,) {
                $cmd = $bit;
            } else {
                push @env, $bit;
            }
        } else {
            # If there's a leading '-' then this is a new
            # parameter, otherwise its a value for the prev
            # parameter.
            if ($bit =~ m,^-,) {
                push @args, $bit;
            } else {
                $args[$#args] .= " " . $bit;
            }
        }
    }

    # We might have to split line argument values...
    @args = map { &rewrap_arg($_) } @args;
    # Print env + command first
    return join(" \\\n", @env, $cmd, @args), "\n";
}

sub rewrap_arg {
    my $arg = shift;
    my @ret;
    my $max_len = 78;

    while (length($arg) > $max_len) {
        my $split = rindex $arg, ",", $max_len;
        if ($split == -1) {
            $split = rindex $arg, ":", $max_len;
        }
        if ($split == -1) {
            $split = rindex $arg, " ", $max_len;
        }
        if ($split == -1) {
            warn "cannot find nice place to split '$arg' below 80 chars\n";
            $split = $max_len - 1;
        }
        $split++;

        push @ret, substr $arg, 0, $split;
        $arg = substr $arg, $split;
    }
    push @ret, $arg;
    return join("\\\n", @ret);
}
