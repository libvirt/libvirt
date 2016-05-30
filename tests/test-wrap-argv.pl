#!/usr/bin/perl
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


foreach my $file (@ARGV) {
    &rewrap($file);
}

sub rewrap {
    my $file = shift;

    # Read the original file
    open FILE, "<", $file or die "cannot read $file: $!";
    my @lines;
    while (<FILE>) {
        # If there is a trailing '\' then kill the new line
        if (/\\$/) {
            chomp;
            $_ =~ s/\\$//;
        }

        push @lines, $_;
    }

    # Skip empty files
    return unless @lines;

    # Kill the last new line in the file
    chomp @lines[$#lines];
    close FILE;

    # Reconstruct the master data by joining all lines
    # and then split again based on the real desired
    # newlines
    @lines = split /\n/, join('', @lines);

    # Now each @lines represents a single command, we
    # can process them
    foreach my $line (@lines) {
        &rewrap_line ($line);
    }

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
    print join(" \\\n", @env, $cmd, @args), "\n";
}

sub rewrap_arg {
    my $arg = shift;
    my @ret;

    while (length($arg) > 80) {
        my $split = rindex $arg, ",", 80;
        if ($split == -1) {
            $split = rindex $arg, ":", 80;
        }
        if ($split == -1) {
            $split = rindex $arg, " ", 80;
        }
        if ($split == -1) {
            warn "cannot find nice place to split '$arg' below 80 chars\n";
            $split = 79;
        }
        $split++;

        push @ret, substr $arg, 0, $split;
        $arg = substr $arg, $split;
    }
    push @ret, $arg;
    return join("\\\n", @ret);
}
