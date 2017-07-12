#!/usr/bin/perl

my %noninlined;
my %mocked;

# Functions in public header don't get the noinline annotation
# so whitelist them here
$noninlined{"virEventAddTimeout"} = 1;

foreach my $arg (@ARGV) {
    if ($arg =~ /\.h$/) {
        #print "Scan header $arg\n";
        &scan_annotations($arg);
    } elsif ($arg =~ /mock\.c$/) {
        #print "Scan mock $arg\n";
        &scan_overrides($arg);
    }
}

my $warned = 0;
foreach my $func (keys %mocked) {
    next if exists $noninlined{$func};

    $warned++;
    print STDERR "$func is mocked at $mocked{$func} but missing noinline annotation\n";
}

exit $warned ? 1 : 0;


sub scan_annotations {
    my $file = shift;

    open FH, $file or die "cannot read $file: $!";

    my $func;
    while (<FH>) {
        if (/^\s*(\w+)\(/ || /^(?:\w+\*?\s+)+(?:\*\s*)?(\w+)\(/) {
            my $name = $1;
            if ($name !~ /ATTRIBUTE/) {
                $func = $name;
            }
        } elsif (/^\s*$/) {
            $func = undef;
        }
        if (/ATTRIBUTE_NOINLINE/) {
            if (defined $func) {
                $noninlined{$func} = 1;
            }
        }
    }

    close FH
}

sub scan_overrides {
    my $file = shift;

    open FH, $file or die "cannot read $file: $!";

    my $func;
    while (<FH>) {
        if (/^(\w+)\(/ || /^\w+\s*(?:\*\s*)?(\w+)\(/) {
            my $name = $1;
            if ($name =~ /^vir/) {
                $mocked{$name} = "$file:$.";
            }
        }
    }

    close FH
}
