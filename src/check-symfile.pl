#!/usr/bin/perl

die "syntax: $0 SYMFILE ELFLIB(S)" unless int(@ARGV) >= 2;

my $symfile = shift @ARGV;
my @elflibs = @ARGV;

my @wantsyms;
my %gotsyms;

# Skip on non-linux
if ($^O ne "linux") {
    return 77; # Automake's skip code
}

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

    push @wantsyms, $1;
}
close SYMFILE;

foreach my $elflib (@elflibs) {
    open NM, "-|", "nm", $elflib or die "cannot run 'nm $elflib': $!";

    while (<NM>) {
        next unless /^\S+\s(?:T|D)\s(\S+)\s*$/;

        $gotsyms{$1} = 1;
    }

    close NM;
}

my $ret = 0;

foreach my $sym (@wantsyms) {
    next if exists $gotsyms{$sym};

    print STDERR "Expected symbol $sym is not in ELF library\n";
    $ret = 1;
}

exit($ret);
