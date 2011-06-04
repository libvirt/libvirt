#!/usr/bin/perl

use strict;
use warnings;

use File::Find;

die "syntax: $0 SRCDIR\n" unless int(@ARGV) == 1;

my $srcdir = shift @ARGV;

my $symslibvirt = "$srcdir/libvirt_public.syms";
my $symsqemu = "$srcdir/libvirt_qemu.syms";
my $drivertable = "$srcdir/driver.h";

my %groupheaders = (
    "virDriver" => "Hypervisor APIs",
    "virNetworkDriver" => "Virtual Network APIs",
    "virInterfaceDriver" => "Host Interface APIs",
    "virDeviceMonitor" => "Host Device APIs",
    "virStorageDriver" => "Storage Pool APIs",
    "virSecretDriver" => "Secret APIs",
    "virNWFilterDriver" => "Network Filter APIs",
    );


my @srcs;
find({
    wanted => sub {
	if (m!$srcdir/.*/\w+_(driver|tmpl|monitor|hal|udev)\.c$!) {
	    push @srcs, $_ if $_ !~ /vbox_driver\.c/;
	}
    }, no_chdir => 1}, $srcdir);
my $line;

# Get the list of all public APIs and their corresponding version

my %apis;
open FILE, "<$symslibvirt"
    or die "cannot read $symslibvirt: $!";

my $vers;
my $prevvers;
while (defined($line = <FILE>)) {
    chomp $line;
    next if $line =~ /^\s*#/;
    next if $line =~ /^\s*$/;
    next if $line =~ /^\s*(global|local):/;
    if ($line =~ /^\s*LIBVIRT_(\d+\.\d+\.\d+)\s*{\s*$/) {
	if (defined $vers) {
	    die "malformed syms file";
	}
	$vers = $1;
    } elsif ($line =~ /\s*}\s*;\s*$/) {
	if (defined $prevvers) {
	    die "malformed syms file";
	}
	$prevvers = $vers;
	$vers = undef;
    } elsif ($line =~ /\s*}\s*LIBVIRT_(\d+\.\d+\.\d+)\s*;\s*$/) {
	if ($1 ne $prevvers) {
	    die "malformed syms file $1 != $vers";
	}
	$prevvers = $vers;
	$vers = undef;
    } elsif ($line =~ /\s*(\w+)\s*;\s*$/) {
	$apis{$1} = $vers;
    } else {
	die "unexpected data $line\n";
    }
}

close FILE;


# And the same for the QEMU specific APIs

open FILE, "<$symsqemu"
    or die "cannot read $symsqemu: $!";

$prevvers = undef;
$vers = undef;
while (defined($line = <FILE>)) {
    chomp $line;
    next if $line =~ /^\s*#/;
    next if $line =~ /^\s*$/;
    next if $line =~ /^\s*(global|local):/;
    if ($line =~ /^\s*LIBVIRT_QEMU_(\d+\.\d+\.\d+)\s*{\s*$/) {
	if (defined $vers) {
	    die "malformed syms file";
	}
	$vers = $1;
    } elsif ($line =~ /\s*}\s*;\s*$/) {
	if (defined $prevvers) {
	    die "malformed syms file";
	}
	$prevvers = $vers;
	$vers = undef;
    } elsif ($line =~ /\s*}\s*LIBVIRT_QEMU_(\d+\.\d+\.\d+)\s*;\s*$/) {
	if ($1 ne $prevvers) {
	    die "malformed syms file $1 != $vers";
	}
	$prevvers = $vers;
	$vers = undef;
    } elsif ($line =~ /\s*(\w+)\s*;\s*$/) {
	$apis{$1} = $vers;
    } else {
	die "unexpected data $line\n";
    }
}

close FILE;


# Some special things which aren't public APIs,
# but we want to report
$apis{virConnectDrvSupportsFeature} = "0.3.2";
$apis{virDomainMigratePrepare} = "0.3.2";
$apis{virDomainMigratePerform} = "0.3.2";
$apis{virDomainMigrateFinish} = "0.3.2";
$apis{virDomainMigratePrepare2} = "0.5.0";
$apis{virDomainMigrateFinish2} = "0.5.0";
$apis{virDomainMigratePrepareTunnel} = "0.7.2";

$apis{virDomainMigrateBegin3} = "0.9.2";
$apis{virDomainMigratePrepare3} = "0.9.2";
$apis{virDomainMigratePrepareTunnel3} = "0.9.2";
$apis{virDomainMigratePerform3} = "0.9.2";
$apis{virDomainMigrateFinish3} = "0.9.2";
$apis{virDomainMigrateConfirm3} = "0.9.2";



# Now we want to get the mapping between public APIs
# and driver struct fields. This lets us later match
# update the driver impls with the public APis.

open FILE, "<$drivertable"
    or die "cannot read $drivertable: $!";

# Group name -> hash of APIs { fields -> api name }
my %groups;
my $ingrp;
while (defined($line = <FILE>)) {
    if ($line =~ /struct _(vir\w*(?:Driver|Monitor))/) {
	my $grp = $1;
	if ($grp ne "virStateDriver" &&
	    $grp ne "virStreamDriver") {
	    $ingrp = $grp;
	    $groups{$ingrp} = { apis => {}, drivers => {} };
	}
    } elsif ($ingrp) {
	if ($line =~ /^\s*vir(?:Drv|DevMon)(\w+)\s+(\w+);\s*$/) {
	    my $field = $2;
	    my $name = $1;

	    my $api;
	    if (exists $apis{"vir$name"}) {
		$api = "vir$name";
	    } elsif (exists $apis{"virConnect$name"}) {
		$api = "virConnect$name";
	    } elsif (exists $apis{"virNode$name"}) {
		$api = "virNode$name";
	    } else {
		die "driver $name does not have a public API";
	    }
	    $groups{$ingrp}->{apis}->{$field} = $api;
	} elsif ($line =~ /};/) {
	    $ingrp = undef;
	}
    }
}

close FILE;


# Finally, we read all the primary driver files and extract
# the driver API tables from each one.

foreach my $src (@srcs) {
    open FILE, "<$src" or
	die "cannot read $src: $!";

    $ingrp = undef;
    my $impl;
    while (defined($line = <FILE>)) {
	if (!$ingrp) {
	    foreach my $grp (keys %groups) {
		if ($line =~ /^\s*(?:static\s+)?$grp\s+(\w+)\s*=\s*{/ ||
		    $line =~ /^\s*(?:static\s+)?$grp\s+NAME\(\w+\)\s*=\s*{/) {
		    $ingrp = $grp;
		    $impl = $src;

		    if ($impl =~ m,.*/node_device_(\w+)\.c,) {
			$impl = $1;
		    } else {
			$impl =~ s,.*/(\w+?)_((\w+)_)?(\w+)\.c,$1,;
		    }

		    if ($groups{$ingrp}->{drivers}->{$impl}) {
			die "Group $ingrp already contains $impl";
		    }

		    $groups{$ingrp}->{drivers}->{$impl} = {};
		}
	    }

	} else {
	    if ($line =~ m!\s*\.(\w+)\s*=\s*(\w+)\s*,?\s*(?:/\*\s*(\d+\.\d+\.\d+)\s*\*/\s*)?$!) {
		my $api = $1;
		my $meth = $2;
		my $vers = $3;

		next if $api eq "no" || $api eq "name";

		die "Method $meth in $src is missing version" unless defined $vers;

		die "Driver method for $api is NULL in $src" if $meth eq "NULL";

		if (!exists($groups{$ingrp}->{apis}->{$api})) {
		    die "Found unexpected method $api in $ingrp\n";
		}

		$groups{$ingrp}->{drivers}->{$impl}->{$api} = $vers;
		if ($api eq "domainMigratePrepare" ||
		    $api eq "domainMigratePrepare2" ||
		    $api eq "domainMigratePrepare3") {
		    $groups{$ingrp}->{drivers}->{$impl}->{"domainMigrate"} = $vers
			unless $groups{$ingrp}->{drivers}->{$impl}->{"domainMigrate"};
		}

	    } elsif ($line =~ /}/) {
		$ingrp = undef;
	    }
	}
    }

    close FILE;
}


# The '.open' driver method is used for 3 public APIs, so we
# have a bit of manual fixup todo with the per-driver versioning
# and support matrix

$groups{virDriver}->{apis}->{"openAuth"} = "virConnectOpenAuth";
$groups{virDriver}->{apis}->{"openReadOnly"} = "virConnectOpenReadOnly";
$groups{virDriver}->{apis}->{"domainMigrate"} = "virDomainMigrate";

my $openAuthVers = (0 * 1000 * 1000) + (4 * 1000) + 0;

foreach my $drv (keys %{$groups{"virDriver"}->{drivers}}) {
    my $openVersStr = $groups{"virDriver"}->{drivers}->{$drv}->{"open"};
    my $openVers;
    if ($openVersStr =~ /(\d+)\.(\d+)\.(\d+)/) {
	$openVers = ($1 * 1000 * 1000) + ($2 * 1000) + $3;
    }

    # virConnectOpenReadOnly always matches virConnectOpen version
    $groups{"virDriver"}->{drivers}->{$drv}->{"openReadOnly"} =
	$groups{"virDriver"}->{drivers}->{$drv}->{"open"};

    # virConnectOpenAuth is always 0.4.0 if the driver existed
    # before this time, otherwise it matches the version of
    # the driver's virConnectOpen entry
    if ($openVersStr eq "Y" ||
	$openVers >= $openAuthVers) {
	$groups{"virDriver"}->{drivers}->{$drv}->{"openAuth"} = $openVersStr;
    } else {
	$groups{"virDriver"}->{drivers}->{$drv}->{"openAuth"} = "0.4.0";
    }
}


# Another special case for the virDomainCreateLinux which was replaced
# with virDomainCreateXML
$groups{virDriver}->{apis}->{"domainCreateLinux"} = "virDomainCreateLinux";

my $createAPIVers = (0 * 1000 * 1000) + (0 * 1000) + 3;

foreach my $drv (keys %{$groups{"virDriver"}->{drivers}}) {
    my $createVersStr = $groups{"virDriver"}->{drivers}->{$drv}->{"domainCreateXML"};
    next unless defined $createVersStr;
    my $createVers;
    if ($createVersStr =~ /(\d+)\.(\d+)\.(\d+)/) {
	$createVers = ($1 * 1000 * 1000) + ($2 * 1000) + $3;
    }

    # virCreateLinux is always 0.0.3 if the driver existed
    # before this time, otherwise it matches the version of
    # the driver's virCreateXML entry
    if ($createVersStr eq "Y" ||
	$createVers >= $createAPIVers) {
	$groups{"virDriver"}->{drivers}->{$drv}->{"domainCreateLinux"} = $createVersStr;
    } else {
	$groups{"virDriver"}->{drivers}->{$drv}->{"domainCreateLinux"} = "0.0.3";
    }
}


# Finally we generate the HTML file with the tables

print <<EOF;
<html>
<head>
<title>libvirt API support matrix</title>
</head>
<body>
<h1>libvirt API support matrix</h1>

<ul id="toc"></ul>

<p>
This page documents which <a href="html/">libvirt calls</a> work on
which libvirt drivers / hypervisors, and which version the API appeared
in.
</p>

EOF

foreach my $grp (sort { $a cmp $b } keys %groups) {
    print "<h2><a name=\"$grp\">", $groupheaders{$grp}, "</a></h2>\n";
    print <<EOF;
<table class="top_table">
<thead>
<tr>
<th>API</th>
<th>Version</th>
EOF

    foreach my $drv (sort { $a cmp $b } keys %{$groups{$grp}->{drivers}}) {
	print "  <th>$drv</th>\n";
    }

    print <<EOF;
</tr>
</thead>
<tbody>
EOF

    my $row = 0;
    foreach my $field (sort {
	$groups{$grp}->{apis}->{$a}
	cmp
	$groups{$grp}->{apis}->{$b}
	} keys %{$groups{$grp}->{apis}}) {
	my $api = $groups{$grp}->{apis}->{$field};
	my $vers = $apis{$api};
	print <<EOF;
<tr>
<td><a href=\"html/libvirt-libvirt.html#$api\">$api</a></td>
<td>$vers</td>
EOF

        foreach my $drv (sort {$a cmp $b } keys %{$groups{$grp}->{drivers}}) {
	    if (exists $groups{$grp}->{drivers}->{$drv}->{$field}) {
		print "<td>", $groups{$grp}->{drivers}->{$drv}->{$field}, "</td>\n";
	    } else {
		print "<td></td>\n";
	    }
        }

	print <<EOF;
</tr>
EOF

        $row++;
        if (($row % 15) == 0) {
            print <<EOF;
<tr>
<th>API</th>
<th>Version</th>
EOF

            foreach my $drv (sort { $a cmp $b } keys %{$groups{$grp}->{drivers}}) {
	        print "  <th>$drv</th>\n";
            }

        print <<EOF;
</tr>
EOF
	}

    }

    print <<EOF;
</tbody>
</table>
EOF
}

print <<EOF;
</body>
</html>
EOF
