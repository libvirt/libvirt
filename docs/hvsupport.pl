#!/usr/bin/env perl

use strict;
use warnings;

use File::Find;

die "syntax: $0 SRCDIR\n" unless int(@ARGV) == 1;

my $srcdir = shift @ARGV;

my $symslibvirt = "$srcdir/libvirt_public.syms";
my $symsqemu = "$srcdir/libvirt_qemu.syms";
my $symslxc = "$srcdir/libvirt_lxc.syms";
my @drivertable = (
    "$srcdir/driver-hypervisor.h",
    "$srcdir/driver-interface.h",
    "$srcdir/driver-network.h",
    "$srcdir/driver-nodedev.h",
    "$srcdir/driver-nwfilter.h",
    "$srcdir/driver-secret.h",
    "$srcdir/driver-state.h",
    "$srcdir/driver-storage.h",
    "$srcdir/driver-stream.h",
    );

my %groupheaders = (
    "virHypervisorDriver" => "Hypervisor APIs",
    "virNetworkDriver" => "Virtual Network APIs",
    "virInterfaceDriver" => "Host Interface APIs",
    "virNodeDeviceDriver" => "Host Device APIs",
    "virStorageDriver" => "Storage Pool APIs",
    "virSecretDriver" => "Secret APIs",
    "virNWFilterDriver" => "Network Filter APIs",
    );


my @srcs;
find({
    wanted => sub {
        if (m!$srcdir/.*/\w+_(driver|common|tmpl|monitor|hal|udev)\.c$!) {
            push @srcs, $_ if $_ !~ /vbox_driver\.c/;
        }
    }, no_chdir => 1}, $srcdir);

# Map API functions to the header and documentation files they're in
# so that we can generate proper hyperlinks to their documentation.
#
# The function names are grep'd from the XML output of apibuild.py.
sub getAPIFilenames {
    my $filename = shift;

    my %files;
    my $line;

    open FILE, "<", $filename or die "cannot read $filename: $!";

    while (defined($line = <FILE>)) {
        if ($line =~ /function name='([^']+)' file='([^']+)'/) {
            $files{$1} = $2;
        }
    }

    close FILE;

    if (keys %files == 0) {
        die "No functions found in $filename. Has the apibuild.py output changed?";
    }
    return \%files;
}

sub parseSymsFile {
    my $apisref = shift;
    my $prefix = shift;
    my $filename = shift;
    my $xmlfilename = shift;

    my $line;
    my $vers;
    my $prevvers;

    my $filenames = getAPIFilenames($xmlfilename);

    open FILE, "<$filename"
        or die "cannot read $filename: $!";

    while (defined($line = <FILE>)) {
        chomp $line;
        next if $line =~ /^\s*#/;
        next if $line =~ /^\s*$/;
        next if $line =~ /^\s*(global|local):/;
        if ($line =~ /^\s*${prefix}_(\d+\.\d+\.\d+)\s*{\s*$/) {
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
        } elsif ($line =~ /\s*}\s*${prefix}_(\d+\.\d+\.\d+)\s*;\s*$/) {
            if ($1 ne $prevvers) {
                die "malformed syms file $1 != $vers";
            }
            $prevvers = $vers;
            $vers = undef;
        } elsif ($line =~ /\s*(\w+)\s*;\s*$/) {
            $$apisref{$1} = {};
            $$apisref{$1}->{vers} = $vers;
            $$apisref{$1}->{file} = $$filenames{$1};
        } else {
            die "unexpected data $line\n";
        }
    }

    close FILE;
}

my %apis;
# Get the list of all public APIs and their corresponding version
parseSymsFile(\%apis, "LIBVIRT", $symslibvirt, "$srcdir/../docs/libvirt-api.xml");

# And the same for the QEMU specific APIs
parseSymsFile(\%apis, "LIBVIRT_QEMU", $symsqemu, "$srcdir/../docs/libvirt-qemu-api.xml");

# And the same for the LXC specific APIs
parseSymsFile(\%apis, "LIBVIRT_LXC", $symslxc, "$srcdir/../docs/libvirt-lxc-api.xml");


# Some special things which aren't public APIs,
# but we want to report
$apis{virConnectSupportsFeature}->{vers} = "0.3.2";
$apis{virDomainMigratePrepare}->{vers} = "0.3.2";
$apis{virDomainMigratePerform}->{vers} = "0.3.2";
$apis{virDomainMigrateFinish}->{vers} = "0.3.2";
$apis{virDomainMigratePrepare2}->{vers} = "0.5.0";
$apis{virDomainMigrateFinish2}->{vers} = "0.5.0";
$apis{virDomainMigratePrepareTunnel}->{vers} = "0.7.2";

$apis{virDomainMigrateBegin3}->{vers} = "0.9.2";
$apis{virDomainMigratePrepare3}->{vers} = "0.9.2";
$apis{virDomainMigratePrepareTunnel3}->{vers} = "0.9.2";
$apis{virDomainMigratePerform3}->{vers} = "0.9.2";
$apis{virDomainMigrateFinish3}->{vers} = "0.9.2";
$apis{virDomainMigrateConfirm3}->{vers} = "0.9.2";

$apis{virDomainMigrateBegin3Params}->{vers} = "1.1.0";
$apis{virDomainMigratePrepare3Params}->{vers} = "1.1.0";
$apis{virDomainMigratePrepareTunnel3Params}->{vers} = "1.1.0";
$apis{virDomainMigratePerform3Params}->{vers} = "1.1.0";
$apis{virDomainMigrateFinish3Params}->{vers} = "1.1.0";
$apis{virDomainMigrateConfirm3Params}->{vers} = "1.1.0";



# Now we want to get the mapping between public APIs
# and driver struct fields. This lets us later match
# update the driver impls with the public APis.

my $line;

# Group name -> hash of APIs { fields -> api name }
my %groups;
my $ingrp;
foreach my $drivertable (@drivertable) {
    open FILE, "<$drivertable"
        or die "cannot read $drivertable: $!";

    while (defined($line = <FILE>)) {
        if ($line =~ /struct _(vir\w*Driver)/) {
            my $grp = $1;
            if ($grp ne "virStateDriver" &&
                $grp ne "virStreamDriver") {
                $ingrp = $grp;
                $groups{$ingrp} = { apis => {}, drivers => {} };
            }
        } elsif ($ingrp) {
            if ($line =~ /^\s*vir(?:Drv)(\w+)\s+(\w+);\s*$/) {
                my $field = $2;
                my $name = $1;

                my $api;
                if (exists $apis{"vir$name"}) {
                    $api = "vir$name";
                } elsif ($name =~ /\w+(Open|Close|URIProbe)/) {
                    next;
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
}


# Finally, we read all the primary driver files and extract
# the driver API tables from each one.

foreach my $src (@srcs) {
    open FILE, "<$src" or
        die "cannot read $src: $!";

    my $groups_regex = join("|", keys %groups);
    $ingrp = undef;
    my $impl;
    while (defined($line = <FILE>)) {
        if (!$ingrp) {
            # skip non-matching lines early to save time
            next if not $line =~ /$groups_regex/;

            if ($line =~ /^\s*(?:static\s+)?($groups_regex)\s+(\w+)\s*=\s*{/ ||
                $line =~ /^\s*(?:static\s+)?($groups_regex)\s+NAME\(\w+\)\s*=\s*{/) {
                $ingrp = $1;
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

        } else {
            if ($line =~ m!\s*\.(\w+)\s*=\s*(\w+)\s*,?\s*(?:/\*\s*(\d+\.\d+\.\d+)\s*\*/\s*)?$!) {
                my $api = $1;
                my $meth = $2;
                my $vers = $3;

                next if $api eq "no" || $api eq "name";

                die "Method $meth in $src is missing version" unless defined $vers || $api eq "connectURIProbe";

                die "Driver method for $api is NULL in $src" if $meth eq "NULL";

                if (!exists($groups{$ingrp}->{apis}->{$api})) {
                    next if $api =~ /\w(Open|Close|URIProbe)/;

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

$groups{virHypervisorDriver}->{apis}->{"openAuth"} = "virConnectOpenAuth";
$groups{virHypervisorDriver}->{apis}->{"openReadOnly"} = "virConnectOpenReadOnly";
$groups{virHypervisorDriver}->{apis}->{"domainMigrate"} = "virDomainMigrate";

my $openAuthVers = (0 * 1000 * 1000) + (4 * 1000) + 0;

foreach my $drv (keys %{$groups{"virHypervisorDriver"}->{drivers}}) {
    my $openVersStr = $groups{"virHypervisorDriver"}->{drivers}->{$drv}->{"connectOpen"};
    my $openVers;
    if ($openVersStr =~ /(\d+)\.(\d+)\.(\d+)/) {
        $openVers = ($1 * 1000 * 1000) + ($2 * 1000) + $3;
    }

    # virConnectOpenReadOnly always matches virConnectOpen version
    $groups{"virHypervisorDriver"}->{drivers}->{$drv}->{"connectOpenReadOnly"} =
        $groups{"virHypervisorDriver"}->{drivers}->{$drv}->{"connectOpen"};

    # virConnectOpenAuth is always 0.4.0 if the driver existed
    # before this time, otherwise it matches the version of
    # the driver's virConnectOpen entry
    if ($openVersStr eq "Y" ||
        $openVers >= $openAuthVers) {
        $groups{"virHypervisorDriver"}->{drivers}->{$drv}->{"connectOpenAuth"} = $openVersStr;
    } else {
        $groups{"virHypervisorDriver"}->{drivers}->{$drv}->{"connectOpenAuth"} = "0.4.0";
    }
}


# Another special case for the virDomainCreateLinux which was replaced
# with virDomainCreateXML
$groups{virHypervisorDriver}->{apis}->{"domainCreateLinux"} = "virDomainCreateLinux";

my $createAPIVers = (0 * 1000 * 1000) + (0 * 1000) + 3;

foreach my $drv (keys %{$groups{"virHypervisorDriver"}->{drivers}}) {
    my $createVersStr = $groups{"virHypervisorDriver"}->{drivers}->{$drv}->{"domainCreateXML"};
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
        $groups{"virHypervisorDriver"}->{drivers}->{$drv}->{"domainCreateLinux"} = $createVersStr;
    } else {
        $groups{"virHypervisorDriver"}->{drivers}->{$drv}->{"domainCreateLinux"} = "0.0.3";
    }
}


# Finally we generate the HTML file with the tables

print <<EOF;
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<body class="hvsupport">
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
        my $vers = $apis{$api}->{vers};
        my $htmlgrp = $apis{$api}->{file};
        print <<EOF;
<tr>
<td>
EOF

        if (defined $htmlgrp) {
            print <<EOF;
<a href=\"html/libvirt-$htmlgrp.html#$api\">$api</a>
EOF

        } else {
            print $api;
        }
        print <<EOF;
</td>
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
