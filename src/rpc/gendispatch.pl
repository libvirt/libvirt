#!/usr/bin/perl -w
#
# Copyright (C) 2010-2015 Red Hat, Inc.
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
# This script parses remote_protocol.x or qemu_protocol.x and produces lots of
# boilerplate code for both ends of the remote connection.
#
# The first non-option argument specifies the prefix to be searched for, and
# output to, the boilerplate code.  The second non-option argument is the
# file you want to operate on.  For instance, to generate the dispatch table
# for both remote_protocol.x and qemu_protocol.x, you would run the
# following:
#
# gendispatch.pl -t remote ../src/remote/remote_protocol.x
# gendispatch.pl -t qemu ../src/remote/qemu_protocol.x
#
# By Richard Jones <rjones@redhat.com>
# Extended by Matthias Bolte <matthias.bolte@googlemail.com>

use strict;

use Getopt::Long;

my $mode = "debug";
my $res = GetOptions("mode=s" => \$mode);

die "cannot parse command line options" unless $res;

die "unknown mode '$mode', expecting 'client', 'server', " .
    "'aclheader', 'aclbody', 'aclsym', 'aclapi' or 'debug'"
    unless $mode =~ /^(client|server|aclheader|aclbody|aclsym|aclapi|debug)$/;

my $structprefix = shift or die "missing struct prefix argument";
my $procprefix = shift or die "missing procedure prefix argument";
my $protocol = shift or die "missing protocol argument";
my @autogen;

my $connect_ptr = $structprefix eq "admin" ? "virAdmConnectPtr" : "virConnectPtr";
my $prefix = ($structprefix eq "admin") ? "admin" : "vir";

sub fixup_name {
    my $name = shift;

    $name =~ s/Nwfilter/NWFilter/;
    $name =~ s/Xml$/XML/;
    $name =~ s/Uri$/URI/;
    $name =~ s/Uuid$/UUID/;
    $name =~ s/Id$/ID/;
    $name =~ s/Mac$/MAC/;
    $name =~ s/Cpu$/CPU/;
    $name =~ s/Os$/OS/;
    $name =~ s/Nmi$/NMI/;
    $name =~ s/Pm/PM/;
    $name =~ s/Fstrim$/FSTrim/;
    $name =~ s/Fsfreeze$/FSFreeze/;
    $name =~ s/Fsthaw$/FSThaw/;
    $name =~ s/Fsinfo$/FSInfo/;
    $name =~ s/Iothread$/IOThread/;
    $name =~ s/Scsi/SCSI/;
    $name =~ s/Wwn$/WWN/;
    $name =~ s/Dhcp$/DHCP/;

    return $name;
}

# Convert name_of_call to NameOfCall.
sub name_to_ProcName {
    my $name = shift;
    my $forcefix = $structprefix eq "admin";

    my @elems;

    if ($forcefix || $name =~ /_/ ||
        (lc $name) eq "open" || (lc $name) eq "close") {
        @elems = split /_/, $name;
        @elems = map lc, @elems;
        @elems = map ucfirst, @elems;
    } else {
        @elems = $name;
    }
    @elems = map { fixup_name($_) } @elems;
    my $procname = join "", @elems;

    return $procname;
}

sub name_to_TypeName {
    my $name = shift;

    my @elems = split /_/, $name;
    @elems = map lc, @elems;
    @elems = map ucfirst, @elems;
    @elems = map { fixup_name($_) } @elems;
    my $typename = join "", @elems;
    return $typename;
}

sub push_privconn {
    my $args = shift;

    if (!@$args) {
        if ($structprefix eq "admin") {
            push(@$args, "priv->dmn");
        } else {
            push(@$args, "priv->conn");
        }
    }
}


# Read the input file (usually remote_protocol.x) and form an
# opinion about the name, args and return type of each RPC.
my ($name, $ProcName, $id, $flags, %calls, @calls, %opts);

my $collect_args_members = 0;
my $collect_ret_members = 0;
my $collect_opts = 0;
my $last_name;

open PROTOCOL, "<$protocol" or die "cannot open $protocol: $!";

while (<PROTOCOL>) {
    if ($collect_args_members) {
        if (/^};/) {
            $collect_args_members = 0;
        } elsif ($_ =~ m/^\s*(.*\S)\s*$/) {
            push(@{$calls{$name}->{args_members}}, $1);
        }
    } elsif ($collect_ret_members) {
        if (/^};/) {
            $collect_ret_members = 0;
        } elsif ($_ =~ m/^\s*(.*\S)\s*$/) {
            push(@{$calls{$name}->{ret_members}}, $1);
        }
    } elsif ($collect_opts) {
        if (m,^\s*\*\s*\@(\w+)\s*:\s*((?:\w|:|\!|\|)+)\s*$,) {
            if ($1 eq "acl" ||
                $1 eq "aclfilter") {
                $opts{$1} = [] unless exists $opts{$1};
                push @{$opts{$1}}, $2;
            } else {
                $opts{$1} = $2;
            }
        } elsif (m,^\s*\*/\s*$,) {
            $collect_opts = 0;
        } elsif (m,^\s*\*\s*$,) {
            # pass
        } else {
            die "cannot parse $_";
        }
    } elsif (m,/\*\*,) {
        %opts = ();
        $collect_opts = 1;
    } elsif (/^struct (${structprefix}_(.*)_args)/ ||
             /^struct (${structprefix}(.*)Args)/) {
        my $structname = $1;
        $name = $2;
        $ProcName = name_to_ProcName ($name);
        $name = lc $name;
        $name =~ s/_//g;
        die "duplicate definition of $_"
            if exists $calls{$name};

        $calls{$name} = {
            name => $name,
            ProcName => $ProcName,
            args => $structname,
            args_members => [],
            ret => "void"
        };

        $collect_args_members = 1;
        $collect_ret_members = 0;
        $last_name = $name;
    } elsif (/^struct (${structprefix}_(.*)_ret)\s+{(.*)$/ ||
             /^struct (${structprefix}(.*)Ret)\s+{(.*)$/) {
        my $structname = $1;
        $name = $2;
        $flags = $3;
        $ProcName = name_to_ProcName ($name);
        $name = lc $name;
        $name =~ s/_//g;

        if (exists $calls{$name}) {
            $calls{$name}->{ret} = $structname;
        } else {
            $calls{$name} = {
                name => $name,
                ProcName => $ProcName,
                args => "void",
                ret => $structname,
                ret_members => []
            }
        }

        if ($flags ne "") {
            if (!($flags =~ m/^\s*\/\*\s*insert@(\d+)\s*\*\/\s*$/)) {
                die "invalid generator flags for $calls{$name}->{ret}";
            }

            $calls{$name}->{ret_offset} = int($1);
        }

        $collect_args_members = 0;
        $collect_ret_members = 1;
        $last_name = $name;
    } elsif (/^struct (${structprefix}_(.*)_msg)/ ||
             /^struct (${structprefix}(.*)Msg)/) {
        my $structname = $1;
        $name = $2;
        $ProcName = name_to_ProcName ($name);
        $name = lc $name;
        $name =~ s/_//g;
        $calls{$name} = {
            name => $name,
            ProcName => $ProcName,
            msg => $structname,
        };

        $collect_args_members = 0;
        $collect_ret_members = 0;
    } elsif (/^\s*(${procprefix}_PROC_(.*?))\s*=\s*(\d+)\s*,?\s*$/) {
        my $constname = $1;
        $name = $2;
        $id = $3;
        $ProcName = name_to_ProcName ($name);
        $name = lc $name;
        $name =~ s/_//g;

        if (!exists $calls{$name}) {
            # that the argument and return value cases have not yet added
            # this procedure to the calls hash means that it has no arguments
            # and no return value. add it to the calls hash now because all
            # procedures have to be listed in the calls hash
            $calls{$name} = {
                name => $name,
                ProcName => $ProcName,
                args => "void",
                ret => "void"
            }
        }
        $calls{$name}->{constname} = $constname;

        if (!exists $opts{generate}) {
            die "'\@generate' annotation missing for $constname";
        }

        if ($opts{generate} !~ /^(both|server|client|none)$/) {
            die "'\@generate' annotation value '$opts{generate}' invalid";
        }

        if ($opts{generate} eq "both") {
            push(@autogen, $ProcName);
        } elsif ($mode eq "server" && ($opts{generate} eq "server")) {
            push(@autogen, $ProcName);
        } elsif ($mode eq "client" && ($opts{generate} eq "client")) {
            push(@autogen, $ProcName);
        }

        if (exists $opts{readstream}) {
            $calls{$name}->{streamflag} = "read";
            $calls{$name}->{streamoffset} = int($opts{readstream});
        } elsif (exists $opts{writestream}) {
            $calls{$name}->{streamflag} = "write";
            $calls{$name}->{streamoffset} = int($opts{writestream});
        } else {
            $calls{$name}->{streamflag} = "none";
        }

        $calls{$name}->{acl} = $opts{acl};
        $calls{$name}->{aclfilter} = $opts{aclfilter};

        # for now, we distinguish only two levels of priority:
        # low (0) and high (1)
        if (exists $opts{priority}) {
            if ($opts{priority} eq "high") {
                $calls{$name}->{priority} = 1;
            } elsif ($opts{priority} eq "low") {
                $calls{$name}->{priority} = 0;
            } else {
                die "\@priority annotation value '$opts{priority}' invalid for $constname"
            }
        } else {
            $calls{$name}->{priority} = 0;
        }

        $calls[$id] = $calls{$name};

        $collect_args_members = 0;
        $collect_ret_members = 0;
    } else {
        $collect_args_members = 0;
        $collect_ret_members = 0;
    }
}

close(PROTOCOL);

# this hash contains the procedures that are allowed to map [unsigned] hyper
# to [unsigned] long for legacy reasons in their signature and return type.
# this list is fixed. new procedures and public APIs have to map [unsigned]
# hyper to [unsigned] long long
my $long_legacy = {
    DomainGetInfo               => { ret => { maxMem => 1, memory => 1 } },
    DomainMigrate               => { arg => { flags => 1, resource => 1 } },
    DomainMigrate2              => { arg => { flags => 1, resource => 1 } },
    DomainMigrateBegin3         => { arg => { flags => 1, resource => 1 } },
    DomainMigrateConfirm3       => { arg => { flags => 1, resource => 1 } },
    DomainMigrateDirect         => { arg => { flags => 1, resource => 1 } },
    DomainMigrateFinish         => { arg => { flags => 1 } },
    DomainMigrateFinish2        => { arg => { flags => 1 } },
    DomainMigrateFinish3        => { arg => { flags => 1 } },
    DomainMigratePeer2Peer      => { arg => { flags => 1, resource => 1 } },
    DomainMigratePerform        => { arg => { flags => 1, resource => 1 } },
    DomainMigratePerform3       => { arg => { flags => 1, resource => 1 } },
    DomainMigratePrepare        => { arg => { flags => 1, resource => 1 } },
    DomainMigratePrepare2       => { arg => { flags => 1, resource => 1 } },
    DomainMigratePrepare3       => { arg => { flags => 1, resource => 1 } },
    DomainMigratePrepareTunnel  => { arg => { flags => 1, resource => 1 } },
    DomainMigratePrepareTunnel3 => { arg => { flags => 1, resource => 1 } },
    DomainMigrateToURI          => { arg => { flags => 1, resource => 1 } },
    DomainMigrateToURI2         => { arg => { flags => 1, resource => 1 } },
    DomainMigrateVersion1       => { arg => { flags => 1, resource => 1 } },
    DomainMigrateVersion2       => { arg => { flags => 1, resource => 1 } },
    DomainMigrateVersion3       => { arg => { flags => 1, resource => 1 } },
    DomainMigrateSetMaxSpeed    => { arg => { bandwidth => 1 } },
    DomainSetMaxMemory          => { arg => { memory => 1 } },
    DomainSetMemory             => { arg => { memory => 1 } },
    DomainSetMemoryFlags        => { arg => { memory => 1 } },
    ConnectGetLibVersion        => { ret => { lib_ver => 1 } },
    ConnectGetVersion           => { ret => { hv_ver => 1 } },
    NodeGetInfo                 => { ret => { memory => 1 } },
    DomainBlockCommit           => { arg => { bandwidth => 1 } },
    DomainBlockPull             => { arg => { bandwidth => 1 } },
    DomainBlockRebase           => { arg => { bandwidth => 1 } },
    DomainBlockJobSetSpeed      => { arg => { bandwidth => 1 } },
    DomainMigrateGetMaxSpeed    => { ret => { bandwidth => 1 } },
};

sub hyper_to_long
{
    my $proc_name = shift;
    my $ret_or_arg = shift;
    my $member = shift;

    if ($long_legacy->{$proc_name} and
        $long_legacy->{$proc_name}->{$ret_or_arg} and
        $long_legacy->{$proc_name}->{$ret_or_arg}->{$member}) {
        return 1;
    } else {
        return 0
    }
}

#----------------------------------------------------------------------
# Output

if ($mode eq "aclsym") {
    print <<__EOF__;
# Automatically generated from $protocol by gendispatch.pl.
# Do not edit this file.  Any changes you make will be lost.
__EOF__
} elsif ($mode eq "aclapi") {
    print <<__EOF__;
<!--
  -  Automatically generated from $protocol by gendispatch.pl.
  -  Do not edit this file.  Any changes you make will be lost.
  -->
__EOF__
} else {
    print <<__EOF__;
/* Automatically generated from $protocol by gendispatch.pl.
 * Do not edit this file.  Any changes you make will be lost.
 */
__EOF__
}

# Debugging.
if ($mode eq "debug") {
    my @keys = sort (keys %calls);
    foreach (@keys) {
        print "$_:\n";
        print "        name $calls{$_}->{name} ($calls{$_}->{ProcName})\n";
        print "        $calls{$_}->{args} -> $calls{$_}->{ret}\n";
        print "        priority -> $calls{$_}->{priority}\n";
    }
}

# Bodies for dispatch functions ("remote_dispatch.h").
elsif ($mode eq "server") {
    my %generate = map { $_ => 1 } @autogen;
    my @keys = sort (keys %calls);

    foreach (@keys) {
        my $call = $calls{$_};

        # skip things which are REMOTE_MESSAGE
        next if $call->{msg};

        my $name = $structprefix . "Dispatch" . $call->{ProcName};
        my $argtype = $call->{args};
        my $rettype = $call->{ret};

        my $argann = $argtype ne "void" ? "" : " ATTRIBUTE_UNUSED";
        my $retann = $rettype ne "void" ? "" : " ATTRIBUTE_UNUSED";

        # First we print out a function declaration for the
        # real dispatcher body
        print "static int ${name}(\n";
        print "    virNetServerPtr server,\n";
        print "    virNetServerClientPtr client,\n";
        print "    virNetMessagePtr msg,\n";
        print "    virNetMessageErrorPtr rerr";
        if ($argtype ne "void") {
            print ",\n    $argtype *args";
        }
        if ($rettype ne "void") {
            print ",\n    $rettype *ret";
        }
        print ");\n";


        # Next we print out a generic wrapper method which has
        # fixed function signature, for use in the dispatcher
        # table. This simply callers the real dispatcher method
        print "static int ${name}Helper(\n";
        print "    virNetServerPtr server,\n";
        print "    virNetServerClientPtr client,\n";
        print "    virNetMessagePtr msg,\n";
        print "    virNetMessageErrorPtr rerr,\n";
        print "    void *args$argann,\n";
        print "    void *ret$retann)\n";
        print "{\n";
        print "  int rv;\n";
        print "  virThreadJobSet(\"$name\");\n";
        print "  VIR_DEBUG(\"server=%p client=%p msg=%p rerr=%p args=%p ret=%p\",\n";
        print "            server, client, msg, rerr, args, ret);\n";
        print "  rv = $name(server, client, msg, rerr";
        if ($argtype ne "void") {
            print ", args";
        }
        if ($rettype ne "void") {
            print ", ret";
        }
        print ");\n";
        print "  virThreadJobClear(rv);\n";
        print "  return rv;\n";
        print "}\n";

        # Finally we print out the dispatcher method body impl
        # (if possible)
        if (!exists($generate{$call->{ProcName}})) {
            print "/* ${structprefix}Dispatch$call->{ProcName} body has " .
                  "to be implemented manually */\n\n\n\n";
            next;
        }

        my $has_node_device = 0;
        my @vars_list = ();
        my @optionals_list = ();
        my @getters_list = ();
        my @args_list = ();
        my @prepare_ret_list = ();
        my @ret_list = ();
        my @free_list = ();
        my @free_list_on_error = ("virNetMessageSaveError(rerr);");

        # handle arguments to the function
        if ($argtype ne "void") {
            # node device is special, as it's identified by name
            if ($argtype =~ m/^remote_node_device_/ and
                !($argtype =~ m/^remote_node_device_lookup_by_name_/) and
                !($argtype =~ m/^remote_node_device_create_xml_/) and
                !($argtype =~ m/^remote_node_device_lookup_scsi_host_by_wwn_/)) {
                $has_node_device = 1;
                push(@vars_list, "virNodeDevicePtr dev = NULL");
                push(@getters_list,
                     "    if (!(dev = virNodeDeviceLookupByName(priv->conn, args->name)))\n" .
                     "        goto cleanup;\n");
                push(@args_list, "dev");
                push(@free_list,
                     "    virObjectUnref(dev);");
            }

            foreach my $args_member (@{$call->{args_members}}) {
                if ($args_member =~ m/^remote_nonnull_string name;/ and $has_node_device) {
                    # ignore the name arg for node devices
                    next
                } elsif ($args_member =~ m/^remote_nonnull_(domain|network|storage_pool|storage_vol|interface|secret|nwfilter) (\S+);/) {
                    my $type_name = name_to_TypeName($1);

                    push(@vars_list, "vir${type_name}Ptr $2 = NULL");
                    push(@getters_list,
                         "    if (!($2 = get_nonnull_$1(priv->conn, args->$2)))\n" .
                         "        goto cleanup;\n");
                    push(@args_list, "$2");
                    push(@free_list,
                         "    virObjectUnref($2);");
                } elsif ($args_member =~ m/^remote_nonnull_domain_snapshot (\S+);$/) {
                    push(@vars_list, "virDomainPtr dom = NULL");
                    push(@vars_list, "virDomainSnapshotPtr snapshot = NULL");
                    push(@getters_list,
                         "    if (!(dom = get_nonnull_domain(priv->conn, args->${1}.dom)))\n" .
                         "        goto cleanup;\n" .
                         "\n" .
                         "    if (!(snapshot = get_nonnull_domain_snapshot(dom, args->${1})))\n" .
                         "        goto cleanup;\n");
                    push(@args_list, "snapshot");
                    push(@free_list,
                         "    virObjectUnref(snapshot);\n" .
                         "    virObjectUnref(dom);");
                } elsif ($args_member =~ m/^(?:(?:admin|remote)_string|remote_uuid) (\S+)<\S+>;/) {
                    push_privconn(\@args_list);
                    push(@args_list, "args->$1.$1_val");
                    push(@args_list, "args->$1.$1_len");
                } elsif ($args_member =~ m/^(?:opaque|(?:admin|remote)_nonnull_string) (\S+)<\S+>;(.*)$/) {
                    push_privconn(\@args_list);

                    my $cast = "";
                    my $arg_name = $1;
                    my $annotation = $2;

                    if ($annotation ne "") {
                        if ($annotation =~ m/\s*\/\*\s*(.*)\s*\*\//) {
                            $cast = $1;
                        } else {
                            die "malformed cast annotation for argument: $args_member";
                        }
                    }

                    push(@args_list, "${cast}args->$arg_name.${arg_name}_val");
                    push(@args_list, "args->$arg_name.${arg_name}_len");
                } elsif ($args_member =~ m/^(?:unsigned )?int (\S+)<\S+>;/) {
                    push_privconn(\@args_list);

                    push(@args_list, "args->$1.$1_val");
                    push(@args_list, "args->$1.$1_len");
                } elsif ($args_member =~ m/^remote_typed_param (\S+)<(\S+)>;/) {
                    push(@vars_list, "virTypedParameterPtr $1 = NULL");
                    push(@vars_list, "int n$1 = 0");
                    if ($call->{ProcName} eq "NodeSetMemoryParameters") {
                        push(@args_list, "priv->conn");
                    }
                    push(@args_list, "$1");
                    push(@args_list, "n$1");
                    push(@getters_list, "    if (virTypedParamsDeserialize((virTypedParameterRemotePtr) args->$1.$1_val,\n" .
                                        "                                  args->$1.$1_len,\n" .
                                        "                                  $2,\n" .
                                        "                                  &$1,\n" .
                                        "                                  &n$1) < 0)\n" .
                                        "        goto cleanup;\n");
                    push(@free_list, "    virTypedParamsFree($1, n$1);");
                } elsif ($args_member =~ m/<\S+>;/ or $args_member =~ m/\[\S+\];/) {
                    # just make all other array types fail
                    die "unhandled type for argument value: $args_member";
                } elsif ($args_member =~ m/^remote_uuid (\S+);/) {
                    push_privconn(\@args_list);

                    push(@args_list, "(unsigned char *) args->$1");
                } elsif ($args_member =~ m/^(?:admin|remote)_string (\S+);/) {
                    push_privconn(\@args_list);

                    push(@vars_list, "char *$1");
                    push(@optionals_list, "$1");
                    push(@args_list, "$1");
                } elsif ($args_member =~ m/^(?:admin|remote)_nonnull_string (\S+);/) {
                    push_privconn(\@args_list);

                    push(@args_list, "args->$1");
                } elsif ($args_member =~ m/^(unsigned )?int (\S+);/) {
                    push_privconn(\@args_list);

                    push(@args_list, "args->$2");
                } elsif ($args_member =~ m/^(unsigned )?hyper (\S+);/) {
                    push_privconn(\@args_list);

                    my $arg_name = $2;

                    if (hyper_to_long($call->{ProcName}, "arg", $arg_name)) {
                        my $type_name = $1; $type_name .= "long";
                        my $sign = ""; $sign = "U" if ($1);

                        push(@vars_list, "$type_name $arg_name");
                        push(@getters_list, "    HYPER_TO_${sign}LONG($arg_name, args->$arg_name);\n");
                        push(@args_list, "$arg_name");
                    } else {
                        push(@args_list, "args->$arg_name");
                    }
                } elsif ($args_member =~ m/^admin_nonnull_(server) (\S+);/) {
                    my $type_name = name_to_TypeName($1);

                    push(@vars_list, "virNet${type_name}Ptr $2 = NULL");
                    push(@getters_list,
                         "    if (!($2 = get_nonnull_$1(priv->dmn, args->$2)))\n" .
                         "        goto cleanup;\n");
                    push(@args_list, "$2");
                    push(@free_list,
                         "    virObjectUnref($2);");
                } elsif ($args_member =~ m/^admin_nonnull_(client) (\S+);/) {
                    my $type_name = name_to_TypeName($1);

                    push(@vars_list, "virNetServerPtr srv = NULL");
                    push(@vars_list, "virNetServer${type_name}Ptr $2 = NULL");
                    push(@getters_list,
                         "    if (!(srv = get_nonnull_server(priv->dmn, args->$2.srv)))\n" .
                         "        goto cleanup;\n");
                    push(@getters_list,
                         "    if (!($2 = get_nonnull_$1(srv, args->$2)))\n" .
                         "        goto cleanup;\n");
                    push(@args_list, "$2");
                    push(@free_list, "    virObjectUnref($2);");
                    push(@free_list, "    virObjectUnref(srv);");
                } elsif ($args_member =~ m/^(\/)?\*/) {
                    # ignore comments
                } else {
                    die "unhandled type for argument value: $args_member";
                }
            }
        }

        # handle return values of the function
        my $single_ret_var = "undefined";
        my $single_ret_by_ref = 0;
        my $single_ret_check = " == undefined";
        my $single_ret_as_list = 0;
        my $single_ret_list_name = "undefined";
        my $single_ret_list_max_var = "undefined";
        my $single_ret_list_max_define = "undefined";
        my $multi_ret = 0;
        my $modern_ret_as_list = 0;
        my $modern_ret_is_nested = 0;
        my $modern_ret_struct_name = "undefined";
        my $modern_ret_nested_struct_name = "undefined";
        my $single_ret_list_error_msg_type = "undefined";

        if ($rettype ne "void" and
            scalar(@{$call->{ret_members}}) > 1) {
            $multi_ret = 1;
        }

        if ($rettype ne "void") {
            foreach my $ret_member (@{$call->{ret_members}}) {
                if ($multi_ret) {
                    if ($ret_member =~ m/^(unsigned )?(char|short|int|hyper) (\S+)\[\S+\];/) {
                        if ($2 eq "hyper" and hyper_to_long($call->{ProcName}, "ret", $3)) {
                            die "legacy [u]long hyper arrays aren't supported";
                        }

                        push(@ret_list, "memcpy(ret->$3, tmp.$3, sizeof(ret->$3));");
                    } elsif ($ret_member =~ m/^(unsigned )?(char|short|int|hyper) (\S+);/) {
                        if (!$modern_ret_as_list) {
                            push(@ret_list, "ret->$3 = tmp.$3;");
                        }
                    } elsif ($ret_member =~ m/(?:admin|remote)_nonnull_(secret|nwfilter|node_device|interface|network|storage_vol|storage_pool|domain_snapshot|domain|server|client) (\S+)<(\S+)>;/) {
                        $modern_ret_struct_name = $1;
                        $single_ret_list_error_msg_type = $1;
                        $single_ret_list_name = $2;
                        $single_ret_list_max_define = $3;

                        $modern_ret_as_list = 1;
                    } else {
                        die "unhandled type for multi-return-value: $ret_member";
                    }
                } elsif ($ret_member =~ m/^(?:admin|remote)_nonnull_string (\S+)<(\S+)>;\s*\/\*\s*insert@(\d+)\s*\*\//) {
                    push(@vars_list, "int len");
                    splice(@args_list, int($3), 0, ("ret->$1.$1_val"));
                    push(@ret_list, "ret->$1.$1_len = len;");
                    push(@free_list_on_error, "VIR_FREE(ret->$1.$1_val);");
                    $single_ret_var = "len";
                    $single_ret_by_ref = 0;
                    $single_ret_check = " < 0";
                    $single_ret_as_list = 1;
                    $single_ret_list_name = $1;
                    $single_ret_list_max_var = "max$1";
                    $single_ret_list_max_define = $2;
                } elsif ($ret_member =~ m/^(admin|remote)_nonnull_string (\S+)<\S+>;/) {
                    # error out on unannotated arrays
                    die "$1_nonnull_string array without insert@<offset> annotation: $ret_member";
                } elsif ($ret_member =~ m/^(?:admin|remote)_nonnull_string (\S+);/) {
                    if ($call->{ProcName} eq "ConnectGetType") {
                        # SPECIAL: virConnectGetType returns a constant string that must
                        #          not be freed. Therefore, duplicate the string here.
                        push(@vars_list, "const char *$1");
                        push(@ret_list, "/* We have to VIR_STRDUP because remoteDispatchClientRequest will");
                        push(@ret_list, " * free this string after it's been serialised. */");
                        push(@ret_list, "if (VIR_STRDUP(ret->type, type) < 0)");
                        push(@ret_list, "    goto cleanup;");
                    } else {
                        push(@vars_list, "char *$1");
                        push(@ret_list, "ret->$1 = $1;");
                    }

                    $single_ret_var = $1;
                    $single_ret_by_ref = 0;
                    $single_ret_check = " == NULL";
                } elsif ($ret_member =~ m/^(?:admin|remote)_string (\S+);/) {
                    push(@vars_list, "char *$1 = NULL");
                    push(@vars_list, "char **$1_p = NULL");
                    push(@ret_list, "ret->$1 = $1_p;");
                    push(@free_list, "    VIR_FREE($1);");
                    push(@free_list_on_error, "VIR_FREE($1_p);");
                    push(@prepare_ret_list,
                         "if (VIR_ALLOC($1_p) < 0)\n" .
                         "        goto cleanup;\n" .
                         "\n" .
                         "    if (VIR_STRDUP(*$1_p, $1) < 0)\n".
                         "        goto cleanup;\n");

                    $single_ret_var = $1;
                    $single_ret_by_ref = 0;
                    $single_ret_check = " == NULL";
                } elsif ($ret_member =~ m/^remote_nonnull_(domain|network|storage_pool|storage_vol|interface|node_device|secret|nwfilter|domain_snapshot) (\S+);/) {
                    my $type_name = name_to_TypeName($1);

                    if ($call->{ProcName} eq "DomainCreateWithFlags") {
                        # SPECIAL: virDomainCreateWithFlags updates the given
                        #          domain object instead of returning a new one
                        push(@ret_list, "make_nonnull_$1(&ret->$2, $2);");
                        $single_ret_var = undef;
                        $single_ret_by_ref = 1;
                    } else {
                        push(@vars_list, "vir${type_name}Ptr $2 = NULL");
                        push(@ret_list, "make_nonnull_$1(&ret->$2, $2);");
                        push(@free_list,
                             "    virObjectUnref($2);");
                        $single_ret_var = $2;
                        $single_ret_by_ref = 0;
                        $single_ret_check = " == NULL";
                    }
                } elsif ($ret_member =~ m/^int (\S+)<(\S+)>;\s*\/\*\s*insert@(\d+)\s*\*\//) {
                    push(@vars_list, "int len");
                    splice(@args_list, int($3), 0, ("ret->$1.$1_val"));
                    push(@ret_list, "ret->$1.$1_len = len;");
                    push(@free_list_on_error, "VIR_FREE(ret->$1.$1_val);");
                    $single_ret_var = "len";
                    $single_ret_by_ref = 0;
                    $single_ret_check = " < 0";
                    $single_ret_as_list = 1;
                    $single_ret_list_name = $1;
                    $single_ret_list_max_var = "max$1";
                    $single_ret_list_max_define = $2;
                } elsif ($ret_member =~ m/^int (\S+)<\S+>;/) {
                    # error out on unannotated arrays
                    die "int array without insert@<offset> annotation: $ret_member";
                } elsif ($ret_member =~ m/^int (\S+);/) {
                    push(@vars_list, "int $1");
                    push(@ret_list, "ret->$1 = $1;");
                    $single_ret_var = $1;

                    if ($call->{ProcName} =~ m/GetAutostart$/) {
                        $single_ret_by_ref = 1;
                    } else {
                        $single_ret_by_ref = 0;

                        if ($call->{ProcName} eq "CPUCompare") {
                            $single_ret_check = " == VIR_CPU_COMPARE_ERROR";
                        } else {
                            $single_ret_check = " < 0";
                        }
                    }
                } elsif ($ret_member =~ m/^(?:unsigned )?hyper (\S+)<(\S+)>;\s*\/\*\s*insert@(\d+)\s*\*\//) {
                    if (hyper_to_long($call->{ProcName}, "ret", $1)) {
                        die "legacy [u]long hyper arrays aren't supported";
                    }

                    push(@vars_list, "int len");
                    push(@ret_list, "ret->$1.$1_len = len;");
                    push(@free_list_on_error, "VIR_FREE(ret->$1.$1_val);");
                    $single_ret_var = "len";
                    $single_ret_by_ref = 0;
                    $single_ret_as_list = 1;
                    $single_ret_list_name = $1;
                    $single_ret_list_max_var = "max$1";
                    $single_ret_list_max_define = $2;

                    if ($call->{ProcName} eq "NodeGetCellsFreeMemory") {
                        $single_ret_check = " <= 0";
                        splice(@args_list, int($3), 0, ("(unsigned long long *)ret->$1.$1_val"));
                    } else {
                        $single_ret_check = " < 0";
                        splice(@args_list, int($3), 0, ("ret->$1.$1_val"));
                    }
                } elsif ($ret_member =~ m/^(?:unsigned )?hyper (\S+)<\S+>;/) {
                    # error out on unannotated arrays
                    die "hyper array without insert@<offset> annotation: $ret_member";
                } elsif ($ret_member =~ m/^(unsigned )?hyper (\S+);(?:\s*\/\*\s*insert@(\d+)\s*\*\/)?/) {
                    my $type_name = $1;
                    my $ret_name = $2;
                    my $ret_assign;
                    my $insert = $3;

                    if (hyper_to_long($call->{ProcName}, "ret", $ret_name)) {
                        my $sign = ""; $sign = "U" if ($1);

                        $type_name .= "long";
                        $ret_assign = "HYPER_TO_${sign}LONG(ret->$ret_name, $ret_name);";
                    } else {
                        $type_name .= "long long";
                        $ret_assign = "ret->$ret_name = $ret_name;";
                    }

                    push(@vars_list, "$type_name $ret_name");
                    push(@ret_list, $ret_assign);

                    if ($insert) {
                        splice(@args_list, int($insert), 0, "&$ret_name");
                        $single_ret_var = undef;
                    } else {
                        $single_ret_var = $ret_name;
                    }

                    if ($call->{ProcName} eq "DomainGetMaxMemory" or
                        $call->{ProcName} eq "NodeGetFreeMemory") {
                        # SPECIAL: virDomainGetMaxMemory and virNodeGetFreeMemory
                        #          return the actual value directly and 0 indicates
                        #          an error
                        $single_ret_by_ref = 0;
                        $single_ret_check = " == 0";
                    } else {
                        $single_ret_by_ref = 1;
                    }
                } elsif ($ret_member =~ m/^opaque (\S+)<(\S+)>;\s*\/\*\s*insert@(\d+)\s*\*\//) {
                    push(@vars_list, "char *$1 = NULL");
                    push(@vars_list, "int $1_len = 0");
                    splice(@args_list, int($3), 0, ("&$1", "&$1_len"));
                    push(@ret_list, "ret->$1.$1_val = $1;");
                    push(@ret_list, "ret->$1.$1_len = $1_len;");
                    push(@free_list_on_error, "VIR_FREE($1);");
                    $single_ret_var = undef;
                    $single_ret_by_ref = 1;
                } elsif ($ret_member =~ m/^opaque (\S+)<\S+>;/) {
                    # error out on unannotated arrays
                    die "opaque array without insert@<offset> annotation: $ret_member";
                } elsif ($ret_member =~ m/^admin_nonnull_(server|client) (\S+);/) {
                    my $type_name = name_to_TypeName($1);

                    if ($1 eq "client") {
                        push(@vars_list, "virNetServer${type_name}Ptr $2 = NULL");
                        push(@ret_list, "make_nonnull_$1(&ret->$2, $2);");
                        push(@ret_list, "make_nonnull_server(&ret->$2.srv, srv);");
                    } else {
                        push(@vars_list, "virNet${type_name}Ptr $2 = NULL");
                        push(@ret_list, "make_nonnull_$1(&ret->$2, $2);");
                    }

                    push(@free_list,
                         "    virObjectUnref($2);");
                    $single_ret_var = $2;
                    $single_ret_by_ref = 0;
                    $single_ret_check = " == NULL";
                } elsif ($ret_member =~ m/^remote_typed_param (\S+)<(\S+)>;\s*\/\*\s*alloc@(\d+)@([^@]+)@(\d+)\s*\*\//) {
                    push(@vars_list, "virTypedParameterPtr $1 = NULL");
                    push(@vars_list, "$4 $1_len = 0");

                    $single_ret_by_ref = 1;
                    $single_ret_var = undef;

                    splice(@args_list, int($3), 0, "&$1");
                    splice(@args_list, int($5), 0, "&$1_len");

                    push(@ret_list, "if (virTypedParamsSerialize($1, $1_len,\n" .
                                    "                                (virTypedParameterRemotePtr *) &ret->$1.$1_val,\n" .
                                    "                                &ret->$1.$1_len,\n" .
                                    "                                VIR_TYPED_PARAM_STRING_OKAY) < 0)\n" .
                                    "        goto cleanup;\n");

                    push(@free_list, "    virTypedParamsFree($1, $1_len);");
                    push(@free_list_on_error, "virTypedParamsRemoteFree((virTypedParameterRemotePtr) ret->params.params_val,\n" .
                                              "                                 ret->params.params_len);\n");
                } elsif ($ret_member =~ m/^(\/)?\*/) {
                    # ignore comments
                } else {
                    die "unhandled type for return value: $ret_member";
                }
            }
        }

        # select struct type for multi-return-value functions
        if ($multi_ret) {
            if (defined $call->{ret_offset}) {
                push_privconn(\@args_list);

                if ($modern_ret_as_list) {
                    my $struct_name = name_to_TypeName($modern_ret_struct_name);

                    if ($structprefix eq "admin") {
                        if ($modern_ret_struct_name eq "client") {
                            $modern_ret_is_nested = 1;
                            $modern_ret_nested_struct_name = "server";
                            $struct_name = "NetServer${struct_name}";
                        } else {
                            $struct_name = "Net${struct_name}";
                        }
                    }

                    push(@vars_list, "vir${struct_name}Ptr *result = NULL");
                    push(@vars_list, "int nresults = 0");

                    @args_list = grep {!/\bneed_results\b/} @args_list;

                    splice(@args_list, $call->{ret_offset}, 0,
                           ("args->need_results ? &result : NULL"));
                } else {
                    my $struct_name = $call->{ProcName};
                    $struct_name =~ s/Get//;

                    splice(@args_list, $call->{ret_offset}, 0, ("&tmp"));

                    if ($call->{ProcName} eq "DomainBlockStats" ||
                        $call->{ProcName} eq "DomainInterfaceStats") {
                        # SPECIAL: virDomainBlockStats and virDomainInterfaceStats
                        #          have a 'Struct' suffix on the actual struct name
                        #          and take the struct size as additional argument
                        $struct_name .= "Struct";
                        splice(@args_list, $call->{ret_offset} + 1, 0, ("sizeof(tmp)"));
                    }

                    push(@vars_list, "vir$struct_name tmp");
                }
            } else {
                die "multi-return-value without insert@<offset> annotation: $call->{ret}";
            }
        }

        if ($call->{streamflag} ne "none") {
            splice(@args_list, $call->{streamoffset}, 0, ("st"));
            push(@free_list_on_error, "if (stream) {");
            push(@free_list_on_error, "    virStreamAbort(st);");
            push(@free_list_on_error, "    daemonFreeClientStream(client, stream);");
            push(@free_list_on_error, "} else {");
            push(@free_list_on_error, "    virObjectUnref(st);");
            push(@free_list_on_error, "}");
        }

        # print functions signature
        print "static int $name(\n";
        print "    virNetServerPtr server ATTRIBUTE_UNUSED,\n";
        print "    virNetServerClientPtr client,\n";
        print "    virNetMessagePtr msg ATTRIBUTE_UNUSED,\n";
        print "    virNetMessageErrorPtr rerr";
        if ($argtype ne "void") {
            print ",\n    $argtype *args";
        }
        if ($rettype ne "void") {
            print ",\n    $rettype *ret";
        }
        print ")\n";

        # print function body
        print "{\n";
        print "    int rv = -1;\n";

        if ($modern_ret_as_list) {
            print "    ssize_t i;\n";
        }

        foreach my $var (@vars_list) {
            print "    $var;\n";
        }

        if ($structprefix eq "admin") {
            print "    struct daemonAdmClientPrivate *priv =\n";
        } else {
            print "    struct daemonClientPrivate *priv =\n";
        }
        print "        virNetServerClientGetPrivateData(client);\n";

        if ($call->{streamflag} ne "none") {
            print "    virStreamPtr st = NULL;\n";
            print "    daemonClientStreamPtr stream = NULL;\n";
        }

        print "\n";

        if ($structprefix eq "admin") {
            print "    if (!priv->dmn) {\n";
        } else {
            print "    if (!priv->conn) {\n";
        }

        print "        virReportError(VIR_ERR_INTERNAL_ERROR, \"%s\", _(\"connection not open\"));\n";
        print "        goto cleanup;\n";
        print "    }\n";
        print "\n";

        if ($single_ret_as_list) {
            print "    if (args->$single_ret_list_max_var > $single_ret_list_max_define) {\n";
            print "        virReportError(VIR_ERR_RPC,\n";
            print "                       \"%s\", _(\"max$single_ret_list_name > $single_ret_list_max_define\"));\n";
            print "        goto cleanup;\n";
            print "    }\n";
            print "\n";
        }

        print join("\n", @getters_list);

        if (@getters_list) {
            print "\n";
        }

        foreach my $optional (@optionals_list) {
            print "    $optional = args->$optional ? *args->$optional : NULL;\n";
        }

        if (@optionals_list) {
            print "\n";
        }

        if ($call->{streamflag} ne "none") {
            print "    if (!(st = virStreamNew(priv->conn, VIR_STREAM_NONBLOCK)))\n";
            print "        goto cleanup;\n";
            print "\n";
            print "    if (!(stream = daemonCreateClientStream(client, st, remoteProgram, &msg->header, false)))\n";
            print "        goto cleanup;\n";
            print "\n";
        }

        if ($rettype eq "void") {
            print "    if ($prefix$call->{ProcName}(";
            print join(', ', @args_list);
            print ") < 0)\n";
            print "        goto cleanup;\n";
            print "\n";
        } elsif (!$multi_ret) {
            my $proc_name = $call->{ProcName};

            push_privconn(\@args_list);

            if ($structprefix eq "qemu" &&
                $call->{ProcName} =~ /^(Connect)?Domain/) {
                $proc_name =~ s/^((Connect)?Domain)/${1}Qemu/;
            }
            if ($structprefix eq "lxc" && $call->{ProcName} =~ /^Domain/) {
                $proc_name =~ s/^(Domain)/${1}Lxc/;
            }

            if ($single_ret_as_list) {
                print "    /* Allocate return buffer. */\n";
                print "    if (VIR_ALLOC_N(ret->$single_ret_list_name.${single_ret_list_name}_val," .
                      " args->$single_ret_list_max_var) < 0)\n";
                print "        goto cleanup;\n";
                print "\n";
            }

            if ($single_ret_by_ref) {
                print "    if ($prefix$proc_name(";
                print join(', ', @args_list);

                if (defined $single_ret_var) {
                    print ", &$single_ret_var";
                }

                print ") < 0)\n";
            } else {
                print "    if (($single_ret_var = $prefix$proc_name(";
                print join(', ', @args_list);
                print "))$single_ret_check)\n";
            }

            print "        goto cleanup;\n";
            print "\n";
        } else {
            if ($modern_ret_as_list) {
                print "    if ((nresults = \n";
                my $indln = "            $prefix$call->{ProcName}(";
                print $indln;
                print join(",\n" . ' ' x (length $indln), @args_list);
                print ")) < 0)\n";
            } else {
                print "    if ($prefix$call->{ProcName}(";
                print join(', ', @args_list);
                print ") < 0)\n";
            }
            print "        goto cleanup;\n";
            print "\n";
        }

        if ($call->{streamflag} ne "none") {
            print "    if (daemonAddClientStream(client, stream, ";

            if ($call->{streamflag} eq "write") {
                print "false";
            } else {
                print "true";
            }

            print ") < 0)\n";
            print "        goto cleanup;\n";
            print "\n";
        }

        if ($modern_ret_as_list) {
            print "    if (nresults > $single_ret_list_max_define) {\n";
            print "        virReportError(VIR_ERR_INTERNAL_ERROR,\n";
            print "                       _(\"Too many ${single_ret_list_error_msg_type}s '%d' for limit '%d'\"),\n";
            print "                       nresults, $single_ret_list_max_define);\n";
            print "        goto cleanup;\n";
            print "    }\n";
            print "\n";
            print "    if (result && nresults) {\n";
            print "        if (VIR_ALLOC_N(ret->$single_ret_list_name.${single_ret_list_name}_val, nresults) < 0)\n";
            print "            goto cleanup;\n";
            print "\n";
            print "        ret->$single_ret_list_name.${single_ret_list_name}_len = nresults;\n";
            if ($modern_ret_is_nested) {
                print "        for (i = 0; i < nresults; i++) {\n";
                print "            make_nonnull_$modern_ret_struct_name(ret->$single_ret_list_name.${single_ret_list_name}_val + i, result[i]);\n";
                print "            make_nonnull_$modern_ret_nested_struct_name(&ret->$single_ret_list_name.${single_ret_list_name}_val[i].srv, srv);\n";
                print "        }\n";
            } else {
                print "        for (i = 0; i < nresults; i++)\n";
                print "            make_nonnull_$modern_ret_struct_name(ret->$single_ret_list_name.${single_ret_list_name}_val + i, result[i]);\n";
            }
            print "    } else {\n";
            print "        ret->$single_ret_list_name.${single_ret_list_name}_len = 0;\n";
            print "        ret->$single_ret_list_name.${single_ret_list_name}_val = NULL;\n";
            print "    }\n";
            print "\n";
            print "    ret->ret = nresults;\n";
        }

        if (@prepare_ret_list) {
            print "    ";
            print join("\n    ", @prepare_ret_list);
            print "\n";
        }

        if (@ret_list) {
            print "    ";
            print join("\n    ", @ret_list);
            print "\n";
        }

        print "    rv = 0;\n";
        print "\n";
        print "cleanup:\n";
        print "    if (rv < 0)";

        if (scalar(@free_list_on_error) > 1) {
            print " {";
        }

        print "\n        ";
        print join("\n        ", @free_list_on_error);
        print "\n";

        if (scalar(@free_list_on_error) > 1) {
            print "    }\n";
        }

        print join("\n", @free_list);

        if (@free_list) {
            print "\n";
        }

        if ($modern_ret_as_list) {
            print "    if (result) {\n";
            print "        for (i = 0; i < nresults; i++)\n";
            print "            virObjectUnref(result[i]);\n";
            print "    }\n";
            print "    VIR_FREE(result);\n";
        }

        print "    return rv;\n";
        print "}\n\n\n\n";
    }


    # Finally we write out the huge dispatch table which lists
    # the dispatch helper method. the XDR proc for processing
    # args and return values, and the size of the args and
    # return value structs. All methods are marked as requiring
    # authentication. Methods are selectively relaxed in the
    # daemon code which registers the program.

    print "virNetServerProgramProc ${structprefix}Procs[] = {\n";
    for ($id = 0 ; $id <= $#calls ; $id++) {
        my ($comment, $name, $argtype, $arglen, $argfilter, $retlen, $retfilter, $priority);

        if (defined $calls[$id] && !$calls[$id]->{msg}) {
            $comment = "/* Method $calls[$id]->{ProcName} => $id */";
            $name = $structprefix . "Dispatch" . $calls[$id]->{ProcName} . "Helper";
            my $argtype = $calls[$id]->{args};
            my $rettype = $calls[$id]->{ret};
            $arglen = $argtype ne "void" ? "sizeof($argtype)" : "0";
            $retlen = $rettype ne "void" ? "sizeof($rettype)" : "0";
            $argfilter = $argtype ne "void" ? "xdr_$argtype" : "xdr_void";
            $retfilter = $rettype ne "void" ? "xdr_$rettype" : "xdr_void";
        } else {
            if ($calls[$id]->{msg}) {
                $comment = "/* Async event $calls[$id]->{ProcName} => $id */";
            } else {
                $comment = "/* Unused $id */";
            }
            $name = "NULL";
            $arglen = $retlen = 0;
            $argfilter = "xdr_void";
            $retfilter = "xdr_void";
        }

    $priority = defined $calls[$id]->{priority} ? $calls[$id]->{priority} : 0;

        print "{ $comment\n   ${name},\n   $arglen,\n   (xdrproc_t)$argfilter,\n   $retlen,\n   (xdrproc_t)$retfilter,\n   true,\n   $priority\n},\n";
    }
    print "};\n";
    print "size_t ${structprefix}NProcs = ARRAY_CARDINALITY(${structprefix}Procs);\n";
}

# Bodies for client functions ("remote_client_bodies.h").
elsif ($mode eq "client") {
    my %generate = map { $_ => 1 } @autogen;
    my @keys = sort (keys %calls);

    foreach (@keys) {
        my $call = $calls{$_};

        # skip things which are REMOTE_MESSAGE
        next if $call->{msg};

        # skip procedures not on generate list
        next if ! exists($generate{$call->{ProcName}});

        my $argtype = $call->{args};
        my $rettype = $call->{ret};

        # handle arguments to the function
        my @args_list = ();
        my @vars_list = ();
        my @args_check_list = ();
        my @setters_list = ();
        my @setters_list2 = ();
        my @free_list = ();
        my $priv_src = "conn";
        my $call_args = "&args";

        if ($argtype eq "void") {
            $call_args = "NULL";
        } else {
            push(@vars_list, "$argtype args");

            my $is_first_arg = 1;
            my $has_node_device = 0;

            # node device is special
            if ($argtype =~ m/^remote_node_/ and
                !($argtype =~ m/^remote_node_device_lookup_by_name_/) and
                !($argtype =~ m/^remote_node_device_create_xml_/)) {
                $has_node_device = 1;
            }

            foreach my $args_member (@{$call->{args_members}}) {
                if ($args_member =~ m/^remote_nonnull_string name;/ and $has_node_device) {
                    $priv_src = "dev->conn";
                    push(@args_list, "virNodeDevicePtr dev");
                    push(@setters_list, "args.name = dev->name;");
                } elsif ($args_member =~ m/^remote_nonnull_(domain|network|storage_pool|storage_vol|interface|secret|nwfilter|domain_snapshot) (\S+);/) {
                    my $name = $1;
                    my $arg_name = $2;
                    my $type_name = name_to_TypeName($name);

                    if ($is_first_arg) {
                        if ($name eq "domain_snapshot") {
                            $priv_src = "$arg_name->domain->conn";
                        } else {
                            $priv_src = "$arg_name->conn";
                        }
                    }

                    push(@args_list, "vir${type_name}Ptr $arg_name");
                    push(@setters_list, "make_nonnull_$1(&args.$arg_name, $arg_name);");
                } elsif ($args_member =~ m/^remote_uuid (\S+);/) {
                    push(@args_list, "const unsigned char *$1");
                    push(@setters_list, "memcpy(args.$1, $1, VIR_UUID_BUFLEN);");
                } elsif ($args_member =~ m/^(?:admin|remote)_string (\S+);/) {
                    push(@args_list, "const char *$1");
                    push(@setters_list, "args.$1 = $1 ? (char **)&$1 : NULL;");
                } elsif ($args_member =~ m/^(?:admin|remote)_nonnull_string (\S+)<(\S+)>;(.*)$/) {
                    my $type_name = "const char **";
                    my $arg_name = $1;
                    my $limit = $2;
                    my $annotation = $3;

                    if ($annotation ne "") {
                        if ($annotation =~ m/\s*\/\*\s*\((.*)\)\s*\*\//) {
                            $type_name = $1;
                        } else {
                            die "malformed cast annotation for argument: $args_member";
                        }
                    }

                    push(@args_list, "$type_name$arg_name");
                    push(@args_list, "unsigned int ${arg_name}len");
                    push(@setters_list, "args.$arg_name.${arg_name}_val = (char **)$arg_name;");
                    push(@setters_list, "args.$arg_name.${arg_name}_len = ${arg_name}len;");
                    push(@args_check_list, { name => "\"$arg_name\"", arg => "${arg_name}len", limit => $2 });
                } elsif ($args_member =~ m/^(?:admin|remote)_nonnull_string (\S+);/) {
                    push(@args_list, "const char *$1");
                    push(@setters_list, "args.$1 = (char *)$1;");
                } elsif ($args_member =~ m/^opaque (\S+)<(\S+)>;(.*)$/) {
                    my $type_name = "const char *";
                    my $arg_name = $1;
                    my $limit = $2;
                    my $annotation = $3;

                    if ($annotation ne "") {
                        if ($annotation =~ m/\s*\/\*\s*\((.*)\)\s*\*\//) {
                            $type_name = $1;
                        } else {
                            die "malformed cast annotation for argument: $args_member";
                        }
                    }

                    push(@args_list, "$type_name$arg_name");

                    if ($call->{ProcName} eq "SecretSetValue") {
                        # SPECIAL: virSecretSetValue uses size_t instead of int
                        push(@args_list, "size_t ${arg_name}len");
                    } else {
                        push(@args_list, "int ${arg_name}len");
                    }

                    push(@setters_list, "args.$arg_name.${arg_name}_val = (char *)$arg_name;");
                    push(@setters_list, "args.$arg_name.${arg_name}_len = ${arg_name}len;");
                    push(@args_check_list, { name => "\"$arg_name\"", arg => "${arg_name}len", limit => $limit });
                } elsif ($args_member =~ m/^(?:admin|remote)_string (\S+)<(\S+)>;/) {
                    my $arg_name = $1;
                    my $limit = $2;

                    push(@args_list, "const char *$arg_name");
                    push(@args_list, "int ${arg_name}len");
                    push(@setters_list, "args.$arg_name.${arg_name}_val = (char *)$arg_name;");
                    push(@setters_list, "args.$arg_name.${arg_name}_len = ${arg_name}len;");
                    push(@args_check_list, { name => "\"$arg_name\"", arg => "${arg_name}len", limit => $limit });
                } elsif ($args_member =~ m/^((?:unsigned )?int) (\S+)<(\S+)>;/) {
                    my $type_name = $1;
                    my $arg_name = $2;
                    my $limit = $3;

                    push(@args_list, "${type_name} *$arg_name");
                    push(@args_list, "int ${arg_name}len");
                    push(@setters_list, "args.$arg_name.${arg_name}_val = $arg_name;");
                    push(@setters_list, "args.$arg_name.${arg_name}_len = ${arg_name}len;");
                    push(@args_check_list, { name => "\"$arg_name\"", arg => "${arg_name}len", limit => $limit });
                } elsif ($args_member =~ m/^remote_typed_param (\S+)<(\S+)>;/) {
                    push(@args_list, "virTypedParameterPtr $1");
                    push(@args_list, "int n$1");
                    push(@setters_list2, "if (virTypedParamsSerialize($1, n$1,\n" .
                                         "                                (virTypedParameterRemotePtr *) &args.$1.$1_val,\n" .
                                         "                                &args.$1.$1_len,\n" .
                                         "                                VIR_TYPED_PARAM_STRING_OKAY) < 0) {\n" .
                                         "        xdr_free((xdrproc_t)xdr_$call->{args}, (char *)&args);\n" .
                                         "        goto done;\n" .
                                         "    }");
                    push(@free_list, "    virTypedParamsRemoteFree((virTypedParameterRemotePtr) args.params.params_val,\n" .
                                     "                             args.params.params_len);\n");
                } elsif ($args_member =~ m/^((?:unsigned )?int) (\S+);\s*\/\*\s*call-by-reference\s*\*\//) {
                    my $type_name = "$1 *";
                    my $arg_name = $2;

                    push(@args_list, "$type_name $arg_name");
                    push(@setters_list, "args.$arg_name = *$arg_name;");
                } elsif ($args_member =~ m/^((?:unsigned )?int) (\S+);/) {
                    my $type_name = $1;
                    my $arg_name = $2;

                    push(@args_list, "$type_name $arg_name");
                    push(@setters_list, "args.$arg_name = $arg_name;");
                } elsif ($args_member =~ m/^(unsigned )?hyper (\S+);/) {
                    my $type_name = $1;
                    my $arg_name = $2;

                    if (hyper_to_long($call->{ProcName}, "arg", $arg_name)) {
                        $type_name .= "long";
                    } else {
                        $type_name .= "long long";
                    }

                    push(@args_list, "$type_name $arg_name");
                    push(@setters_list, "args.$arg_name = $arg_name;");
                } elsif ($args_member =~ m/^admin_nonnull_(server|client) (\S+);/) {
                    my $name = $1;
                    my $arg_name = $2;
                    my $type_name = name_to_TypeName($name);

                    if ($is_first_arg) {
                        if ($name eq "client") {
                            $priv_src = "$arg_name->srv->conn";
                        } else {
                            $priv_src = "$arg_name->conn";
                        }
                    }

                    push(@args_list, "virAdm${type_name}Ptr $arg_name");
                    push(@setters_list, "make_nonnull_$1(&args.$arg_name, $arg_name);");
                } elsif ($args_member =~ m/^(\/)?\*/) {
                    # ignore comments
                } else {
                    die "unhandled type for argument value: $args_member";
                }

                if ($is_first_arg and $priv_src eq "conn") {
                    unshift(@args_list, "$connect_ptr conn");
                }

                $is_first_arg = 0;
            }
        }

        if (!@args_list) {
            push(@args_list, "$connect_ptr conn");
        }

        # handle return values of the function
        my @ret_list = ();
        my @ret_list2 = ();
        my $call_ret = "&ret";
        my $single_ret_var = "int rv = -1";
        my $single_ret_type = "int";
        my $single_ret_as_list = 0;
        my $single_ret_list_error_msg_type = "undefined";
        my $single_ret_list_name = "undefined";
        my $single_ret_list_max_var = "undefined";
        my $single_ret_list_max_define = "undefined";
        my $single_ret_cleanup = 0;
        my $multi_ret = 0;
        my $modern_ret_as_list = 0;
        my $modern_ret_struct_name = "undefined";
        my $modern_ret_var_type = "undefined";
        my @custom_error_cleanup = ();

        if ($rettype ne "void" and
            scalar(@{$call->{ret_members}}) > 1) {
            $multi_ret = 1;
        }

        if ($rettype eq "void") {
            $call_ret = "NULL";
        } else {
            push(@vars_list, "$rettype ret");

            foreach my $ret_member (@{$call->{ret_members}}) {
                if ($multi_ret) {
                    if ($ret_member =~ m/^(unsigned )?(char|short|int|hyper) (\S+)\[\S+\];/) {
                        if ($2 eq "hyper" and hyper_to_long($call->{ProcName}, "ret", $3)) {
                            die "legacy [u]long hyper arrays aren't supported";
                        }

                        push(@ret_list, "memcpy(result->$3, ret.$3, sizeof(result->$3));");
                    } elsif ($ret_member =~ m/(?:admin|remote)_nonnull_(secret|nwfilter|node_device|interface|network|storage_vol|storage_pool|domain_snapshot|domain|server|client) (\S+)<(\S+)>;/) {
                        my $proc_name = name_to_TypeName($1);

                        if ($structprefix eq "admin") {
                            $modern_ret_var_type = "virAdm${proc_name}Ptr";
                        } else {
                            $modern_ret_var_type = "vir${proc_name}Ptr";
                        }

                        $modern_ret_struct_name = $1;
                        $single_ret_list_name = $2;
                        $single_ret_list_max_var = $3;
                        $single_ret_list_error_msg_type = $1;

                        $modern_ret_as_list = 1;
                    } elsif ($ret_member =~ m/<\S+>;/ or $ret_member =~ m/\[\S+\];/) {
                        # just make all other array types fail
                        die "unhandled type for multi-return-value for " .
                            "procedure $call->{name}: $ret_member";
                    } elsif ($ret_member =~ m/^(unsigned )?(char|short|int|hyper) (\S+);/) {
                        if ($2 eq "hyper" and hyper_to_long($call->{ProcName}, "ret", $3)) {
                            my $sign = ""; $sign = "U" if ($1);

                            push(@ret_list, "HYPER_TO_${sign}LONG(result->$3, ret.$3);");
                        } elsif (!$modern_ret_as_list) {
                            push(@ret_list, "result->$3 = ret.$3;");
                        }
                    } else {
                        die "unhandled type for multi-return-value for " .
                            "procedure $call->{name}: $ret_member";
                    }
                } elsif ($ret_member =~ m/^(?:admin|remote)_nonnull_string (\S+)<(\S+)>;\s*\/\*\s*insert@(\d+)\s*\*\//) {
                    splice(@args_list, int($3), 0, ("char **const $1"));
                    push(@ret_list, "rv = ret.$1.$1_len;");
                    $single_ret_var = "int rv = -1";
                    $single_ret_type = "int";
                    $single_ret_as_list = 1;
                    $single_ret_list_name = $1;
                    $single_ret_list_max_var = "max$1";
                    $single_ret_list_max_define = $2;
                } elsif ($ret_member =~ m/^(admin|remote)_nonnull_string (\S+)<\S+>;/) {
                    # error out on unannotated arrays
                    die "$1_nonnull_string array without insert@<offset> annotation: $ret_member";
                } elsif ($ret_member =~ m/^(?:admin|remote)_nonnull_string (\S+);/) {
                    push(@ret_list, "rv = ret.$1;");
                    $single_ret_var = "char *rv = NULL";
                    $single_ret_type = "char *";
                } elsif ($ret_member =~ m/^(?:admin|remote)_string (\S+);/) {
                    push(@ret_list, "rv = ret.$1 ? *ret.$1 : NULL;");
                    push(@ret_list, "VIR_FREE(ret.$1);");
                    $single_ret_var = "char *rv = NULL";
                    $single_ret_type = "char *";
                } elsif ($ret_member =~ m/^remote_nonnull_(domain|network|storage_pool|storage_vol|node_device|interface|secret|nwfilter|domain_snapshot) (\S+);/) {
                    my $name = $1;
                    my $arg_name = $2;
                    my $type_name = name_to_TypeName($name);

                    if ($call->{ProcName} eq "DomainCreateWithFlags") {
                        # SPECIAL: virDomainCreateWithFlags updates the given
                        #          domain object instead of returning a new one
                        push(@ret_list, "dom->id = ret.dom.id;");
                        push(@ret_list, "xdr_free((xdrproc_t)xdr_$call->{ret}, (char *)&ret);");
                        push(@ret_list, "rv = 0;");
                        $single_ret_var = "int rv = -1";
                        $single_ret_type = "int";
                    } else {
                        if ($name eq "domain_snapshot") {
                            my $dom = "$priv_src";
                            $dom =~ s/->conn//;
                            push(@ret_list, "rv = get_nonnull_$name($dom, ret.$arg_name);");
                        } else {
                            push(@ret_list, "rv = get_nonnull_$name($priv_src, ret.$arg_name);");
                        }

                        push(@ret_list, "xdr_free((xdrproc_t)xdr_$rettype, (char *)&ret);");
                        $single_ret_var = "vir${type_name}Ptr rv = NULL";
                        $single_ret_type = "vir${type_name}Ptr";
                    }
                } elsif ($ret_member =~ m/^remote_typed_param (\S+)<(\S+)>;\s*\/\*\s*alloc@(\d+)@([^@]+)@(\d+)\s*\*\//) {
                    # handle self allocating arrays of typed parameters
                    splice(@args_list, int($3), 0, ("virTypedParameterPtr *$1"));
                    splice(@args_list, int($5), 0, ("$4 *n$1"));
                    push(@vars_list, "virTypedParameterPtr ret_params = NULL");
                    push(@vars_list, "int ret_nparams = 0");
                    # virTypedParamsDeserialize allocates the array if @params is null
                    push(@ret_list2, "if (virTypedParamsDeserialize((virTypedParameterRemotePtr) ret.$1.$1_val,\n" .
                                     "                                  ret.$1.$1_len,\n" .
                                     "                                  $2,\n" .
                                     "                                  &ret_params,\n" .
                                     "                                  &ret_nparams) < 0)\n" .
                                     "        goto cleanup;\n");
                    push(@ret_list2, "*$1 = ret_params;");
                    push(@ret_list2, "*n$1 = ret_nparams;");
                    push(@custom_error_cleanup, "virTypedParamsFree(ret_params, ret_nparams);\n");
                    $single_ret_cleanup = 1;
                } elsif ($ret_member =~ m/^remote_typed_param (\S+)<(\S+)>;\s*\/\*\s*insert@(\d+)\s*\*\//) {
                    splice(@args_list, int($3), 0, ("virTypedParameterPtr $1"));
                    push(@ret_list2, "if (virTypedParamsDeserialize((virTypedParameterRemotePtr) ret.$1.$1_val,\n" .
                                     "                                  ret.$1.$1_len,\n" .
                                     "                                  $2,\n" .
                                     "                                  &$1,\n" .
                                     "                                  n$1) < 0)\n" .
                                     "        goto cleanup;\n");
                    $single_ret_cleanup = 1;
                } elsif ($ret_member =~ m/^remote_typed_param (\S+)<\S+>;/) {
                    # error out on unannotated arrays
                    die "remote_typed_param array without insert@... or alloc@... annotation: $ret_member";
                } elsif ($ret_member =~ m/^int (\S+);/) {
                    my $arg_name = $1;

                    if ($call->{ProcName} =~ m/GetAutostart$/) {
                        push(@args_list, "int *$arg_name");
                        push(@ret_list, "if ($arg_name) *$arg_name = ret.$arg_name;");
                        push(@ret_list, "rv = 0;");
                    } else {
                        push(@ret_list, "rv = ret.$arg_name;");
                    }

                    $single_ret_var = "int rv = -1";
                    $single_ret_type = "int";
                } elsif ($ret_member =~ m/^(unsigned )?hyper (\S+);\s*\/\*\s*insert@(\d+)\s*\*\//) {
                    my $type_name = $1;
                    my $sign = ""; $sign = "U" if ($1);
                    my $ret_name = $2;
                    my $insert = $3;

                    if (hyper_to_long($call->{ProcName}, "ret", $ret_name)) {
                        $type_name .= "long";
                        push(@ret_list, "if ($ret_name) HYPER_TO_${sign}LONG(*$ret_name, ret.$ret_name);");
                    } else {
                        $type_name .= "long long";
                        push(@ret_list, "if ($ret_name) *$ret_name = ret.$ret_name;");
                    }

                    splice(@args_list, int($insert), 0, ("$type_name *$ret_name"));
                    push(@ret_list, "rv = 0;");
                    $single_ret_var = "int rv = -1";
                    $single_ret_type = "int";
                } elsif ($ret_member =~ m/^unsigned hyper (\S+);/) {
                    my $ret_name = $1;

                    if ($call->{ProcName} =~ m/Get(Lib)?Version/) {
                        if ($structprefix eq "admin") {
                            push(@args_list, "unsigned long long *$ret_name");
                            push(@ret_list, "*$ret_name = ret.$ret_name;");
                        } else {
                            push(@args_list, "unsigned long *$ret_name");
                            push(@ret_list, "if ($ret_name) HYPER_TO_ULONG(*$ret_name, ret.$ret_name);");
                        }
                        push(@ret_list, "rv = 0;");
                        $single_ret_var = "int rv = -1";
                        $single_ret_type = "int";
                    } elsif (hyper_to_long($call->{ProcName}, "ret", $ret_name)) {
                        push(@ret_list, "HYPER_TO_ULONG(rv, ret.$ret_name);");
                        $single_ret_var = "unsigned long rv = 0";
                        $single_ret_type = "unsigned long";
                    } else {
                        push(@ret_list, "rv = ret.$ret_name;");
                        $single_ret_var = "unsigned long long rv = 0";
                        $single_ret_type = "unsigned long long";
                    }
                } elsif ($ret_member =~ m/^admin_nonnull_(server|client) (\S+);/) {
                    my $name = $1;
                    my $arg_name = $2;
                    my $type_name = name_to_TypeName($name);

                    if ($name eq "client") {
                        my $clnt = $priv_src;
                        $clnt =~ s/->conn//;
                        push(@ret_list, "rv = get_nonnull_$name($clnt, ret.$arg_name);");
                    } else {
                        push(@ret_list, "rv = get_nonnull_$name($priv_src, ret.$arg_name);");
                    }

                    push(@ret_list, "xdr_free((xdrproc_t)xdr_$rettype, (char *)&ret);");

                    $single_ret_var = "virAdm${type_name}Ptr rv = NULL";
                    $single_ret_type = "virAdm${type_name}Ptr";
                } elsif ($ret_member =~ m/^(\/)?\*/) {
                    # ignore comments
                } else {
                    die "unhandled type for return value for procedure " .
                        "$call->{name}: $ret_member";
                }
            }
        }

        if ($modern_ret_as_list) {
            # clear arguments and setters we don't want in this code
            @args_list = grep {!/\bneed_results\b/} @args_list;
            @setters_list = grep {!/\bneed_results\b/} @setters_list;

            push(@vars_list, "${modern_ret_var_type} *tmp_results = NULL");
            push(@setters_list, "args.need_results = !!result;");

            $single_ret_var = "int rv = -1";
            $single_ret_type = "int";
        }

        # select struct type for multi-return-value functions
        if ($multi_ret) {
            my $struct_name = "undefined";

            if (!(defined $call->{ret_offset})) {
                die "multi-return-value without insert@<offset> annotation: $call->{ret}";
            }

            if ($modern_ret_as_list) {
                $struct_name = name_to_TypeName($modern_ret_struct_name);

                $struct_name .= "Ptr **";
                if ($structprefix eq "admin") {
                    $struct_name = "Adm${struct_name}";
                }
            } else {
                $struct_name = $call->{ProcName};

                $struct_name =~ s/Get//;
                $struct_name = "${struct_name}Ptr "
            }
            splice(@args_list, $call->{ret_offset}, 0, ("vir${struct_name}result"));
        }

        if ($call->{streamflag} ne "none") {
            splice(@args_list, $call->{streamoffset}, 0, ("virStreamPtr st"));
        }

        # print function
        print "\n";
        print "static $single_ret_type\n";
        if ($structprefix eq "remote") {
            print "$structprefix$call->{ProcName}(";
        } else {
            my $proc = $call->{ProcName};
            my $extra = $structprefix;
            $extra =~ s/^(\w)/uc $1/e;
            if ($structprefix eq "admin") {
                $proc = $extra . $proc;
            } else {
                $proc =~ s/^(Domain)(.*)/$1 . $extra . $2/e;
            }
            print "remote$proc(";
        }

        print join(", ", @args_list);

        print ")\n";
        print "{\n";
        print "    $single_ret_var;\n";
        if ($structprefix eq "admin") {
            print "    remoteAdminPrivPtr priv = $priv_src->privateData;\n";
        } else {
            print "    struct private_data *priv = $priv_src->privateData;\n";
        }

        foreach my $var (@vars_list) {
            print "    $var;\n";
        }

        if ($single_ret_as_list or
            $modern_ret_as_list) {
            print "    size_t i;\n";
        }

        if ($call->{streamflag} ne "none") {
            print "    virNetClientStreamPtr netst = NULL;\n";
        }

        print "\n";
        if ($structprefix eq "admin") {
            print "    virObjectLock(priv);\n";
        } else {
            print "    remoteDriverLock(priv);\n";
        }

        if ($call->{streamflag} ne "none") {
            print "\n";
            print "    if (!(netst = virNetClientStreamNew(st, priv->remoteProgram, $call->{constname}, priv->counter, false)))\n";
            print "        goto done;\n";
            print "\n";
            print "    if (virNetClientAddStream(priv->client, netst) < 0) {\n";
            print "        virObjectUnref(netst);\n";
            print "        goto done;\n";
            print "    }";
            print "\n";
            print "    st->driver = &remoteStreamDrv;\n";
            print "    st->privateData = netst;\n";
        }

        if ($call->{ProcName} eq "SupportsFeature") {
            # SPECIAL: VIR_DRV_FEATURE_REMOTE feature is handled directly
            print "\n";
            print "    if (feature == VIR_DRV_FEATURE_REMOTE) {\n";
            print "        rv = 1;\n";
            print "        goto done;\n";
            print "    }\n";
        }

        foreach my $args_check (@args_check_list) {
            print "\n";
            print "    if ($args_check->{arg} > $args_check->{limit}) {\n";
            print "        virReportError(VIR_ERR_RPC,\n";
            print "                       _(\"%s length greater than maximum: %d > %d\"),\n";
            print "                       $args_check->{name}, (int)$args_check->{arg}, $args_check->{limit});\n";
            print "        goto done;\n";
            print "    }\n";
        }

        if ($single_ret_as_list) {
            print "\n";
            print "    if ($single_ret_list_max_var > $single_ret_list_max_define) {\n";
            print "        virReportError(VIR_ERR_RPC,\n";
            print "                       _(\"too many remote ${single_ret_list_error_msg_type}s: %d > %d\"),\n";
            print "                       $single_ret_list_max_var, $single_ret_list_max_define);\n";
            print "        goto done;\n";
            print "    }\n";
        }

        if (@setters_list) {
            print "\n";
            print "    ";
        }

        print join("\n    ", @setters_list);

        if (@setters_list) {
            print "\n";
        }

        if (@setters_list2) {
            print "\n";
            print "    ";
        }

        print join("\n    ", @setters_list2);

        if (@setters_list2) {
            print "\n";
        }

        if ($rettype ne "void") {
            print "\n";
            print "    memset(&ret, 0, sizeof(ret));\n";
        }

        my $callflags = "0";
        if ($structprefix eq "qemu") {
            $callflags = "REMOTE_CALL_QEMU";
        }
        if ($structprefix eq "lxc") {
            $callflags = "REMOTE_CALL_LXC";
        }

        my $call_priv = $priv_src;
        if ($structprefix ne "admin") {
            $call_priv = "$call_priv, priv";
        }

        print "\n";
        print "    if (call($call_priv, $callflags, $call->{constname},\n";
        print "             (xdrproc_t)xdr_$argtype, (char *)$call_args,\n";
        print "             (xdrproc_t)xdr_$rettype, (char *)$call_ret) == -1) {\n";

        if ($call->{streamflag} ne "none") {
            print "        virNetClientRemoveStream(priv->client, netst);\n";
            print "        virObjectUnref(netst);\n";
            print "        st->driver = NULL;\n";
            print "        st->privateData = NULL;\n";
        }

        print "        goto done;\n";
        print "    }\n";
        print "\n";

        if ($single_ret_as_list or
            $modern_ret_as_list) {
            print "    if (ret.$single_ret_list_name.${single_ret_list_name}_len > $single_ret_list_max_var) {\n";
            print "        virReportError(VIR_ERR_RPC,\n";
            print "                       _(\"too many remote ${single_ret_list_error_msg_type}s: %d > %d\"),\n";
            print "                       ret.$single_ret_list_name.${single_ret_list_name}_len, $single_ret_list_max_var);\n";
            print "        goto cleanup;\n";
            print "    }\n";
            print "\n";
        }

        if ($single_ret_as_list) {
            print "    /* This call is caller-frees (although that isn't clear from\n";
            print "     * the documentation).  However xdr_free will free up both the\n";
            print "     * names and the list of pointers, so we have to VIR_STRDUP the\n";
            print "     * names here. */\n";
            print "    for (i = 0; i < ret.$single_ret_list_name.${single_ret_list_name}_len; ++i) {\n";
            print "        if (VIR_STRDUP(${single_ret_list_name}[i],\n";
            print "                       ret.$single_ret_list_name.${single_ret_list_name}_val[i]) < 0) {\n";
            print "            size_t j;\n";
            print "            for (j = 0; j < i; j++)\n";
            print "                VIR_FREE(${single_ret_list_name}[j]);\n";
            print "\n";
            print "            goto cleanup;\n";
            print "        }\n";
            print "    }\n";
            print "\n";
        } elsif ($modern_ret_as_list) {
            if ($modern_ret_struct_name =~ m/domain_snapshot|client/) {
                $priv_src =~ s/->conn//;
            }
            print "    if (result) {\n";
            print "        if (VIR_ALLOC_N(tmp_results, ret.$single_ret_list_name.${single_ret_list_name}_len + 1) < 0)\n";
            print "            goto cleanup;\n";
            print "\n";
            print "        for (i = 0; i < ret.$single_ret_list_name.${single_ret_list_name}_len; i++) {\n";
            print "            tmp_results[i] = get_nonnull_$modern_ret_struct_name($priv_src, ret.$single_ret_list_name.${single_ret_list_name}_val[i]);\n";
            print "            if (!tmp_results[i])\n";
            print "                goto cleanup;\n";
            print "        }\n";
            print "        *result = tmp_results;\n";
            print "        tmp_results = NULL;\n";
            print "    }\n";
            print "\n";
        }


        if (@ret_list2) {
            print "    ";
            print join("\n    ", @ret_list2);
            print "\n";
        }

        if (@ret_list) {
            print "    ";
            print join("\n    ", @ret_list);
            print "\n";
        }

        if ($call->{ProcName} eq "DomainDestroy" ||
            $call->{ProcName} eq "DomainSave" ||
            $call->{ProcName} eq "DomainManagedSave") {
            # SPECIAL: virDomain{Destroy|Save|ManagedSave} need to reset
            # the domain id explicitly on success
            print "    dom->id = -1;\n";
        }

        if ($multi_ret or !@ret_list) {
            if ($modern_ret_as_list) {
                print "    rv = ret.ret;\n";
            } else {
                print "    rv = 0;\n";
            }
        }

        if ($single_ret_as_list or $single_ret_cleanup or $modern_ret_as_list) {
            print "\n";
            print "cleanup:\n";
            if (@custom_error_cleanup) {
                print "    if (rv != 0) {\n";
                print "        ";
                print join("\n        ", @custom_error_cleanup);
                print "    }\n";
            }
            if ($modern_ret_as_list) {
                print "    if (tmp_results) {\n";
                print "        for (i = 0; i < ret.$single_ret_list_name.${single_ret_list_name}_len; i++)\n";
                print "            virObjectUnref(tmp_results[i]);\n";
                print "        VIR_FREE(tmp_results);\n";
                print "    }\n";
                print "\n";
            }
            print "    xdr_free((xdrproc_t)xdr_$call->{ret}, (char *)&ret);\n";
        }

        print "\n";
        print "done:\n";

        print join("\n", @free_list);

        if ($structprefix eq "admin") {
            print "    virObjectUnlock(priv);\n";
        } else {
            print "    remoteDriverUnlock(priv);\n";
        }

        print "    return rv;\n";
        print "}\n";
    }
} elsif ($mode eq "aclheader" ||
         $mode eq "aclbody" ||
         $mode eq "aclsym" ||
         $mode eq "aclapi") {
    my %generate = map { $_ => 1 } @autogen;
    my @keys = keys %calls;

    if ($mode eq "aclsym") {
        @keys = sort { my $c = $a . "ensureacl";
                       my $d = $b . "ensureacl";
                       $c cmp $d } @keys;
    } else {
        @keys = sort { $a cmp $b } @keys;
    }

    if ($mode eq "aclheader") {
        my @headers = (
            "internal.h",
            "domain_conf.h",
            "network_conf.h",
            "secret_conf.h",
            "storage_conf.h",
            "nwfilter_conf.h",
            "node_device_conf.h",
            "interface_conf.h"
            );
        foreach my $hdr (@headers) {
            print "#include \"$hdr\"\n";
        }
        print "\n";
    } elsif ($mode eq "aclbody") {
        my $header = shift;
        print "#include <config.h>\n";
        print "#include \"$header\"\n";
        print "#include \"access/viraccessmanager.h\"\n";
        print "#include \"datatypes.h\"\n";
        print "#include \"virerror.h\"\n";
        print "\n";
        print "#define VIR_FROM_THIS VIR_FROM_ACCESS\n";
        print "\n";
    } elsif ($mode eq "aclapi") {
        print "<aclinfo>\n";
    } else {
        print "\n";
    }

    foreach (@keys) {
        my $call = $calls{$_};

        die "missing 'acl' option for $call->{ProcName}"
            unless exists $call->{acl} &&
            $#{$call->{acl}} != -1;

        next if $call->{acl}->[0] eq "none";

        if ($mode eq "aclsym") {
            my $apiname = $prefix . $call->{ProcName};
            if ($structprefix eq "qemu") {
                $apiname =~ s/(vir(Connect)?Domain)/${1}Qemu/;
            } elsif ($structprefix eq "lxc") {
                $apiname =~ s/virDomain/virDomainLxc/;
            }
            if (defined $call->{aclfilter}) {
                print $apiname . "CheckACL;\n";
            }
            print $apiname . "EnsureACL;\n";
        } elsif ($mode eq "aclapi") {
            &generate_aclapi($call);
        } else {
            &generate_acl($call, $call->{acl}, "Ensure");
            if (defined $call->{aclfilter}) {
                &generate_acl($call, $call->{aclfilter}, "Check");
            }
        }

        sub generate_acl {
            my $call = shift;
            my $acl = shift;
            my $action = shift;

            my @acl;
            foreach (@{$acl}) {
                my @bits = split /:/;
                push @acl, { object => $bits[0], perm => $bits[1], flags => $bits[2] }
            }

            my $checkflags = 0;
            for (my $i = 1 ; $i <= $#acl ; $i++) {
                if ($acl[$i]->{object} ne $acl[0]->{object}) {
                    die "acl for '$call->{ProcName}' cannot check different objects";
                }
                if (defined $acl[$i]->{flags}) {
                    $checkflags = 1;
                }
            }

            my $apiname = $prefix . $call->{ProcName};
            if ($structprefix eq "qemu") {
                $apiname =~ s/(vir(Connect)?Domain)/${1}Qemu/;
            } elsif ($structprefix eq "lxc") {
                $apiname =~ s/virDomain/virDomainLxc/;
            }

            my $object = $acl[0]->{object};
            my $arg = $acl[0]->{object};
            $arg =~ s/^.*_(\w+)$/$1/;
            $object =~ s/^(\w)/uc $1/e;
            $object =~ s/_(\w)/uc $1/e;
            $object =~ s/Nwfilter/NWFilter/;
            my $objecttype = $prefix . $object . "DefPtr";
            $apiname .= $action . "ACL";

            if ($arg eq "interface") {
                $arg = "iface";
            }

            my @argdecls;
            push @argdecls, "$connect_ptr conn";
            if ($object ne "Connect") {
                if ($object eq "StorageVol") {
                    push @argdecls, "virStoragePoolDefPtr pool";
                }
                push @argdecls, "$objecttype $arg";
            }
            if ($checkflags) {
                push @argdecls, "unsigned int flags";
            }

            my $ret;
            my $pass;
            my $fail;
            if ($action eq "Check") {
                $ret = "bool";
                $pass = "true";
                $fail = "false";
            } else {
                $ret = "int";
                $pass = "0";
                $fail = "-1";
            }

            if ($mode eq "aclheader") {
                print "extern $ret $apiname(" . join(", ", @argdecls) . ");\n";
            } else {
                my @argvars;
                push @argvars, "mgr";
                push @argvars, "conn->driver->name";
                if ($object ne "Connect") {
                    if ($object eq "StorageVol") {
                        push @argvars, "pool";
                    }
                    push @argvars, $arg;
                }

                print "/* Returns: $fail on error/denied, $pass on allowed */\n";
                print "$ret $apiname(" . join(", ", @argdecls) . ")\n";
                print "{\n";
                print "    virAccessManagerPtr mgr;\n";
                print "    int rv;\n";
                print "\n";
                print "    if (!(mgr = virAccessManagerGetDefault())) {\n";
                if ($action eq "Check") {
                    print "        virResetLastError();\n";
                }
                print "        return $fail;\n";
                print "    }\n";
                print "\n";

                foreach my $acl (@acl) {
                    my $perm = "vir_access_perm_" . $acl->{object} . "_" . $acl->{perm};
                    $perm =~ tr/a-z/A-Z/;

                    my $method = "virAccessManagerCheck" . $object;
                    my $space = ' ' x length($method);
                    print "    if (";
                    if (defined $acl->{flags}) {
                        my $flags = $acl->{flags};
                        if ($flags =~ /^\!/) {
                            $flags = substr $flags, 1;
                            print "((flags & ($flags)) == 0) &&\n";
                        } else {
                            print "((flags & ($flags)) == ($flags)) &&\n";
                        }
                        print "        ";
                    }
                    print "(rv = $method(" . join(", ", @argvars, $perm) . ")) <= 0) {\n";
                    print "        virObjectUnref(mgr);\n";
                    if ($action eq "Ensure") {
                        print "        if (rv == 0)\n";
                        print "            virReportError(VIR_ERR_ACCESS_DENIED, NULL);\n";
                        print "        return $fail;\n";
                    } else {
                        print "        virResetLastError();\n";
                        print "        return $fail;\n";
                    }
                    print "    }";
                    print "\n";
                }

                print "    virObjectUnref(mgr);\n";
                print "    return $pass;\n";
                print "}\n\n";
            }
        }

        sub generate_aclapi {
            my $call = shift;

            my $apiname = $prefix . $call->{ProcName};
            if ($structprefix eq "qemu") {
                $apiname =~ s/(vir(Connect)?Domain)/${1}Qemu/;
            } elsif ($structprefix eq "lxc") {
                $apiname =~ s/virDomain/virDomainLxc/;
            }

            print "  <api name='$apiname'>\n";

            my $acl = $call->{acl};
            foreach (@{$acl}) {
                my @bits = split /:/;
                print "    <check object='$bits[0]' perm='$bits[1]'";
                if (defined $bits[2]) {
                    print " flags='$bits[2]'";
                }
                print "/>\n";
            }

            my $aclfilter = $call->{aclfilter};
            foreach (@{$aclfilter}) {
                my @bits = split /:/;
                print "    <filter object='$bits[0]' perm='$bits[1]'/>\n";
            }

            print "  </api>\n";
        }

    }

    if ($mode eq "aclapi") {
        print "</aclinfo>\n";
    }
}
