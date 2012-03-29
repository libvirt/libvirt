#!/usr/bin/perl -w
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

use Getopt::Std;

# Command line options.
our ($opt_p, $opt_t, $opt_a, $opt_r, $opt_d, $opt_b, $opt_k);
getopts ('ptardbk');

my $structprefix = shift or die "missing prefix argument";
my $protocol = shift or die "missing protocol argument";
my @autogen;

my $procprefix = uc $structprefix;

# Convert name_of_call to NameOfCall.
sub name_to_ProcName {
    my $name = shift;
    my @elems = split /_/, $name;
    @elems = map ucfirst, @elems;
    @elems = map { $_ =~ s/Nwfilter/NWFilter/; $_ =~ s/Xml$/XML/;
                   $_ =~ s/Uri$/URI/; $_ =~ s/Uuid$/UUID/; $_ =~ s/Id$/ID/;
                   $_ =~ s/Mac$/MAC/; $_ =~ s/Cpu$/CPU/; $_ =~ s/Os$/OS/;
                   $_ =~ s/Nmi$/NMI/; $_ =~ s/Pm/PM/; $_ } @elems;
    join "", @elems
}

# Read the input file (usually remote_protocol.x) and form an
# opinion about the name, args and return type of each RPC.
my ($name, $ProcName, $id, $flags, %calls, @calls);

my $collect_args_members = 0;
my $collect_ret_members = 0;
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
    } elsif (/^struct ${structprefix}_(.*)_args/) {
        $name = $1;
        $ProcName = name_to_ProcName ($name);

        die "duplicate definition of ${structprefix}_${name}_args"
            if exists $calls{$name};

        $calls{$name} = {
            name => $name,
            ProcName => $ProcName,
            UC_NAME => uc $name,
            args => "${structprefix}_${name}_args",
            args_members => [],
            ret => "void"
        };

        $collect_args_members = 1;
        $collect_ret_members = 0;
        $last_name = $name;
    } elsif (/^struct ${structprefix}_(.*)_ret\s+{(.*)$/) {
        $name = $1;
        $flags = $2;
        $ProcName = name_to_ProcName ($name);

        if (exists $calls{$name}) {
            $calls{$name}->{ret} = "${structprefix}_${name}_ret";
        } else {
            $calls{$name} = {
                name => $name,
                ProcName => $ProcName,
                UC_NAME => uc $name,
                args => "void",
                ret => "${structprefix}_${name}_ret",
                ret_members => []
            }
        }

        if ($flags ne "" and ($opt_b or $opt_k)) {
            if (!($flags =~ m/^\s*\/\*\s*insert@(\d+)\s*\*\/\s*$/)) {
                die "invalid generator flags for $calls{$name}->{ret}";
            }

            $calls{$name}->{ret_offset} = int($1);
        }

        $collect_args_members = 0;
        $collect_ret_members = 1;
        $last_name = $name;
    } elsif (/^struct ${structprefix}_(.*)_msg/) {
        $name = $1;
        $ProcName = name_to_ProcName ($name);

        $calls{$name} = {
            name => $name,
            ProcName => $ProcName,
            UC_NAME => uc $name,
            msg => "${structprefix}_${name}_msg"
        };

        $collect_args_members = 0;
        $collect_ret_members = 0;
    } elsif (/^\s*${procprefix}_PROC_(.*?)\s*=\s*(\d+)\s*,?(.*)$/) {
        $name = lc $1;
        $id = $2;
        $flags = $3;
        $ProcName = name_to_ProcName ($name);

        if (!exists $calls{$name}) {
            # that the argument and return value cases have not yet added
            # this procedure to the calls hash means that it has no arguments
            # and no return value. add it to the calls hash now because all
            # procedures have to be listed in the calls hash
            $calls{$name} = {
                name => $name,
                ProcName => $ProcName,
                UC_NAME => uc $name,
                args => "void",
                ret => "void"
            }
        }

        if ($opt_b or $opt_k) {
            if (!($flags =~ m/^\s*\/\*\s*(\S+)\s+(\S+)\s*(\|.*)?\s+(priority:(\S+))?\s*\*\/\s*$/)) {
                die "invalid generator flags for ${procprefix}_PROC_${name}"
            }

            my $genmode = $opt_b ? $1 : $2;
            my $genflags = $3;
            my $priority = defined $5 ? $5 : "low";

            if ($genmode eq "autogen") {
                push(@autogen, $ProcName);
            } elsif ($genmode eq "skipgen") {
                # ignore it
            } else {
                die "invalid generator flags for ${procprefix}_PROC_${name}"
            }

            if (defined $genflags and $genflags ne "") {
                if ($genflags =~ m/^\|\s*(read|write)stream@(\d+)\s*$/) {
                    $calls{$name}->{streamflag} = $1;
                    $calls{$name}->{streamoffset} = int($2);
                } else {
                    die "invalid generator flags for ${procprefix}_PROC_${name}"
                }
            } else {
                $calls{$name}->{streamflag} = "none";
            }

            # for now, we distinguish only two levels of prioroty:
            # low (0) and high (1)
            if ($priority eq "high") {
                $calls{$name}->{priority} = 1;
            } elsif ($priority eq "low") {
                $calls{$name}->{priority} = 0;
            } else {
                die "invalid priority ${priority} for ${procprefix}_PROC_${name}"
            }
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
    GetLibVersion               => { ret => { lib_ver => 1 } },
    GetVersion                  => { ret => { hv_ver => 1 } },
    NodeGetInfo                 => { ret => { memory => 1 } },
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

print <<__EOF__;
/* Automatically generated by gendispatch.pl.
 * Do not edit this file.  Any changes you make will be lost.
 */
__EOF__

if (!$opt_b and !$opt_k) {
    print "\n";
}

# Debugging.
if ($opt_d) {
    my @keys = sort (keys %calls);
    foreach (@keys) {
        print "$_:\n";
        print "        name $calls{$_}->{name} ($calls{$_}->{ProcName})\n";
        print "        $calls{$_}->{args} -> $calls{$_}->{ret}\n";
        print "        priority -> $calls{$_}->{priority}\n";
    }
}

# Bodies for dispatch functions ("remote_dispatch_bodies.h").
elsif ($opt_b) {
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
	print "  VIR_DEBUG(\"server=%p client=%p msg=%p rerr=%p args=%p ret=%p\", server, client, msg, rerr, args, ret);\n";
	print "  return $name(server, client, msg, rerr";
	if ($argtype ne "void") {
	    print ", args";
	}
	if ($rettype ne "void") {
	    print ", ret";
	}
	print ");\n";
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
                !($argtype =~ m/^remote_node_device_create_xml_/)) {
                $has_node_device = 1;
                push(@vars_list, "virNodeDevicePtr dev = NULL");
                push(@getters_list,
                     "    if (!(dev = virNodeDeviceLookupByName(priv->conn, args->name)))\n" .
                     "        goto cleanup;\n");
                push(@args_list, "dev");
                push(@free_list,
                     "    if (dev)\n" .
                     "        virNodeDeviceFree(dev);");
            }

            foreach my $args_member (@{$call->{args_members}}) {
                if ($args_member =~ m/^remote_nonnull_string name;/ and $has_node_device) {
                    # ignore the name arg for node devices
                    next
                } elsif ($args_member =~ m/^remote_nonnull_(domain|network|storage_pool|storage_vol|interface|secret|nwfilter) (\S+);/) {
                    my $type_name = name_to_ProcName($1);

                    push(@vars_list, "vir${type_name}Ptr $2 = NULL");
                    push(@getters_list,
                         "    if (!($2 = get_nonnull_$1(priv->conn, args->$2)))\n" .
                         "        goto cleanup;\n");
                    push(@args_list, "$2");
                    push(@free_list,
                         "    if ($2)\n" .
                         "        vir${type_name}Free($2);");
                } elsif ($args_member =~ m/^remote_nonnull_domain_snapshot /) {
                    push(@vars_list, "virDomainPtr dom = NULL");
                    push(@vars_list, "virDomainSnapshotPtr snapshot = NULL");
                    push(@getters_list,
                         "    if (!(dom = get_nonnull_domain(priv->conn, args->snap.dom)))\n" .
                         "        goto cleanup;\n" .
                         "\n" .
                         "    if (!(snapshot = get_nonnull_domain_snapshot(dom, args->snap)))\n" .
                         "        goto cleanup;\n");
                    push(@args_list, "snapshot");
                    push(@free_list,
                         "    if (snapshot)\n" .
                         "        virDomainSnapshotFree(snapshot);\n" .
                         "    if (dom)\n" .
                         "        virDomainFree(dom);");
                } elsif ($args_member =~ m/^(?:remote_string|remote_uuid) (\S+)<\S+>;/) {
                    if (! @args_list) {
                        push(@args_list, "priv->conn");
                    }

                    push(@args_list, "args->$1.$1_val");
                    push(@args_list, "args->$1.$1_len");
                } elsif ($args_member =~ m/^(?:opaque|remote_nonnull_string) (\S+)<\S+>;(.*)$/) {
                    if (! @args_list) {
                        push(@args_list, "priv->conn");
                    }

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
                    if (! @args_list) {
                        push(@args_list, "priv->conn");
                    }

                    push(@args_list, "args->$1.$1_val");
                    push(@args_list, "args->$1.$1_len");
                } elsif ($args_member =~ m/^remote_typed_param (\S+)<(\S+)>;/) {
                    push(@vars_list, "virTypedParameterPtr $1 = NULL");
                    push(@vars_list, "int n$1");
                    push(@args_list, "$1");
                    push(@args_list, "n$1");
                    push(@getters_list, "    if (($1 = remoteDeserializeTypedParameters(args->$1.$1_val,\n" .
                                        "                                                   args->$1.$1_len,\n" .
                                        "                                                   $2,\n" .
                                        "                                                   &n$1)) == NULL)\n" .
                                        "        goto cleanup;\n");
                    push(@free_list, "    virTypedParameterArrayClear($1, n$1);");
                    push(@free_list, "    VIR_FREE($1);");
                } elsif ($args_member =~ m/<\S+>;/ or $args_member =~ m/\[\S+\];/) {
                    # just make all other array types fail
                    die "unhandled type for argument value: $args_member";
                } elsif ($args_member =~ m/^remote_uuid (\S+);/) {
                    if (! @args_list) {
                        push(@args_list, "priv->conn");
                    }

                    push(@args_list, "(unsigned char *) args->$1");
                } elsif ($args_member =~ m/^remote_string (\S+);/) {
                    if (! @args_list) {
                        push(@args_list, "priv->conn");
                    }

                    push(@vars_list, "char *$1");
                    push(@optionals_list, "$1");
                    push(@args_list, "$1");
                } elsif ($args_member =~ m/^remote_nonnull_string (\S+);/) {
                    if (! @args_list) {
                        push(@args_list, "priv->conn");
                    }

                    push(@args_list, "args->$1");
                } elsif ($args_member =~ m/^(unsigned )?int (\S+);/) {
                    if (! @args_list) {
                        push(@args_list, "priv->conn");
                    }

                    push(@args_list, "args->$2");
                } elsif ($args_member =~ m/^(unsigned )?hyper (\S+);/) {
                    if (! @args_list) {
                        push(@args_list, "priv->conn");
                    }

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
                        push(@ret_list, "ret->$3 = tmp.$3;");
                    } else {
                        die "unhandled type for multi-return-value: $ret_member";
                    }
                } elsif ($ret_member =~ m/^remote_nonnull_string (\S+)<(\S+)>;\s*\/\*\s*insert@(\d+)\s*\*\//) {
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
                } elsif ($ret_member =~ m/^remote_nonnull_string (\S+)<\S+>;/) {
                    # error out on unannotated arrays
                    die "remote_nonnull_string array without insert@<offset> annotation: $ret_member";
                } elsif ($ret_member =~ m/^remote_nonnull_string (\S+);/) {
                    if ($call->{ProcName} eq "GetType") {
                        # SPECIAL: virConnectGetType returns a constant string that must
                        #          not be freed. Therefore, duplicate the string here.
                        push(@vars_list, "const char *$1");
                        push(@ret_list, "/* We have to strdup because remoteDispatchClientRequest will");
                        push(@ret_list, " * free this string after it's been serialised. */");
                        push(@ret_list, "if (!(ret->type = strdup(type))) {");
                        push(@ret_list, "    virReportOOMError();");
                        push(@ret_list, "    goto cleanup;");
                        push(@ret_list, "}");
                    } else {
                        push(@vars_list, "char *$1");
                        push(@ret_list, "ret->$1 = $1;");
                    }

                    $single_ret_var = $1;
                    $single_ret_by_ref = 0;
                    $single_ret_check = " == NULL";
                } elsif ($ret_member =~ m/^remote_string (\S+);/) {
                    push(@vars_list, "char *$1 = NULL");
                    push(@vars_list, "char **$1_p = NULL");
                    push(@ret_list, "ret->$1 = $1_p;");
                    push(@free_list, "    VIR_FREE($1);");
                    push(@free_list_on_error, "VIR_FREE($1_p);");
                    push(@prepare_ret_list,
                         "if (VIR_ALLOC($1_p) < 0) {\n" .
                         "        virReportOOMError();\n" .
                         "        goto cleanup;\n" .
                         "    }\n" .
                         "    \n" .
                         "    *$1_p = strdup($1);\n" .
                         "    if (*$1_p == NULL) {\n" .
                         "        virReportOOMError();\n" .
                         "        goto cleanup;\n" .
                         "    }\n");

                    $single_ret_var = $1;
                    $single_ret_by_ref = 0;
                    $single_ret_check = " == NULL";
                } elsif ($ret_member =~ m/^remote_nonnull_(domain|network|storage_pool|storage_vol|interface|node_device|secret|nwfilter|domain_snapshot) (\S+);/) {
                    my $type_name = name_to_ProcName($1);

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
                             "    if ($2)\n" .
                             "        vir${type_name}Free($2);");
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
                } elsif ($ret_member =~ m/^(\/)?\*/) {
                    # ignore comments
                } else {
                    die "unhandled type for return value: $ret_member";
                }
            }
        }

        # select struct type for multi-return-value functions
        if ($multi_ret) {
            if (!(defined $call->{ret_offset})) {
                die "multi-return-value without insert@<offset> annotation: $call->{ret}";
            }

            if (! @args_list) {
                push(@args_list, "priv->conn");
            }

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

        if ($call->{streamflag} ne "none") {
            splice(@args_list, $call->{streamoffset}, 0, ("st"));
            push(@free_list_on_error, "if (stream) {");
            push(@free_list_on_error, "    virStreamAbort(st);");
            push(@free_list_on_error, "    daemonFreeClientStream(client, stream);");
            push(@free_list_on_error, "} else {");
            push(@free_list_on_error, "    virStreamFree(st);");
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

        foreach my $var (@vars_list) {
            print "    $var;\n";
        }
	print "    struct daemonClientPrivate *priv =\n";
        print "        virNetServerClientGetPrivateData(client);\n";

        if ($call->{streamflag} ne "none") {
            print "    virStreamPtr st = NULL;\n";
            print "    daemonClientStreamPtr stream = NULL;\n";
        }

        print "\n";
        print "    if (!priv->conn) {\n";
        print "        virNetError(VIR_ERR_INTERNAL_ERROR, \"%s\", _(\"connection not open\"));\n";
        print "        goto cleanup;\n";
        print "    }\n";
        print "\n";

        if ($single_ret_as_list) {
            print "    if (args->$single_ret_list_max_var > $single_ret_list_max_define) {\n";
            print "        virNetError(VIR_ERR_INTERNAL_ERROR,\n";
            print "                    \"%s\", _(\"max$single_ret_list_name > $single_ret_list_max_define\"));\n";
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
            print "    if (!(stream = daemonCreateClientStream(client, st, remoteProgram, &msg->header)))\n";
            print "        goto cleanup;\n";
            print "\n";
        }

        if ($rettype eq "void") {
            print "    if (vir$call->{ProcName}(";
            print join(', ', @args_list);
            print ") < 0)\n";
            print "        goto cleanup;\n";
            print "\n";
        } elsif (!$multi_ret) {
            my $prefix = "";
            my $proc_name = $call->{ProcName};

            if (! @args_list) {
                push(@args_list, "priv->conn");

                if ($call->{ProcName} ne "NodeGetFreeMemory") {
                    $prefix = "Connect"
                }
            }

            if ($call->{ProcName} eq "GetSysinfo" or
                $call->{ProcName} eq "GetMaxVcpus" or
                $call->{ProcName} eq "DomainXMLFromNative" or
                $call->{ProcName} eq "DomainXMLToNative" or
                $call->{ProcName} eq "FindStoragePoolSources" or
                $call->{ProcName} =~ m/^List/) {
                $prefix = "Connect"
            } elsif ($call->{ProcName} eq "SupportsFeature") {
                $prefix = "Drv"
            } elsif ($call->{ProcName} eq "CPUBaseline") {
                $proc_name = "ConnectBaselineCPU"
            } elsif ($call->{ProcName} eq "CPUCompare") {
                $proc_name = "ConnectCompareCPU"
            } elsif ($structprefix eq "qemu" && $call->{ProcName} =~ /^Domain/) {
                $proc_name =~ s/^(Domain)/${1}Qemu/;
            }

            if ($single_ret_as_list) {
                print "    /* Allocate return buffer. */\n";
                print "    if (VIR_ALLOC_N(ret->$single_ret_list_name.${single_ret_list_name}_val," .
                      " args->$single_ret_list_max_var) < 0) {\n";
                print "        virReportOOMError();\n";
                print "        goto cleanup;\n";
                print "    }\n";
                print "\n";
            }

            if ($single_ret_by_ref) {
                print "    if (vir$prefix$proc_name(";
                print join(', ', @args_list);

                if (defined $single_ret_var) {
                    print ", &$single_ret_var";
                }

                print ") < 0)\n";
            } else {
                print "    if (($single_ret_var = vir$prefix$proc_name(";
                print join(', ', @args_list);
                print "))$single_ret_check)\n";
            }

            print "        goto cleanup;\n";
            print "\n";
        } else {
            print "    if (vir$call->{ProcName}(";
            print join(', ', @args_list);
            print ") < 0)\n";
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
elsif ($opt_k) {
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
        my $priv_name = "privateData";
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
                $priv_name = "devMonPrivateData";
            }

            foreach my $args_member (@{$call->{args_members}}) {
                if ($args_member =~ m/^remote_nonnull_string name;/ and $has_node_device) {
                    $priv_src = "dev->conn";
                    push(@args_list, "virNodeDevicePtr dev");
                    push(@setters_list, "args.name = dev->name;");
                } elsif ($args_member =~ m/^remote_nonnull_(domain|network|storage_pool|storage_vol|interface|secret|nwfilter|domain_snapshot) (\S+);/) {
                    my $name = $1;
                    my $arg_name = $2;
                    my $type_name = name_to_ProcName($name);

                    if ($is_first_arg) {
                        if ($name eq "domain_snapshot") {
                            $priv_src = "$arg_name->domain->conn";
                        } else {
                            $priv_src = "$arg_name->conn";
                        }

                        if ($name =~ m/^storage_/) {
                            $priv_name = "storagePrivateData";
                        } elsif (!($name =~ m/^domain/)) {
                            $priv_name = "${name}PrivateData";
                        }
                    }

                    push(@args_list, "vir${type_name}Ptr $arg_name");
                    push(@setters_list, "make_nonnull_$1(&args.$arg_name, $arg_name);");
                } elsif ($args_member =~ m/^remote_uuid (\S+);/) {
                    push(@args_list, "const unsigned char *$1");
                    push(@setters_list, "memcpy(args.$1, $1, VIR_UUID_BUFLEN);");
                } elsif ($args_member =~ m/^remote_string (\S+);/) {
                    push(@args_list, "const char *$1");
                    push(@setters_list, "args.$1 = $1 ? (char **)&$1 : NULL;");
                } elsif ($args_member =~ m/^remote_nonnull_string (\S+)<(\S+)>;(.*)$/) {
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
                } elsif ($args_member =~ m/^remote_nonnull_string (\S+);/) {
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
                } elsif ($args_member =~ m/^remote_string (\S+)<(\S+)>;/) {
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
                    push(@setters_list2, "if (remoteSerializeTypedParameters($1, n$1, &args.$1.$1_val, &args.$1.$1_len) < 0) {\n" .
                                         "        xdr_free((xdrproc_t)xdr_$call->{args}, (char *)&args);\n" .
                                         "        goto done;\n" .
                                         "    }");
                    push(@free_list, "    remoteFreeTypedParameters(args.params.params_val, args.params.params_len);\n");
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
                } elsif ($args_member =~ m/^(\/)?\*/) {
                    # ignore comments
                } else {
                    die "unhandled type for argument value: $args_member";
                }

                if ($is_first_arg and $priv_src eq "conn") {
                    unshift(@args_list, "virConnectPtr conn");
                }

                $is_first_arg = 0;
            }
        }

        if (! @args_list) {
            push(@args_list, "virConnectPtr conn");
        }

        # fix priv_name for the NumOf* functions
        if ($priv_name eq "privateData" and
            !($call->{ProcName} =~ m/(Domains|DomainSnapshot)/) and
            ($call->{ProcName} =~ m/NumOf(Defined|Domain)*(\S+)s/ or
             $call->{ProcName} =~ m/List(Defined|Domain)*(\S+)s/)) {
            my $prefix = lc $2;
            $prefix =~ s/(pool|vol)$//;
            $priv_name = "${prefix}PrivateData";
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
                    } elsif ($ret_member =~ m/<\S+>;/ or $ret_member =~ m/\[\S+\];/) {
                        # just make all other array types fail
                        die "unhandled type for multi-return-value for " .
                            "procedure $call->{name}: $ret_member";
                    } elsif ($ret_member =~ m/^(unsigned )?(char|short|int|hyper) (\S+);/) {
                        if ($2 eq "hyper" and hyper_to_long($call->{ProcName}, "ret", $3)) {
                            my $sign = ""; $sign = "U" if ($1);

                            push(@ret_list, "HYPER_TO_${sign}LONG(result->$3, ret.$3);");
                        } else {
                            push(@ret_list, "result->$3 = ret.$3;");
                        }
                    } else {
                        die "unhandled type for multi-return-value for " .
                            "procedure $call->{name}: $ret_member";
                    }
                } elsif ($ret_member =~ m/^remote_nonnull_string (\S+)<(\S+)>;\s*\/\*\s*insert@(\d+)\s*\*\//) {
                    splice(@args_list, int($3), 0, ("char **const $1"));
                    push(@ret_list, "rv = ret.$1.$1_len;");
                    $single_ret_var = "int rv = -1";
                    $single_ret_type = "int";
                    $single_ret_as_list = 1;
                    $single_ret_list_name = $1;
                    $single_ret_list_max_var = "max$1";
                    $single_ret_list_max_define = $2;
                } elsif ($ret_member =~ m/^remote_nonnull_string (\S+)<\S+>;/) {
                    # error out on unannotated arrays
                    die "remote_nonnull_string array without insert@<offset> annotation: $ret_member";
                } elsif ($ret_member =~ m/^remote_nonnull_string (\S+);/) {
                    push(@ret_list, "rv = ret.$1;");
                    $single_ret_var = "char *rv = NULL";
                    $single_ret_type = "char *";
                } elsif ($ret_member =~ m/^remote_string (\S+);/) {
                    push(@ret_list, "rv = ret.$1 ? *ret.$1 : NULL;");
                    push(@ret_list, "VIR_FREE(ret.$1);");
                    $single_ret_var = "char *rv = NULL";
                    $single_ret_type = "char *";
                } elsif ($ret_member =~ m/^remote_nonnull_(domain|network|storage_pool|storage_vol|node_device|interface|secret|nwfilter|domain_snapshot) (\S+);/) {
                    my $name = $1;
                    my $arg_name = $2;
                    my $type_name = name_to_ProcName($name);

                    if ($name eq "node_device") {
                        $priv_name = "devMonPrivateData";
                    } elsif ($name =~ m/^storage_/) {
                        $priv_name = "storagePrivateData";
                    } elsif (!($name =~ m/^domain/)) {
                        $priv_name = "${name}PrivateData";
                    }

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
                } elsif ($ret_member =~ m/^remote_typed_param (\S+)<(\S+)>;\s*\/\*\s*insert@(\d+)\s*\*\//) {
                    splice(@args_list, int($3), 0, ("virTypedParameterPtr $1"));
                    push(@ret_list2, "if (remoteDeserializeTypedParameters(ret.$1.$1_val,\n" .
                                     "                                         ret.$1.$1_len,\n" .
                                     "                                         $2,\n" .
                                     "                                         $1,\n" .
                                     "                                         n$1) < 0)\n" .
                                     "        goto cleanup;\n");
                    $single_ret_cleanup = 1;
                } elsif ($ret_member =~ m/^remote_typed_param (\S+)<\S+>;/) {
                    # error out on unannotated arrays
                    die "remote_typed_param array without insert@<offset> annotation: $ret_member";
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
                        push(@args_list, "unsigned long *$ret_name");
                        push(@ret_list, "if ($ret_name) HYPER_TO_ULONG(*$ret_name, ret.$ret_name);");
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
                } elsif ($ret_member =~ m/^(\/)?\*/) {
                    # ignore comments
                } else {
                    die "unhandled type for return value for procedure " .
                        "$call->{name}: $ret_member";
                }
            }
        }

        # select struct type for multi-return-value functions
        if ($multi_ret) {
            if (!(defined $call->{ret_offset})) {
                die "multi-return-value without insert@<offset> annotation: $call->{ret}";
            }

            my $struct_name = $call->{ProcName};
            $struct_name =~ s/Get//;

            splice(@args_list, $call->{ret_offset}, 0, ("vir${struct_name}Ptr result"));
        }

        if ($call->{streamflag} ne "none") {
            splice(@args_list, $call->{streamoffset}, 0, ("virStreamPtr st"));
        }

        # print function
        print "\n";
        print "static $single_ret_type\n";
        print "$structprefix$call->{ProcName}(";

        print join(", ", @args_list);

        print ")\n";
        print "{\n";
        print "    $single_ret_var;\n";
        print "    struct private_data *priv = $priv_src->$priv_name;\n";

        foreach my $var (@vars_list) {
            print "    $var;\n";
        }

        if ($single_ret_as_list) {
            print "    int i;\n";
        }

        if ($call->{streamflag} ne "none") {
            print "    virNetClientStreamPtr netst = NULL;\n";
        }

        print "\n";
        print "    remoteDriverLock(priv);\n";

        if ($call->{streamflag} ne "none") {
            print "\n";
            print "    if (!(netst = virNetClientStreamNew(priv->remoteProgram, REMOTE_PROC_$call->{UC_NAME}, priv->counter)))\n";
            print "        goto done;\n";
            print "\n";
            print "    if (virNetClientAddStream(priv->client, netst) < 0) {\n";
            print "        virNetClientStreamFree(netst);\n";
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
            print "        remoteError(VIR_ERR_RPC,\n";
            print "                    _(\"%s length greater than maximum: %d > %d\"),\n";
            print "                    $args_check->{name}, (int)$args_check->{arg}, $args_check->{limit});\n";
            print "        goto done;\n";
            print "    }\n";
        }

        if ($single_ret_as_list) {
            print "\n";
            print "    if ($single_ret_list_max_var > $single_ret_list_max_define) {\n";
            print "        remoteError(VIR_ERR_RPC,\n";
            print "                    _(\"too many remote ${single_ret_list_error_msg_type}s: %d > %d\"),\n";
            print "                    $single_ret_list_max_var, $single_ret_list_max_define);\n";
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

        print "\n";
        print "    if (call($priv_src, priv, $callflags, ${procprefix}_PROC_$call->{UC_NAME},\n";
        print "             (xdrproc_t)xdr_$argtype, (char *)$call_args,\n";
        print "             (xdrproc_t)xdr_$rettype, (char *)$call_ret) == -1) {\n";

        if ($call->{streamflag} ne "none") {
            print "        virNetClientRemoveStream(priv->client, netst);\n";
            print "        virNetClientStreamFree(netst);\n";
            print "        st->driver = NULL;\n";
            print "        st->privateData = NULL;\n";
        }

        print "        goto done;\n";
        print "    }\n";
        print "\n";

        if ($single_ret_as_list) {
            print "    if (ret.$single_ret_list_name.${single_ret_list_name}_len > $single_ret_list_max_var) {\n";
            print "        remoteError(VIR_ERR_RPC,\n";
            print "                    _(\"too many remote ${single_ret_list_error_msg_type}s: %d > %d\"),\n";
            print "                    ret.$single_ret_list_name.${single_ret_list_name}_len, $single_ret_list_max_var);\n";
            print "        goto cleanup;\n";
            print "    }\n";
            print "\n";
            print "    /* This call is caller-frees (although that isn't clear from\n";
            print "     * the documentation).  However xdr_free will free up both the\n";
            print "     * names and the list of pointers, so we have to strdup the\n";
            print "     * names here. */\n";
            print "    for (i = 0; i < ret.$single_ret_list_name.${single_ret_list_name}_len; ++i) {\n";
            print "        ${single_ret_list_name}[i] = strdup(ret.$single_ret_list_name.${single_ret_list_name}_val[i]);\n";
            print "\n";
            print "        if (${single_ret_list_name}[i] == NULL) {\n";
            print "            for (--i; i >= 0; --i)\n";
            print "                VIR_FREE(${single_ret_list_name}[i]);\n";
            print "\n";
            print "            virReportOOMError();\n";
            print "            goto cleanup;\n";
            print "        }\n";
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
            print "    rv = 0;\n";
        }

        if ($single_ret_as_list or $single_ret_cleanup) {
            print "\n";
            print "cleanup:\n";
            print "    xdr_free((xdrproc_t)xdr_remote_$call->{name}_ret, (char *)&ret);\n";
        }

        print "\n";
        print "done:\n";

        print join("\n", @free_list);

        print "    remoteDriverUnlock(priv);\n";
        print "    return rv;\n";
        print "}\n";
    }
}
