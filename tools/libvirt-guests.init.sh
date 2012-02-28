#!/bin/sh

# the following is the LSB init header
#
### BEGIN INIT INFO
# Provides: libvirt-guests
# Required-Start: libvirtd
# Required-Stop: libvirtd
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: suspend/resume libvirt guests on shutdown/boot
# Description: This is a script for suspending active libvirt guests
#              on shutdown and resuming them on next boot
#              See http://libvirt.org
### END INIT INFO

# the following is chkconfig init header
#
# libvirt-guests:   suspend/resume libvirt guests on shutdown/boot
#
# chkconfig: 345 99 01
# description:  This is a script for suspending active libvirt guests \
#               on shutdown and resuming them on next boot \
#               See http://libvirt.org
#

sysconfdir="@sysconfdir@"
localstatedir="@localstatedir@"
libvirtd="@sbindir@"/libvirtd

# Source function library.
test ! -r "$sysconfdir"/rc.d/init.d/functions ||
    . "$sysconfdir"/rc.d/init.d/functions

# Source gettext library.
# Make sure this file is recognized as having translations: _("dummy")
. "@bindir@"/gettext.sh

export TEXTDOMAIN="@PACKAGE@" TEXTDOMAINDIR="@localedir@"

URIS=default
ON_BOOT=start
ON_SHUTDOWN=suspend
SHUTDOWN_TIMEOUT=0
START_DELAY=0
BYPASS_CACHE=0

test -f "$sysconfdir"/sysconfig/libvirt-guests &&
    . "$sysconfdir"/sysconfig/libvirt-guests

LISTFILE="$localstatedir"/lib/libvirt/libvirt-guests
VAR_SUBSYS_LIBVIRT_GUESTS="$localstatedir"/lock/subsys/libvirt-guests

RETVAL=0

# retval COMMAND ARGUMENTS...
# run command with arguments and convert non-zero return value to 1 and set
# the global return variable
retval() {
    "$@"
    if [ $? -ne 0 ]; then
        RETVAL=1
        return 1
    else
        return 0
    fi
}

# run_virsh URI ARGUMENTS...
# start virsh and let it execute ARGUMENTS on URI
# If URI is "default" virsh is called without the "-c" argument
# (using libvirt's default connection)
run_virsh() {
    uri=$1
    shift

    if [ "x$uri" = xdefault ]; then
        virsh "$@" </dev/null
    else
        virsh -c "$uri" "$@" </dev/null
    fi
}

# run_virsh_c URI ARGUMENTS
# Same as "run_virsh" but the "C" locale is used instead of
# the system's locale.
run_virsh_c() {
    ( export LC_ALL=C; run_virsh "$@" )
}

# list_guests URI PERSISTENT
# List running guests on URI.
# PERSISTENT argument options:
# --persistent: list only persistent guests
# --transient: list only transient guests
# [none]: list both persistent and transient guests
list_guests() {
    uri=$1
    persistent=$2

    list=$(run_virsh_c "$uri" list --uuid $persistent)
    if [ $? -ne 0 ]; then
        RETVAL=1
        return 1
    fi

    echo $list
}

# guest_name URI UUID
# return name of guest UUID on URI
guest_name() {
    uri=$1
    uuid=$2

    run_virsh "$uri" domname "$uuid" 2>/dev/null
}

# guest_is_on URI UUID
# check if guest UUID on URI is running
# Result is returned by variable "guest_running"
guest_is_on() {
    uri=$1
    uuid=$2

    guest_running=false
    id=$(run_virsh "$uri" domid "$uuid")
    if [ $? -ne 0 ]; then
        RETVAL=1
        return 1
    fi

    [ -n "$id" ] && [ "x$id" != x- ] && guest_running=true
    return 0
}

# started
# Create the startup lock file
started() {
    touch "$VAR_SUBSYS_LIBVIRT_GUESTS"
}

# start
# Start or resume the guests
start() {
    [ -f "$LISTFILE" ] || { started; return 0; }

    if [ "x$ON_BOOT" != xstart ]; then
        gettext "libvirt-guests is configured not to start any guests on boot"
        echo
        rm -f "$LISTFILE"
        started
        return 0
    fi

    isfirst=true
    bypass=
    test "x$BYPASS_CACHE" = x0 || bypass=--bypass-cache
    while read uri list; do
        configured=false
        set -f
        for confuri in $URIS; do
            set +f
            if [ "x$confuri" = "x$uri" ]; then
                configured=true
                break
            fi
        done
        set +f
        if ! "$configured"; then
            eval_gettext "Ignoring guests on \$uri URI"; echo
            continue
        fi

        eval_gettext "Resuming guests on \$uri URI..."; echo
        for guest in $list; do
            name=$(guest_name "$uri" "$guest")
            eval_gettext "Resuming guest \$name: "
            if guest_is_on "$uri" "$guest"; then
                if "$guest_running"; then
                    gettext "already active"; echo
                else
                    if "$isfirst"; then
                        isfirst=false
                    else
                        sleep $START_DELAY
                    fi
                    retval run_virsh "$uri" start $bypass "$name" \
                        >/dev/null && \
                    gettext "done"; echo
                fi
            fi
        done
    done <"$LISTFILE"

    rm -f "$LISTFILE"
    started
}

# suspend_guest URI GUEST
# Do a managed save on a GUEST on URI. This function returns after the guest
# was saved.
suspend_guest()
{
    uri=$1
    guest=$2

    name=$(guest_name "$uri" "$guest")
    label=$(eval_gettext "Suspending \$name: ")
    bypass=
    test "x$BYPASS_CACHE" = x0 || bypass=--bypass-cache
    printf %s "$label"
    run_virsh "$uri" managedsave $bypass "$guest" >/dev/null &
    virsh_pid=$!
    while true; do
        sleep 1
        kill -0 "$virsh_pid" >/dev/null 2>&1 || break
        progress=$(run_virsh_c "$uri" domjobinfo "$guest" 2>/dev/null | \
                   awk '/^Data processed:/{print $3, $4}')
        if [ -n "$progress" ]; then
            printf '\r%s%12s ' "$label" "$progress"
        else
            printf '\r%s%-12s ' "$label" "..."
        fi
    done
    retval wait "$virsh_pid" && printf '\r%s%-12s\n' "$label" "$(gettext "done")"
}

# shutdown_guest URI GUEST
# Start a ACPI shutdown of GUEST on URI. This function return after the quest
# was successfully shutdown or the timeout defined by $SHUTDOWN_TIMEOUT expires.
shutdown_guest()
{
    uri=$1
    guest=$2

    name=$(guest_name "$uri" "$guest")
    label=$(eval_gettext "Shutting down \$name: ")
    printf %s "$label"
    retval run_virsh "$uri" shutdown "$guest" >/dev/null || return
    timeout=$SHUTDOWN_TIMEOUT
    while [ "$timeout" -gt 0 ]; do
        sleep 1
        timeout=$((timeout - 1))
        guest_is_on "$uri" "$guest" || return
        "$guest_running" || break
        printf '\r%s%-12d ' "$label" "$timeout"
    done

    if guest_is_on "$uri" "$guest"; then
        if "$guest_running"; then
            printf '\r%s%-12s\n' "$label" \
                "$(gettext "failed to shutdown in time")"
        else
            printf '\r%s%-12s\n' "$label" "$(gettext "done")"
        fi
    fi
}

# stop
# Shutdown or save guests on the configured uris
stop() {
    # last stop was not followed by start
    [ -f "$LISTFILE" ] && return 0

    suspending=true
    if [ "x$ON_SHUTDOWN" = xshutdown ]; then
        suspending=false
        if [ $SHUTDOWN_TIMEOUT -le 0 ]; then
            gettext "Shutdown action requested but SHUTDOWN_TIMEOUT was not set"
            echo
            RETVAL=6
            return
        fi
    fi

    : >"$LISTFILE"
    set -f
    for uri in $URIS; do
        set +f
        eval_gettext "Running guests on \$uri URI: "

        if [ "x$uri" = xdefault ] && [ ! -x "$libvirtd" ]; then
            gettext "libvirtd not installed; skipping this URI."; echo
            continue
        fi

        list=$(list_guests "$uri")
        if [ $? -eq 0 ]; then
            empty=true
            for uuid in $list; do
                "$empty" || printf ", "
                printf %s "$(guest_name "$uri" "$uuid")"
                empty=false
            done

            if "$empty"; then
                gettext "no running guests."
            fi
            echo
        fi

        if "$suspending"; then
            transient=$(list_guests "$uri" "--transient")
            if [ $? -eq 0 ]; then
                empty=true
                for uuid in $transient; do
                    if "$empty"; then
                        eval_gettext "Not suspending transient guests on URI: \$uri: "
                        empty=false
                    else
                        printf ", "
                    fi
                    printf %s "$(guest_name "$uri" "$uuid")"
                done
                echo
                # reload domain list to contain only persistent guests
                list=$(list_guests "$uri" "--persistent")
                if [ $? -ne 0 ]; then
                    eval_gettext "Failed to list persistent guests on \$uri"
                    echo
                    RETVAL=1
                    set +f
                    return
                fi
            else
                gettext "Failed to list transient guests"
                echo
                RETVAL=1
                set +f
                return
            fi
        fi

        if [ -n "$list" ]; then
            echo "$uri" "$list" >>"$LISTFILE"
        fi
    done
    set +f

    while read uri list; do
        if "$suspending"; then
            eval_gettext "Suspending guests on \$uri URI..."; echo
        else
            eval_gettext "Shutting down guests on \$uri URI..."; echo
        fi

        for guest in $list; do
            if "$suspending"; then
                suspend_guest "$uri" "$guest"
            else
                shutdown_guest "$uri" "$guest"
            fi
        done
    done <"$LISTFILE"

    rm -f "$VAR_SUBSYS_LIBVIRT_GUESTS"
}

# gueststatus
# List status of guests
gueststatus() {
    set -f
    for uri in $URIS; do
        set +f
        echo "* $uri URI:"
        retval run_virsh "$uri" list || echo
    done
    set +f
}

# rh_status
# Display current status: whether saved state exists, and whether start
# has been executed.  We cannot use status() from the functions library,
# since there is no external daemon process matching this init script.
rh_status() {
    if [ -f "$LISTFILE" ]; then
        gettext "stopped, with saved guests"; echo
        RETVAL=3
    else
        if [ -f "$VAR_SUBSYS_LIBVIRT_GUESTS" ]; then
            gettext "started"; echo
        else
            gettext "stopped, with no saved guests"; echo
        fi
        RETVAL=0
    fi
}

# usage [val]
# Display usage string, then exit with VAL (defaults to 2).
usage() {
    program_name=$0
    eval_gettext "Usage: \$program_name {start|stop|status|restart|"\
"condrestart|try-restart|reload|force-reload|gueststatus|shutdown}"; echo
    exit ${1-2}
}

# See how we were called.
if test $# != 1; then
    usage
fi
case "$1" in
    --help)
        usage 0
        ;;
    start|stop|gueststatus)
        "$1"
        ;;
    restart)
        stop && start
        ;;
    condrestart|try-restart)
        [ -f "$VAR_SUBSYS_LIBVIRT_GUESTS" ] && stop && start
        ;;
    reload|force-reload)
        # Nothing to do; we reread configuration on each invocation
        ;;
    status)
        rh_status
        ;;
    shutdown)
        ON_SHUTDOWN=shutdown
        stop
        ;;
    *)
        usage
        ;;
esac
exit $RETVAL
