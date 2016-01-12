/* -*- c -*-
 */

%#include "internal.h"
%#include "lock_driver_lockd.h"

typedef opaque virLockSpaceProtocolUUID[VIR_UUID_BUFLEN];

/* Length of long, but not unbounded, strings.
 * This is an arbitrary limit designed to stop the decoder from trying
 * to allocate unbounded amounts of memory when fed with a bad message.
 */
const VIR_LOCK_SPACE_PROTOCOL_STRING_MAX = 65536;

/* A long string, which may NOT be NULL. */
typedef string virLockSpaceProtocolNonNullString<VIR_LOCK_SPACE_PROTOCOL_STRING_MAX>;

/* A long string, which may be NULL. */
typedef virLockSpaceProtocolNonNullString *virLockSpaceProtocolString;

struct virLockSpaceProtocolOwner {
    virLockSpaceProtocolUUID uuid;
    virLockSpaceProtocolNonNullString name;
    unsigned int id;
    unsigned int pid;
};

struct virLockSpaceProtocolRegisterArgs {
    virLockSpaceProtocolOwner owner;
    unsigned int flags;
};

struct virLockSpaceProtocolRestrictArgs {
    unsigned int flags;
};

struct virLockSpaceProtocolNewArgs {
    virLockSpaceProtocolNonNullString path;
    unsigned int flags;
};

struct virLockSpaceProtocolCreateResourceArgs {
    virLockSpaceProtocolNonNullString path;
    virLockSpaceProtocolNonNullString name;
    unsigned int flags;
};

struct virLockSpaceProtocolDeleteResourceArgs {
    virLockSpaceProtocolNonNullString path;
    virLockSpaceProtocolNonNullString name;
    unsigned int flags;
};

struct virLockSpaceProtocolAcquireResourceArgs {
    virLockSpaceProtocolNonNullString path;
    virLockSpaceProtocolNonNullString name;
    unsigned int flags;
};

struct virLockSpaceProtocolReleaseResourceArgs {
    virLockSpaceProtocolNonNullString path;
    virLockSpaceProtocolNonNullString name;
    unsigned int flags;
};

struct virLockSpaceProtocolCreateLockSpaceArgs {
    virLockSpaceProtocolNonNullString path;
};


/* Define the program number, protocol version and procedure numbers here. */
const VIR_LOCK_SPACE_PROTOCOL_PROGRAM = 0xEA7BEEF;
const VIR_LOCK_SPACE_PROTOCOL_PROGRAM_VERSION = 1;

enum virLockSpaceProtocolProcedure {
    /* Each function must be preceded by a comment providing one or
     * more annotations:
     *
     * - @generate: none|client|server|both
     *
     *   Whether to generate the dispatch stubs for the server
     *   and/or client code.
     *
     * - @readstream: paramnumber
     * - @writestream: paramnumber
     *
     *   The @readstream or @writestream annotations let daemon and src/remote
     *   create a stream.  The direction is defined from the src/remote point
     *   of view.  A readstream transfers data from daemon to src/remote.  The
     *   <paramnumber> specifies at which offset the stream parameter is inserted
     *   in the function parameter list.
     *
     * - @priority: low|high
     *
     *   Each API that might eventually access hypervisor's  monitor (and thus
     *   block) MUST fall into low priority. However, there are some exceptions
     *   to this rule, e.g. domainDestroy. Other APIs MAY  be marked as high
     *   priority. If in doubt, it's safe to choose low. Low is taken as default,
     *   and thus can be left out.
     */

    /**
     * @generate: none
     * @acl: none
     */
    VIR_LOCK_SPACE_PROTOCOL_PROC_REGISTER = 1,

    /**
     * @generate: none
     * @acl: none
     */
    VIR_LOCK_SPACE_PROTOCOL_PROC_RESTRICT = 2,

    /**
     * @generate: none
     * @acl: none
     */
    VIR_LOCK_SPACE_PROTOCOL_PROC_NEW = 3,

    /**
     * @generate: none
     * @acl: none
     */
    VIR_LOCK_SPACE_PROTOCOL_PROC_CREATE_RESOURCE = 4,

    /**
     * @generate: none
     * @acl: none
     */
    VIR_LOCK_SPACE_PROTOCOL_PROC_DELETE_RESOURCE = 5,

    /**
     * @generate: none
     * @acl: none
     */
    VIR_LOCK_SPACE_PROTOCOL_PROC_ACQUIRE_RESOURCE = 6,

    /**
     * @generate: none
     * @acl: none
     */
    VIR_LOCK_SPACE_PROTOCOL_PROC_RELEASE_RESOURCE = 7,

    /**
     * @generate: none
     * @acl: none
     */
    VIR_LOCK_SPACE_PROTOCOL_PROC_CREATE_LOCKSPACE = 8
};
