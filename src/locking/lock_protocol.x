/* -*- c -*-
 */

%#include "internal.h"

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

enum virLockSpaceProtocolAcquireResourceFlags {
    VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_SHARED     = 1,
    VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_AUTOCREATE = 2
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
    /* Each function must have a two-word comment.  The first word is
     * whether remote_generator.pl handles daemon, the second whether
     * it handles src/remote.  Additional flags can be specified after a
     * pipe.
     */
    VIR_LOCK_SPACE_PROTOCOL_PROC_REGISTER = 1, /* skipgen skipgen */
    VIR_LOCK_SPACE_PROTOCOL_PROC_RESTRICT = 2, /* skipgen skipgen */
    VIR_LOCK_SPACE_PROTOCOL_PROC_NEW = 3, /* skipgen skipgen */
    VIR_LOCK_SPACE_PROTOCOL_PROC_CREATE_RESOURCE = 4, /* skipgen skipgen */
    VIR_LOCK_SPACE_PROTOCOL_PROC_DELETE_RESOURCE = 5, /* skipgen skipgen */

    VIR_LOCK_SPACE_PROTOCOL_PROC_ACQUIRE_RESOURCE = 6, /* skipgen skipgen */
    VIR_LOCK_SPACE_PROTOCOL_PROC_RELEASE_RESOURCE = 7, /* skipgen skipgen */

    VIR_LOCK_SPACE_PROTOCOL_PROC_CREATE_LOCKSPACE = 8 /* skipgen skipgen */
};
