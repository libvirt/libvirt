/* -*- c -*-
 */

%#include "internal.h"
%#include "virxdrdefs.h"

typedef opaque virLogManagerProtocolUUID[VIR_UUID_BUFLEN];

/* Length of long, but not unbounded, strings.
 * This is an arbitrary limit designed to stop the decoder from trying
 * to allocate unbounded amounts of memory when fed with a bad message.
 */
const VIR_LOG_MANAGER_PROTOCOL_STRING_MAX = 4194304;

/* A long string, which may NOT be NULL. */
typedef string virLogManagerProtocolNonNullString<VIR_LOG_MANAGER_PROTOCOL_STRING_MAX>;

/* A long string, which may be NULL. */
typedef virLogManagerProtocolNonNullString *virLogManagerProtocolString;

struct virLogManagerProtocolDomain {
    virLogManagerProtocolUUID uuid;
    virLogManagerProtocolNonNullString name;
};

struct virLogManagerProtocolLogFilePosition {
    unsigned hyper inode;
    unsigned hyper offset;
};

enum virLogManagerProtocolDomainOpenLogFileFlags {
    VIR_LOG_MANAGER_PROTOCOL_DOMAIN_OPEN_LOG_FILE_TRUNCATE = 1
};

/* Obtain a file handle suitable for writing to a
 * log file for a domain
 */
struct virLogManagerProtocolDomainOpenLogFileArgs {
    virLogManagerProtocolNonNullString driver;
    virLogManagerProtocolDomain dom;
    virLogManagerProtocolNonNullString path;
    unsigned int flags;
};

struct virLogManagerProtocolDomainOpenLogFileRet {
    virLogManagerProtocolLogFilePosition pos;
};

struct virLogManagerProtocolDomainGetLogFilePositionArgs {
    virLogManagerProtocolNonNullString path;
    unsigned int flags;
};

struct virLogManagerProtocolDomainGetLogFilePositionRet {
    virLogManagerProtocolLogFilePosition pos;
};

struct virLogManagerProtocolDomainReadLogFileArgs {
    virLogManagerProtocolNonNullString path;
    virLogManagerProtocolLogFilePosition pos;
    unsigned hyper maxlen;
    unsigned int flags;
};

struct virLogManagerProtocolDomainReadLogFileRet {
    virLogManagerProtocolNonNullString data;
};

struct virLogManagerProtocolDomainAppendLogFileArgs {
    virLogManagerProtocolNonNullString driver;
    virLogManagerProtocolDomain dom;
    virLogManagerProtocolNonNullString path;
    virLogManagerProtocolNonNullString message;
    unsigned int flags;
};

struct virLogManagerProtocolDomainAppendLogFileRet {
    int ret;
};

/* Define the program number, protocol version and procedure numbers here. */
const VIR_LOG_MANAGER_PROTOCOL_PROGRAM = 0x87539319;
const VIR_LOG_MANAGER_PROTOCOL_PROGRAM_VERSION = 1;

enum virLogManagerProtocolProcedure {
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
    VIR_LOG_MANAGER_PROTOCOL_PROC_DOMAIN_OPEN_LOG_FILE = 1,

    /**
     * @generate: none
     * @acl: none
     */
    VIR_LOG_MANAGER_PROTOCOL_PROC_DOMAIN_GET_LOG_FILE_POSITION = 2,

    /**
     * @generate: none
     * @acl: none
     */
    VIR_LOG_MANAGER_PROTOCOL_PROC_DOMAIN_READ_LOG_FILE = 3,

    /**
     * @generate: none
     * @acl: none
     */
    VIR_LOG_MANAGER_PROTOCOL_PROC_DOMAIN_APPEND_LOG_FILE = 4
};
