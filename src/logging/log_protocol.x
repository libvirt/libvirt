/* -*- c -*-
 */

%#include "internal.h"

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

/* Define the program number, protocol version and procedure numbers here. */
const VIR_LOG_MANAGER_PROTOCOL_PROGRAM = 0x87539319;
const VIR_LOG_MANAGER_PROTOCOL_PROGRAM_VERSION = 1;
