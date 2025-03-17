#!/usr/bin/env python3
#
# Copyright (C) 2018-2019 Red Hat, Inc.
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
# Validate that header files follow a standard layout:
#
# /*
#  ...copyright header...
#  */
# <one blank line>
# #pragma once
# ....content....
#
# ---
#
# For any file ending priv.h, before the #pragma once
# We will have a further section
#
# #ifndef SYMBOL_ALLOW
# # error ....
# #endif /* SYMBOL_ALLOW */
# <one blank line>
#
#  ---
#
# For public headers (files in include/), use the standard
# header guard instead of #pragma once:
# #ifndef SYMBOL
# # define SYMBOL
# ....content....
# #endif /* SYMBOL */

import os.path
import re
import sys

STATE_COPYRIGHT_COMMENT = 0
STATE_COPYRIGHT_BLANK = 1
STATE_PRIV_START = 2
STATE_PRIV_ERROR = 3
STATE_PRIV_END = 4
STATE_PRIV_BLANK = 5
STATE_GUARD_START = 6
STATE_GUARD_DEFINE = 7
STATE_GUARD_END = 8
STATE_EOF = 9
STATE_PRAGMA = 10


def check_header(filename):
    ifdef = ""
    ifdefpriv = ""

    state = STATE_EOF

    ifdef = os.path.basename(filename).upper()
    ifdef = re.sub(r"""[^A-Z0-9]""", "_", ifdef)
    ifdef = re.sub(r"""__+""", "_", ifdef)

    if (not ifdef.startswith("LIBVIRT_") or
            "libvirt_internal.h" in filename):
        ifdef = "LIBVIRT_" + ifdef

    ifdefpriv = ifdef + "_ALLOW"

    state = STATE_COPYRIGHT_COMMENT
    publicheader = False
    if "include/" in filename:
        publicheader = True

    with open(filename, "r") as fh:
        for line in fh:
            if state == STATE_COPYRIGHT_COMMENT:
                if "*/" in line:
                    state = STATE_COPYRIGHT_BLANK
            elif state == STATE_COPYRIGHT_BLANK:
                if not line.isspace():
                    print("%s: missing blank line after copyright header" %
                          filename, file=sys.stderr)
                    return True

                if filename.endswith("priv.h"):
                    state = STATE_PRIV_START
                else:
                    state = STATE_GUARD_START
            elif state == STATE_PRIV_START:
                if line.isspace():
                    print("%s: too many blank lines after copyright header" %
                          filename, file=sys.stderr)
                    return True
                elif re.search(r"""#ifndef %s$""" % ifdefpriv, line):
                    state = STATE_PRIV_ERROR
                else:
                    print("%s: missing '#ifndef %s'" % (filename, ifdefpriv),
                          file=sys.stderr)
                    return True
            elif state == STATE_PRIV_ERROR:
                if re.search(r"""# error ".*"$""", line):
                    state = STATE_PRIV_END
                else:
                    print("%s: missing '# error ...priv allow...'" %
                          filename, file=sys.stderr)
                    return True
            elif state == STATE_PRIV_END:
                if re.search(r"""#endif /\* %s \*/""" % ifdefpriv, line):
                    state = STATE_PRIV_BLANK
                else:
                    print("%s: missing '#endif /* %s */'" %
                          (filename, ifdefpriv), file=sys.stderr)
                    return True
            elif state == STATE_PRIV_BLANK:
                if not line.isspace():
                    print("%s: missing blank line after priv guard" %
                          filename, file=sys.stderr)
                    return True
                state = STATE_GUARD_START
            elif state == STATE_GUARD_START:
                if line.isspace():
                    print("%s: too many blank lines after copyright header" %
                          filename, file=sys.stderr)
                    return True
                if publicheader:
                    if re.search(r"""#ifndef %s$""" % ifdef, line):
                        state = STATE_GUARD_DEFINE
                    else:
                        print("%s: missing '#ifndef %s'" %
                              (filename, ifdef), file=sys.stderr)
                        return True
                else:
                    if re.search(r"""#pragma once""", line):
                        state = STATE_PRAGMA
                    else:
                        print("%s: missing '#pragma once' header guard" %
                              filename, file=sys.stderr)
                        return True
            elif state == STATE_GUARD_DEFINE:
                if re.search(r"""# define %s$""" % ifdef, line):
                    state = STATE_GUARD_END
                else:
                    print("%s: missing '# define %s'" %
                          (filename, ifdef), file=sys.stderr)
                    return True
            elif state == STATE_GUARD_END:
                if re.search(r"""#endif /\* %s \*/$""" % ifdef, line):
                    state = STATE_EOF
            elif state == STATE_PRAGMA:
                next
            elif state == STATE_EOF:
                print("%s: unexpected content after '#endif /* %s */'" %
                      (filename, ifdef), file=sys.stderr)
                return True
            else:
                print("%s: unexpected state $state" %
                      filename, file=sys.stderr)
                return True

    if state == STATE_COPYRIGHT_COMMENT:
        print("%s: missing copyright comment" %
              filename, file=sys.stderr)
        return True
    elif state == STATE_COPYRIGHT_BLANK:
        print("%s: missing blank line after copyright header" %
              filename, file=sys.stderr)
        return True
    elif state == STATE_PRIV_START:
        print("%s: missing '#ifndef %s'" %
              (filename, ifdefpriv), file=sys.stderr)
        return True
    elif state == STATE_PRIV_ERROR:
        print("%s: missing '# error ...priv allow...'" %
              filename, file=sys.stderr)
        return True
    elif state == STATE_PRIV_END:
        print("%s: missing '#endif /* %s */'" %
              (filename, ifdefpriv), file=sys.stderr)
        return True
    elif state == STATE_PRIV_BLANK:
        print("%s: missing blank line after priv header check" %
              filename, file=sys.stderr)
        return True
    elif state == STATE_GUARD_START:
        if publicheader:
            print("%s: missing '#ifndef %s'" %
                  (filename, ifdef), file=sys.stderr)
            return True
        else:
            print("%s: missing '#pragma once' header guard" %
                  filename, file=sys.stderr)
            return True
    elif state == STATE_GUARD_DEFINE:
        print("%s: missing '# define %s'" %
              (filename, ifdef), file=sys.stderr)
        return True
    elif state == STATE_GUARD_END:
        print("%s: missing '#endif /* %s */'" %
              (filename, ifdef), file=sys.stderr)
        return True

    return False


ret = 0

for filename in sys.argv[1:]:
    if "config-post.h" in filename:
        continue
    if "vbox_CAPI" in filename:
        continue
    if "vbox_XPCOM" in filename:
        continue
    if check_header(filename):
        ret = 1

sys.exit(ret)
