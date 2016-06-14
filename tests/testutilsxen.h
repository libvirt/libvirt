#ifndef _TESTUTILSXEN_H_
# define _TESTUTILSXEN_H_

# include "capabilities.h"
# ifdef WITH_LIBXL
#  include "libxl/libxl_capabilities.h"
# endif

virCapsPtr testXenCapsInit(void);

virCapsPtr testXLInitCaps(void);

#endif /* _TESTUTILSXEN_H_ */
