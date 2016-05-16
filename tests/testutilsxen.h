#ifndef _TESTUTILSXEN_H_
# define _TESTUTILSXEN_H_

# include "capabilities.h"
# include "libxl/libxl_capabilities.h"

virCapsPtr testXenCapsInit(void);

virCapsPtr testXLInitCaps(void);

#endif /* _TESTUTILSXEN_H_ */
