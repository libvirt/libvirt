#include <config.h>

#include <fcntl.h>

#include "viriommufd.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.iommufd");

#ifdef __linux__

# include <sys/ioctl.h>
# include <linux/types.h>

# ifdef HAVE_LINUX_IOMMUFD_H
#  include <linux/iommufd.h>
# endif

# ifndef IOMMU_OPTION

enum iommufd_option {
    IOMMU_OPTION_RLIMIT_MODE = 0,
    IOMMU_OPTION_HUGE_PAGES = 1,
};

enum iommufd_option_ops {
    IOMMU_OPTION_OP_SET = 0,
    IOMMU_OPTION_OP_GET = 1,
};

struct iommu_option {
    __u32 size;
    __u32 option_id;
    __u16 op;
    __u16 __reserved;
    __u32 object_id;
    __aligned_u64 val64;
};

#  define IOMMUFD_TYPE (';')
#  define IOMMUFD_CMD_OPTION 0x87
#  define IOMMU_OPTION _IO(IOMMUFD_TYPE, IOMMUFD_CMD_OPTION)

# endif

/**
 * virIOMMUFDSetRLimitMode:
 * @fd: iommufd file descriptor
 * @processAccounting: true for per-process, false for per-user
 *
 * Set RLIMIT_MEMLOCK accounting mode for the iommufd.
 *
 * Returns: 0 on success, -1 on error
 */
static int
virIOMMUFDSetRLimitMode(int fd, bool processAccounting)
{
    struct iommu_option option = {
        .size = sizeof(struct iommu_option),
        .option_id = IOMMU_OPTION_RLIMIT_MODE,
        .op = IOMMU_OPTION_OP_SET,
        .__reserved = 0,
        .object_id = 0,
        .val64 = processAccounting ? 1 : 0,
    };

    if (ioctl(fd, IOMMU_OPTION, &option) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to set memory accounting for iommufd"));
        return -1;
    }

    VIR_DEBUG("Set iommufd rlimit mode to %s-based accounting",
              processAccounting ? "process" : "user");
    return 0;
}

int
virIOMMUFDOpenDevice(void)
{
    int fd = -1;

    if ((fd = open(VIR_IOMMU_DEV_PATH, O_RDWR | O_CLOEXEC)) < 0)
        virReportSystemError(errno, "%s", _("cannot open IOMMUFD device"));

    if (virIOMMUFDSetRLimitMode(fd, true) < 0) {
        VIR_FORCE_CLOSE(fd);
        return -1;
    }

    return fd;
}

#else

int
virIOMMUFDOpenDevice(void)
{
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("IOMMUFD is not supported on this platform"));
    return -1;
}

#endif

/**
 * virIOMMUFDSupported:
 *
 * Check the presence of IOMMU device.
 *
 * Retruns: true if it exists, false otherwise
 */
bool
virIOMMUFDSupported(void)
{
    return virFileExists(VIR_IOMMU_DEV_PATH);
}
