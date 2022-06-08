/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>


#include "testutils.h"
#include "virlog.h"

#include "storage/storage_util.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.storageutiltest");


struct testGlusterExtractPoolSourcesData {
    const char *srcxml;
    const char *dstxml;
    virStoragePoolType type;
};

static int
testGlusterExtractPoolSources(const void *opaque)
{
    const struct testGlusterExtractPoolSourcesData *data = opaque;
    virStoragePoolSourceList list = { .type = data->type,
                                      .nsources = 0,
                                      .sources = NULL
                                    };
    size_t i;
    int ret = -1;
    g_autofree char *srcxmldata = NULL;
    g_autofree char *actual = NULL;

    if (virTestLoadFile(data->srcxml, &srcxmldata) < 0)
        goto cleanup;

    if (virStorageUtilGlusterExtractPoolSources("testhost", srcxmldata,
                                                &list, data->type) < 0)
        goto cleanup;

    if (!(actual = virStoragePoolSourceListFormat(&list)))
        goto cleanup;

    ret = virTestCompareToFile(actual, data->dstxml);

 cleanup:
    for (i = 0; i < list.nsources; i++)
        virStoragePoolSourceClear(&list.sources[i]);
    VIR_FREE(list.sources);

    return ret;
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST_GLUSTER_EXTRACT_POOL_SOURCES_FULL(testname, sffx, pooltype) \
    do { \
        struct testGlusterExtractPoolSourcesData data; \
        data.srcxml = abs_srcdir "/virstorageutildata/" \
                      "gluster-parse-" testname "-src.xml"; \
        data.dstxml = abs_srcdir "/virstorageutildata/" \
                      "gluster-parse-" testname "-" sffx ".xml"; \
        data.type = pooltype; \
        if (virTestRun("gluster-parse-" testname "-" sffx, \
                       testGlusterExtractPoolSources, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_GLUSTER_EXTRACT_POOL_SOURCES_NATIVE(testname) \
    DO_TEST_GLUSTER_EXTRACT_POOL_SOURCES_FULL(testname, "native", \
                                              VIR_STORAGE_POOL_GLUSTER)
#define DO_TEST_GLUSTER_EXTRACT_POOL_SOURCES_NETFS(testname) \
    DO_TEST_GLUSTER_EXTRACT_POOL_SOURCES_FULL(testname, "netfs", \
                                              VIR_STORAGE_POOL_NETFS)

    DO_TEST_GLUSTER_EXTRACT_POOL_SOURCES_NATIVE("basic");
    DO_TEST_GLUSTER_EXTRACT_POOL_SOURCES_NETFS("basic");
    DO_TEST_GLUSTER_EXTRACT_POOL_SOURCES_NATIVE("multivol");
    DO_TEST_GLUSTER_EXTRACT_POOL_SOURCES_NETFS("multivol");

#undef DO_TEST_GLUSTER_EXTRACT_POOL_SOURCES_NATIVE
#undef DO_TEST_GLUSTER_EXTRACT_POOL_SOURCES_NETFS
#undef DO_TEST_GLUSTER_EXTRACT_POOL_SOURCES_FULL

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
