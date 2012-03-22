#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"
#include "xml.h"
#include "testutils.h"
#include "xen/xen_hypervisor.h"
#include "virfile.h"

static int
testCompareFiles(const char *hostmachine, const char *xml_rel,
                 const char *cpuinfo_rel, const char *capabilities_rel)
{
  char *expectxml = NULL;
  char *actualxml = NULL;
  FILE *fp1 = NULL, *fp2 = NULL;
  virCapsPtr caps = NULL;

  int ret = -1;

  char *xml = NULL;
  char *cpuinfo = NULL;
  char *capabilities = NULL;

  if (virAsprintf(&xml, "%s/%s", abs_srcdir, xml_rel) < 0 ||
      virAsprintf(&cpuinfo, "%s/%s", abs_srcdir, cpuinfo_rel) < 0 ||
      virAsprintf(&capabilities, "%s/%s", abs_srcdir, capabilities_rel) < 0)
      goto fail;

  if (virtTestLoadFile(xml, &expectxml) < 0)
      goto fail;

  if (!(fp1 = fopen(cpuinfo, "r")))
      goto fail;

  if (!(fp2 = fopen(capabilities, "r")))
      goto fail;

  if (!(caps = xenHypervisorMakeCapabilitiesInternal(NULL, hostmachine, fp1, fp2)))
      goto fail;

  if (!(actualxml = virCapabilitiesFormatXML(caps)))
      goto fail;

  if (STRNEQ(expectxml, actualxml)) {
      virtTestDifference(stderr, expectxml, actualxml);
      goto fail;
  }

  ret = 0;

 fail:
  VIR_FREE(expectxml);
  VIR_FREE(actualxml);
  VIR_FREE(xml);
  VIR_FREE(cpuinfo);
  VIR_FREE(capabilities);
  VIR_FORCE_FCLOSE(fp1);
  VIR_FORCE_FCLOSE(fp2);

  virCapabilitiesFree(caps);
  return ret;
}

static int testXeni686(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("i686",
                          "xencapsdata/xen-i686.xml",
                          "xencapsdata/xen-i686.cpuinfo",
                          "xencapsdata/xen-i686.caps");
}

static int testXeni686PAE(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("i686",
                          "xencapsdata/xen-i686-pae.xml",
                          "xencapsdata/xen-i686-pae.cpuinfo",
                          "xencapsdata/xen-i686-pae.caps");
}

static int testXeni686PAEHVM(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("i686",
                          "xencapsdata/xen-i686-pae-hvm.xml",
                          "xencapsdata/xen-i686-pae-hvm.cpuinfo",
                          "xencapsdata/xen-i686-pae-hvm.caps");
}

/* No PAE + HVM is non-sensical - all VMX capable
   CPUs have PAE */
/*
static int testXeni686HVM(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("i686",
                          "xencapsdata/xen-i686-hvm.xml",
                          "xencapsdata/xen-i686.cpuinfo",
                          "xencapsdata/xen-i686-hvm.caps");
}
*/

static int testXenx86_64(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("x86_64",
                          "xencapsdata/xen-x86_64.xml",
                          "xencapsdata/xen-x86_64.cpuinfo",
                          "xencapsdata/xen-x86_64.caps");
}
static int testXenx86_64HVM(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("x86_64",
                          "xencapsdata/xen-x86_64-hvm.xml",
                          "xencapsdata/xen-x86_64-hvm.cpuinfo",
                          "xencapsdata/xen-x86_64-hvm.caps");
}

static int testXenia64(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("ia64",
                          "xencapsdata/xen-ia64.xml",
                          "xencapsdata/xen-ia64.cpuinfo",
                          "xencapsdata/xen-ia64.caps");
}
static int testXenia64BE(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("ia64",
                          "xencapsdata/xen-ia64-be.xml",
                          "xencapsdata/xen-ia64-be.cpuinfo",
                          "xencapsdata/xen-ia64-be.caps");
}

static int testXenia64HVM(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("ia64",
                          "xencapsdata/xen-ia64-hvm.xml",
                          "xencapsdata/xen-ia64-hvm.cpuinfo",
                          "xencapsdata/xen-ia64-hvm.caps");
}
static int testXenia64BEHVM(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("ia64",
                          "xencapsdata/xen-ia64-be-hvm.xml",
                          "xencapsdata/xen-ia64-be-hvm.cpuinfo",
                          "xencapsdata/xen-ia64-be-hvm.caps");
}

static int testXenppc64(const void *data ATTRIBUTE_UNUSED) {
  return testCompareFiles("ppc64",
                          "xencapsdata/xen-ppc64.xml",
                          "xencapsdata/xen-ppc64.cpuinfo",
                          "xencapsdata/xen-ppc64.caps");
}


/* Fake initialization data for xenHypervisorInit(). Must be initialized
 * explicitly before the implicit call via virInitialize(). */
static struct xenHypervisorVersions hv_versions = {
    .hv = 0,
    .hypervisor = 2,
    .sys_interface = -1,
    .dom_interface = -1,
};

static int
mymain(void)
{
    int ret = 0;

    xenHypervisorInit(&hv_versions);
    virInitialize();

    if (virtTestRun("Capabilities for i686, no PAE, no HVM",
                    1, testXeni686, NULL) != 0)
        ret = -1;

    if (virtTestRun("Capabilities for i686, PAE, no HVM",
                    1, testXeni686PAE, NULL) != 0)
        ret = -1;

    /* No PAE + HVM is non-sensical - all VMX capable
       CPUs have PAE */
    /*if (virtTestRun("Capabilities for i686, no PAE, HVM",
                    1, testXeni686HVM, NULL) != 0)
        ret = -1;
    */

    if (virtTestRun("Capabilities for i686, PAE, HVM",
                    1, testXeni686PAEHVM, NULL) != 0)
        ret = -1;

    if (virtTestRun("Capabilities for x86_64, no HVM",
                    1, testXenx86_64, NULL) != 0)
        ret = -1;

    if (virtTestRun("Capabilities for x86_64, HVM",
                    1, testXenx86_64HVM, NULL) != 0)
        ret = -1;

    if (virtTestRun("Capabilities for ia64, no HVM, LE",
                    1, testXenia64, NULL) != 0)
        ret = -1;

    if (virtTestRun("Capabilities for ia64, HVM, LE",
                    1, testXenia64HVM, NULL) != 0)
        ret = -1;

    if (virtTestRun("Capabilities for ia64, no HVM, BE",
                    1, testXenia64BE, NULL) != 0)
        ret = -1;

    if (virtTestRun("Capabilities for ia64, HVM, BE",
                    1, testXenia64BEHVM, NULL) != 0)
        ret = -1;

    if (virtTestRun("Capabilities for ppc64",
                    1, testXenppc64, NULL) != 0)
        ret = -1;


    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
